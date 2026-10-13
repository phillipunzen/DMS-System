import email
import imaplib
import io
import re
import ssl
import hashlib
import shutil
import magic
from datetime import timedelta
from email.policy import default
from urllib.parse import urlparse
import caldav
from icalendar import Calendar, Event
from fastapi import HTTPException
from sqlalchemy import select
from .db import Integration, MailImport, CalendarSync, Document, Tenant, Folder, Membership, now
from .security import decrypt
from .storage import save_document, path_for, MAX_UPLOAD


def validate_config(kind, config, enabled):
    if kind == 'imap':
        selected_filter = config.get('attachment_filter', 'all')
        if not isinstance(selected_filter, str) or selected_filter not in {'all', 'pdf'}:
            raise HTTPException(422, 'Ungültiger E-Mail-Anhangfilter.')
        if not isinstance(config.get('import_body', False), bool):
            raise HTTPException(422, 'E-Mail-Textimport muss ein Wahrheitswert sein.')
    if kind == 'folder':
        if set(config) - {'after_import', 'settle_seconds', 'folder_id'}:
            raise HTTPException(422, 'Der Importpfad wird ausschließlich vom Server vorgegeben.')
        if config.get('after_import', 'delete') not in {'delete', 'archive'}:
            raise HTTPException(422, 'Ungültige Aktion nach dem Import.')
        delay = config.get('settle_seconds', 30)
        if isinstance(delay, bool) or not isinstance(delay, int) or not 5 <= delay <= 3600:
            raise HTTPException(422, 'Die Wartezeit muss zwischen 5 und 3600 Sekunden liegen.')
        folder_id = config.get('folder_id')
        if folder_id is not None and not isinstance(folder_id, str):
            raise HTTPException(422, 'Ungültiger DMS-Zielordner.')
        config['settle_seconds'] = delay
        config.setdefault('after_import', 'delete')
        return
    if kind == 'ai':
        if not isinstance(config.get('document_fallback', False), bool):
            raise HTTPException(422, 'Ungültige Freigabe für vollständige Dokumente.')
        if config.get('document_fallback') is True and (config.get('privacy_mode') != 'automatic' or config.get('automatic_consent') is not True or config.get('consent') is not True):
            raise HTTPException(422, 'Vollständige Dokumentübertragung benötigt den automatischen Modus mit Zustimmung.')
        mode = config.setdefault('privacy_mode', 'manual')
        if not isinstance(mode, str) or mode not in {'manual', 'automatic'}:
            raise HTTPException(422, 'Ungültiger KI-Verarbeitungsmodus.')
        limit = config.setdefault('text_limit', 10000)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1000 <= limit <= 10000:
            raise HTTPException(422, 'Die KI-Textgrenze muss zwischen 1.000 und 10.000 Zeichen liegen.')
        if mode == 'automatic' and config.get('automatic_consent') is not True:
            raise HTTPException(422, 'Automatische externe KI-Verarbeitung benötigt eine ausdrückliche Freigabe.')
        if enabled and config.get('consent') is not True:
            raise HTTPException(422, 'Bitte der Übertragung des minimierten Texts zustimmen.')
        provider = config.get('provider', 'openai')
        if not isinstance(provider, str) or provider not in {'openai', 'codex'}:
            raise HTTPException(422, 'Unbekannter KI-Anbieter.')
        if provider == 'codex':
            if set(config) - {'provider', 'model', 'consent', 'privacy_mode', 'text_limit', 'automatic_consent', 'document_fallback'}:
                raise HTTPException(422, 'Codex verwendet die Server-Anmeldung; keine Schlüssel oder eigenen Befehle erlaubt.')
            model = config.get('model', '')
            if not isinstance(model, str) or len(model) > 150 or (model and not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:/-]*', model)):
                raise HTTPException(422, 'Ungültige Codex-Modell-ID.')
            if enabled and config.get('consent') is not True:
                raise HTTPException(422, 'Bitte der Textübertragung an Codex zustimmen.')
            return
    if not enabled:
        return
    required = {'ai': ['api_key', 'model', 'consent'], 'imap': ['host', 'username', 'password'], 'caldav': ['url', 'username', 'password']}[kind]
    if any(not config.get(k) for k in required):
        raise HTTPException(422, 'Bitte alle Pflichtfelder ausfüllen; KI benötigt die Zustimmung zur Textübertragung.')
    if kind in {'ai', 'caldav'}:
        url = config.get('base_url', 'https://api.openai.com/v1') if kind == 'ai' else config['url']
        parsed = urlparse(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            raise HTTPException(422, 'Die URL muss HTTPS verwenden und darf keine Zugangsdaten enthalten.')
    if kind == 'imap':
        try:
            port = int(config.get('port', 993))
        except (TypeError, ValueError):
            raise HTTPException(422, 'Ungültiger IMAP-Port.')
        if not 1 <= port <= 65535:
            raise HTTPException(422, 'Ungültiger IMAP-Port.')
        config['port'] = port


def import_mail(db, integration, config):
    # A row lock prevents worker and manual sync from importing the same message.
    db.scalar(select(Integration).where(Integration.id == integration.id).with_for_update())
    tenant = db.scalar(select(Tenant).where(Tenant.id == integration.tenant_id).with_for_update())
    owner = db.scalar(select(Membership.user_id).where(Membership.tenant_id == tenant.id, Membership.role == 'owner'))
    inbox = db.scalar(select(Folder).where(Folder.tenant_id == tenant.id, Folder.name == 'Eingang'))
    count = 0
    skipped = 0
    pdf_only = config.get('attachment_filter', 'all') == 'pdf'
    integration._created_paths = []
    with imaplib.IMAP4_SSL(config['host'], int(config.get('port', 993)), ssl_context=ssl.create_default_context(), timeout=20) as client:
        client.login(config['username'], config['password'])
        status, _ = client.select(config.get('folder', 'INBOX'), readonly=True)
        if status != 'OK':
            raise ValueError('IMAP-Ordner nicht verfügbar')
        validity_data = client.response('UIDVALIDITY')[1]
        if not validity_data or not any(isinstance(value, bytes) and value.strip().isdigit() and int(value.strip()) > 0 for value in validity_data):
            raise ValueError('IMAP UIDVALIDITY fehlt')
        # Preserve existing receipt keys across upgrades; UIDVALIDITY separates
        # reused UIDs after a mailbox reset. Nondefault ports need their own namespace.
        validity = str(validity_data)
        status, data = client.uid('search', None, 'ALL')
        if status != 'OK':
            raise ValueError('IMAP-Suche fehlgeschlagen')
        # Progress from oldest to newest so large mailboxes are not starved.
        processed = 0
        for uid in data[0].split():
            source = config['host'] + config['username'] + config.get('folder', 'INBOX') + validity + uid.decode()
            if int(config.get('port', 993)) != 993:
                source += '\0port=' + str(config['port'])
            key = hashlib.sha256(source.encode()).hexdigest()
            filtered_key = hashlib.sha256((key + ':filter:pdf:v1').encode()).hexdigest()
            if db.scalar(select(MailImport.id).where(MailImport.integration_id == integration.id, MailImport.message_key == key)):
                continue
            if pdf_only and db.scalar(select(MailImport.id).where(MailImport.integration_id == integration.id, MailImport.message_key == filtered_key)):
                continue
            if processed >= 30:
                break
            processed += 1
            status, sizes = client.uid('fetch', uid, '(RFC822.SIZE)')
            size_match = re.search(rb'RFC822.SIZE (\d+)', b' '.join(x for x in sizes if isinstance(x, bytes)))
            if status != 'OK' or not size_match or int(size_match[1]) > MAX_UPLOAD * 2:
                continue
            status, message_data = client.uid('fetch', uid, '(BODY.PEEK[])')
            if status != 'OK':
                continue
            raw = next((item[1] for item in message_data if isinstance(item, tuple)), None)
            if not raw or len(raw) > MAX_UPLOAD * 2:
                continue
            message = email.message_from_bytes(raw, policy=default)
            attachments = []
            for index, part in enumerate(message.walk(), 1):
                filename = part.get_filename()
                if part.is_multipart() or (not filename and (not pdf_only or part.get_content_disposition() != 'attachment')):
                    continue
                content = part.get_payload(decode=True)
                if not content:
                    continue
                if pdf_only and magic.from_buffer(content, mime=True) != 'application/pdf':
                    continue
                attachments.append((str(filename or f'Anhang-{index}.pdf'), content))
            if pdf_only and not attachments:
                # Remember a nonmatch for this filter only. Widening the filter
                # later can still import it; successful imports always use key.
                db.add(MailImport(integration_id=integration.id, message_key=filtered_key))
                db.flush()
                skipped += 1
                continue
            created = []
            try:
                for filename, content in attachments:
                    try:
                        doc = save_document(db, tenant.id, owner, str(filename), io.BytesIO(content), source='email')
                        doc.folder_id = inbox.id if inbox else None
                        created.append(doc)
                        integration._created_paths.append(path_for(tenant.id, doc.id).parent)
                        count += 1
                    except HTTPException as e:
                        if e.status_code not in {409, 415}:
                            raise
                if config.get('import_body'):
                    body = message.get_body(preferencelist=('plain',))
                    if body:
                        text = 'Betreff: ' + str(message.get('Subject', 'E-Mail')) + '\nVon: ' + str(message.get('From', '')) + '\n\n' + body.get_content()
                        try:
                            doc = save_document(db, tenant.id, owner, str(message.get('Subject', 'E-Mail'))[:200] + '.txt', io.BytesIO(text.encode()), source='email')
                            doc.folder_id = inbox.id if inbox else None
                            created.append(doc)
                            integration._created_paths.append(path_for(tenant.id, doc.id).parent)
                            count += 1
                        except HTTPException as e:
                            if e.status_code != 409:
                                raise
                db.add(MailImport(integration_id=integration.id, message_key=key))
                db.flush()
            except Exception:
                for doc in created:
                    shutil.rmtree(path_for(tenant.id, doc.id).parent, ignore_errors=True)
                raise
    return f'{count} Dokumente importiert.' + (f' {skipped} E-Mails ohne PDF-Anhang übersprungen.' if skipped else '')


def sync_calendar(db, integration, config):
    db.scalar(select(Integration).where(Integration.id == integration.id).with_for_update())
    count = 0
    with caldav.DAVClient(url=config['url'], username=config['username'], password=config['password'], timeout=20) as client:
        calendar = client.calendar(url=config['url'])
        docs = db.scalars(select(Document).where(Document.tenant_id == integration.tenant_id, Document.due_date.is_not(None), Document.deleted_at.is_(None), Document.paid.is_(False))).all()
        active_ids = {d.id for d in docs}
        for doc in docs:
            uid = f'archivraum-{doc.tenant_id}-{doc.id}'
            cal = Calendar()
            cal.add('prodid', '-//Archivraum//DMS//DE')
            cal.add('version', '2.0')
            event = Event()
            event.add('uid', uid)
            event.add('dtstamp', now().replace(tzinfo=__import__('datetime').timezone.utc))
            event.add('dtstart', doc.due_date)
            event.add('dtend', doc.due_date + timedelta(days=1))
            event.add('summary', 'Fällig: ' + doc.title)
            event.add('description', f'Lieferant: {doc.supplier}\nBetrag: {doc.amount or "–"}\nDokument-ID: {doc.id}')
            cal.add_component(event)
            calendar.save_event(cal.to_ical().decode())
            if not db.scalar(select(CalendarSync.id).where(CalendarSync.integration_id == integration.id, CalendarSync.document_id == doc.id)):
                db.add(CalendarSync(integration_id=integration.id, document_id=doc.id, event_uid=uid))
            count += 1
        for sync in db.scalars(select(CalendarSync).where(CalendarSync.integration_id == integration.id)).all():
            if sync.document_id not in active_ids:
                old = db.get(Document, sync.document_id) if sync.document_id else None
                event_uid = sync.event_uid or (f'archivraum-{old.tenant_id}-{old.id}' if old else None)
                if event_uid:
                    try:
                        calendar.event_by_uid(event_uid).delete()
                    except caldav.error.NotFoundError:
                        pass
                db.delete(sync)
    return f'{count} Fälligkeiten synchronisiert.'


def run_integration_once(db, integration, retry_errors=False):
    config = decrypt(integration.config_encrypted)
    try:
        if integration.kind == 'folder':
            from .folder_import import import_directory
            result = import_directory(db, integration, config, retry_errors=retry_errors)
        elif integration.kind == 'imap':
            result = import_mail(db, integration, config)
        elif integration.kind == 'caldav':
            result = sync_calendar(db, integration, config)
        else:
            raise ValueError('Unbekannte Integration')
        integration.last_status = result
        integration.last_run = now()
        db.commit()
        return result
    except Exception:
        for path in getattr(integration, "_created_paths", []):
            shutil.rmtree(path, ignore_errors=True)
        db.rollback()
        integration = db.get(Integration, integration.id)
        integration.last_status = 'Verbindung oder Import fehlgeschlagen. Zugang, Zertifikat und Speicherlimit prüfen.'
        integration.last_run = now()
        db.commit()
        return integration.last_status
