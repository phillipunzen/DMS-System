"""Tenant-scoped productivity tools and revocable, version-pinned public shares."""
import io
import os
import re
import secrets
import shutil
import tempfile
from datetime import date, timedelta
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field, ConfigDict, model_validator, field_validator
from sqlalchemy import select, func, update
from sqlalchemy.exc import IntegrityError
from itsdangerous import URLSafeTimedSerializer, BadSignature
from starlette.background import BackgroundTask
from .db import (Document, DocumentVersion, DocumentNote, Annotation, Contract, ShareLink,
    Membership, Tenant, User, Integration, FolderImport, Setting, Audit, AuthAttempt, now, get_db)
from .security import current_user, admin_user, membership, audit, digest, passwords, secret, COOKIE_SECURE
from .permissions import document_access, document_clause, folder_access, rule_permissions
from .storage import ROOT, version_path

router = APIRouter()
signer = URLSafeTimedSerializer(secret, salt='document-share-unlock-v1')


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid')


class BulkInput(Input):
    document_ids: list[str] = Field(min_length=1, max_length=100)
    action: Literal['move', 'tags', 'paid', 'type', 'trash', 'restore', 'reprocess']
    folder_id: str | None = None
    tags: list[str] = Field(default_factory=list, max_length=20)
    paid: bool = True
    doc_type: Literal['Rechnung', 'Vertrag', 'Lieferschein', 'Sonstiges'] = 'Sonstiges'

    @field_validator('tags')
    @classmethod
    def valid_tags(cls, values):
        if any(not tag.strip() or len(tag) > 80 for tag in values):
            raise ValueError('Tags benötigen 1 bis 80 Zeichen.')
        return list(dict.fromkeys(tag.strip() for tag in values))


@router.post('/api/tenants/{tenant_id}/bulk')
def bulk(tenant_id: str, data: BulkInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'editor')
    # Authorize every object before the first mutation. Sorted locks avoid deadlocks.
    docs = [document_access(db, user, tenant_id, ident, edit=True, lock=True)
            for ident in sorted(set(data.document_ids))]
    if any(d.status in {'queued', 'processing'} for d in docs):
        raise HTTPException(409, 'Auswahl enthält noch nicht fertig verarbeitete Dokumente.')
    if data.action != 'restore' and any(d.deleted_at for d in docs):
        raise HTTPException(409, 'Dokumente zunächst aus dem Papierkorb wiederherstellen.')
    if data.action == 'move' and data.folder_id:
        folder_access(db, user, tenant_id, data.folder_id, edit=True)
    from .features import invalidate_review
    from .processing import classify
    for doc in docs:
        if data.action == 'move': doc.folder_id = data.folder_id
        elif data.action == 'tags': doc.tags = data.tags
        elif data.action == 'paid': doc.paid = data.paid
        elif data.action == 'type': doc.doc_type = data.doc_type
        elif data.action == 'trash': doc.deleted_at = now()
        elif data.action == 'restore': doc.deleted_at = None
        elif data.action == 'reprocess':
            doc.status, doc.error = 'queued', None
            doc.ai_pending, doc.ai_retry_at, doc.ai_attempts = False, None, 0
        if data.action in {'move', 'tags', 'paid', 'type', 'reprocess'}:
            invalidate_review(db, doc)
        if data.action == 'type':
            classify(db, doc, permitted=rule_permissions(db, user, tenant_id), actor_id=user.id, rename_only=True)
        audit(db, user, tenant_id, 'document.bulk_' + data.action, doc.id)
    db.commit()
    return {'changed': len(docs)}


def text_tokens(text):
    # Bounded comparisons; do not hide differences such as invoice numbers.
    return set(re.findall(r'\w+', (text or '')[:50000].casefold()))


@router.get('/api/tenants/{tenant_id}/duplicates')
def duplicates(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    member = membership(db, user, tenant_id)
    query = select(Document).where(Document.tenant_id == tenant_id, Document.deleted_at.is_(None),
        document_clause(user.id, member.role)).order_by(Document.created_at.desc())
    count = db.scalar(select(func.count()).select_from(query.subquery()))
    docs = db.scalars(query.limit(200)).all()
    tokens = {d.id: text_tokens(d.text) for d in docs}
    pairs = []
    for index, left in enumerate(docs):
        for right in docs[index + 1:]:
            exact = left.sha256 == right.sha256
            a, b = tokens[left.id], tokens[right.id]
            if not exact and (min(len(a), len(b)) < 12 or min(len(left.text or ''), len(right.text or '')) < 100): continue
            score = 1.0 if exact else len(a & b) / max(1, len(a | b))
            if score >= .85:
                pairs.append({'left': {'id': left.id, 'title': left.title, 'filename': left.filename},
                    'right': {'id': right.id, 'title': right.title, 'filename': right.filename},
                    'kind': 'identical' if exact else 'similar_text', 'similarity': round(score * 100)})
    pairs.sort(key=lambda p: p['similarity'], reverse=True)
    return {'items': pairs[:100], 'scanned': len(docs), 'total': count, 'limited': count > 200 or len(pairs) > 100}


class ContractInput(Input):
    partner: str = Field(default='', max_length=150)
    start_date: date | None = None
    end_date: date
    notice_days: int = Field(default=30, ge=0, le=3650)
    reminder_days: int = Field(default=30, ge=0, le=3650)
    status: Literal['active', 'cancelled', 'expired'] = 'active'
    note: str = Field(default='', max_length=2000)

    @model_validator(mode='after')
    def dates(self):
        if self.start_date and self.start_date > self.end_date:
            raise ValueError('Vertragsbeginn muss vor dem Vertragsende liegen.')
        return self


def contract_data(row):
    result = {k: getattr(row, k) for k in ['document_id', 'partner', 'start_date', 'end_date', 'notice_days', 'reminder_days', 'status', 'note']}
    deadline = row.end_date - timedelta(days=row.notice_days)
    reminder = deadline - timedelta(days=row.reminder_days)
    today = now().date()
    result.update(cancel_by=deadline, remind_on=reminder,
        reminder_due=row.status == 'active' and reminder <= today,
        deadline_passed=row.status == 'active' and deadline < today)
    return result


@router.get('/api/tenants/{tenant_id}/contracts')
def contracts(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    member = membership(db, user, tenant_id)
    rows = db.execute(select(Contract, Document).join(Document, Contract.document_id == Document.id).where(
        Document.tenant_id == tenant_id, Document.deleted_at.is_(None), document_clause(user.id, member.role))
        .order_by(Contract.end_date).limit(1000)).all()
    return [contract_data(c) | {'title': d.title, 'can_edit': db.scalar(select(Document.id).where(Document.id == d.id,
        document_clause(user.id, member.role, True))) is not None and member.role != 'viewer'} for c, d in rows]


@router.get('/api/tenants/{tenant_id}/documents/{document_id}/contract')
def get_contract(tenant_id: str, document_id: str, user=Depends(current_user), db=Depends(get_db)):
    document_access(db, user, tenant_id, document_id)
    row = db.get(Contract, document_id)
    return contract_data(row) if row else None


@router.put('/api/tenants/{tenant_id}/documents/{document_id}/contract')
def put_contract(tenant_id: str, document_id: str, data: ContractInput, user=Depends(current_user), db=Depends(get_db)):
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    if doc.deleted_at or doc.status in {'processing', 'queued'}:
        raise HTTPException(409, 'Vertrag benötigt ein aktives, fertig verarbeitetes Dokument.')
    row = db.get(Contract, doc.id)
    if not row: row = Contract(document_id=doc.id); db.add(row)
    for key, value in data.model_dump().items(): setattr(row, key, value)
    doc.doc_type = 'Vertrag'
    from .features import invalidate_review
    invalidate_review(db, doc)
    audit(db, user, tenant_id, 'contract.updated', doc.id); db.commit()
    return contract_data(row)


@router.delete('/api/tenants/{tenant_id}/documents/{document_id}/contract')
def delete_contract(tenant_id: str, document_id: str, user=Depends(current_user), db=Depends(get_db)):
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    row = db.get(Contract, doc.id)
    if row: db.delete(row)
    audit(db, user, tenant_id, 'contract.removed', doc.id); db.commit()
    return {'ok': True}


class NoteInput(Input):
    body: str = Field(min_length=1, max_length=4000)
    @field_validator('body')
    @classmethod
    def nonempty(cls, value):
        if not value.strip(): raise ValueError('Notiz darf nicht leer sein.')
        return value.strip()


@router.get('/api/tenants/{tenant_id}/documents/{document_id}/notes')
def notes(tenant_id: str, document_id: str, user=Depends(current_user), db=Depends(get_db)):
    document_access(db, user, tenant_id, document_id)
    rows = db.execute(select(DocumentNote, User.name).join(User, DocumentNote.author_id == User.id)
        .where(DocumentNote.document_id == document_id).order_by(DocumentNote.created_at)).all()
    return [{k: getattr(n, k) for k in ['id', 'body', 'author_id', 'created_at', 'updated_at']} | {'author': name} for n, name in rows]


@router.post('/api/tenants/{tenant_id}/documents/{document_id}/notes')
def add_note(tenant_id: str, document_id: str, data: NoteInput, user=Depends(current_user), db=Depends(get_db)):
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    if doc.deleted_at: raise HTTPException(409, 'Dokument liegt im Papierkorb.')
    row = DocumentNote(document_id=document_id, author_id=user.id, body=data.body)
    db.add(row); audit(db, user, tenant_id, 'document.note_added', document_id); db.commit()
    return {'id': row.id}


def author_permission(db, user, tenant_id, row):
    if row.author_id != user.id and membership(db, user, tenant_id).role != 'owner':
        raise HTTPException(403, 'Nur Autor oder Eigentümer dürfen diesen Eintrag ändern.')


@router.put('/api/tenants/{tenant_id}/documents/{document_id}/notes/{note_id}')
def edit_note(tenant_id: str, document_id: str, note_id: str, data: NoteInput, user=Depends(current_user), db=Depends(get_db)):
    document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    row = db.scalar(select(DocumentNote).where(DocumentNote.id == note_id, DocumentNote.document_id == document_id))
    if not row: raise HTTPException(404, 'Notiz nicht gefunden.')
    author_permission(db, user, tenant_id, row)
    row.body, row.updated_at = data.body, now()
    audit(db, user, tenant_id, 'document.note_updated', document_id); db.commit()
    return {'ok': True}


@router.delete('/api/tenants/{tenant_id}/documents/{document_id}/notes/{note_id}')
def remove_note(tenant_id: str, document_id: str, note_id: str, user=Depends(current_user), db=Depends(get_db)):
    document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    row = db.scalar(select(DocumentNote).where(DocumentNote.id == note_id, DocumentNote.document_id == document_id))
    if not row: raise HTTPException(404, 'Notiz nicht gefunden.')
    author_permission(db, user, tenant_id, row)
    db.delete(row); audit(db, user, tenant_id, 'document.note_removed', document_id); db.commit()
    return {'ok': True}


def pdf_pages(path):
    from .processing import run
    try:
        info = run(['pdfinfo', str(path)], 20)
        match = re.search(r'^Pages:\s+(\d+)', info, re.M)
        if match and 1 <= int(match[1]) <= 100: return int(match[1])
    except Exception: pass
    raise HTTPException(422, 'PDF ist nicht lesbar oder hat mehr als 100 Seiten.')


def pdf_version(db, doc, number):
    row = db.scalar(select(DocumentVersion).where(DocumentVersion.document_id == doc.id, DocumentVersion.number == number))
    if not row or row.mime != 'application/pdf': raise HTTPException(422, 'PDF-Version benötigt.')
    path = version_path(doc.tenant_id, doc.id, number)
    if not path.is_file(): raise HTTPException(404, 'Versionsdatei fehlt.')
    return path


class AnnotationInput(Input):
    version: int = Field(ge=1, le=100000)
    page: int = Field(ge=1, le=100)
    rect: list[float] = Field(min_length=4, max_length=4)
    color: Literal['yellow', 'green', 'blue', 'pink'] = 'yellow'
    body: str = Field(default='', max_length=1000)
    @field_validator('rect')
    @classmethod
    def rectangle(cls, v):
        import math
        if any(not math.isfinite(x) or not 0 <= x <= 1 for x in v) or v[2] <= .001 or v[3] <= .001 or v[0]+v[2] > 1.00001 or v[1]+v[3] > 1.00001:
            raise ValueError('Ungültige Markierungsfläche.')
        return v


@router.get('/api/tenants/{tenant_id}/documents/{document_id}/annotations')
def annotations(tenant_id: str, document_id: str, version: int | None = None, user=Depends(current_user), db=Depends(get_db)):
    doc = document_access(db, user, tenant_id, document_id)
    number = version or doc.current_version
    path = pdf_version(db, doc, number)
    rows = db.scalars(select(Annotation).where(Annotation.document_id == doc.id, Annotation.version == number)).all()
    return {'version': number, 'pages': pdf_pages(path), 'items': [{k: getattr(a, k) for k in ['id', 'author_id', 'page', 'rect', 'color', 'body', 'created_at']} for a in rows]}


@router.get('/api/tenants/{tenant_id}/documents/{document_id}/pdf-page/{number}/{page}')
def pdf_page(tenant_id: str, document_id: str, number: int, page: int, user=Depends(current_user), db=Depends(get_db)):
    doc = document_access(db, user, tenant_id, document_id)
    path = pdf_version(db, doc, number)
    if not 1 <= page <= pdf_pages(path): raise HTTPException(404, 'Seite nicht gefunden.')
    directory = Path(tempfile.mkdtemp(prefix='dms-preview-'))
    try:
        from .processing import run
        run(['pdftoppm', '-f', str(page), '-l', str(page), '-scale-to', '1600', '-singlefile', '-png', str(path), str(directory/'page')], 45)
        return FileResponse(directory/'page.png', media_type='image/png', headers={'Cache-Control': 'no-store'},
            background=BackgroundTask(shutil.rmtree, directory, ignore_errors=True))
    except Exception:
        shutil.rmtree(directory, ignore_errors=True)
        raise HTTPException(422, 'PDF-Seite konnte nicht dargestellt werden.')


@router.post('/api/tenants/{tenant_id}/documents/{document_id}/annotations')
def add_annotation(tenant_id: str, document_id: str, data: AnnotationInput, user=Depends(current_user), db=Depends(get_db)):
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    if doc.deleted_at: raise HTTPException(409, 'Dokument liegt im Papierkorb.')
    path = pdf_version(db, doc, data.version)
    if data.page > pdf_pages(path): raise HTTPException(422, 'Seite nicht vorhanden.')
    row = Annotation(document_id=doc.id, author_id=user.id, **data.model_dump())
    db.add(row); audit(db, user, tenant_id, 'document.annotated', doc.id); db.commit()
    return {'id': row.id}


@router.delete('/api/tenants/{tenant_id}/documents/{document_id}/annotations/{annotation_id}')
def remove_annotation(tenant_id: str, document_id: str, annotation_id: str, user=Depends(current_user), db=Depends(get_db)):
    document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    row = db.scalar(select(Annotation).where(Annotation.id == annotation_id, Annotation.document_id == document_id))
    if not row: raise HTTPException(404, 'Markierung nicht gefunden.')
    author_permission(db, user, tenant_id, row)
    db.delete(row); audit(db, user, tenant_id, 'document.annotation_removed', document_id); db.commit()
    return {'ok': True}


class ShareInput(Input):
    expires_days: int = Field(default=7, ge=1, le=90)
    password: str = Field(default='', max_length=256)
    @field_validator('password')
    @classmethod
    def valid_password(cls, v):
        if v and len(v) < 12: raise ValueError('Link-Passwort benötigt mindestens 12 Zeichen.')
        return v


def share_permission(db, user, tenant_id, document_id):
    membership(db, user, tenant_id, 'manager')
    return document_access(db, user, tenant_id, document_id, edit=True, lock=True)


@router.get('/api/tenants/{tenant_id}/documents/{document_id}/shares')
def shares(tenant_id: str, document_id: str, user=Depends(current_user), db=Depends(get_db)):
    share_permission(db, user, tenant_id, document_id)
    rows = db.scalars(select(ShareLink).where(ShareLink.document_id == document_id).order_by(ShareLink.created_at.desc())).all()
    return [{k: getattr(s, k) for k in ['id', 'version', 'expires_at', 'revoked_at', 'created_at', 'downloads']} | {'password_protected': bool(s.password_hash)} for s in rows]


@router.post('/api/tenants/{tenant_id}/documents/{document_id}/shares')
def create_share(tenant_id: str, document_id: str, data: ShareInput, user=Depends(current_user), db=Depends(get_db)):
    doc = share_permission(db, user, tenant_id, document_id)
    if doc.deleted_at or doc.status not in {'ready', 'error'}: raise HTTPException(409, 'Nur aktive, fertig verarbeitete Dokumente freigeben.')
    token = secrets.token_urlsafe(40)
    row = ShareLink(document_id=doc.id, creator_id=user.id, token_hash=digest(token), version=doc.current_version,
        filename=doc.filename, password_hash=passwords.hash(data.password) if data.password else None, expires_at=now()+timedelta(days=data.expires_days))
    db.add(row); audit(db, user, tenant_id, 'document.shared', doc.id); db.commit()
    return {'id': row.id, 'path': '/share/' + token, 'expires_at': row.expires_at, 'version': row.version}


@router.delete('/api/tenants/{tenant_id}/documents/{document_id}/shares/{share_id}')
def revoke_share(tenant_id: str, document_id: str, share_id: str, user=Depends(current_user), db=Depends(get_db)):
    share_permission(db, user, tenant_id, document_id)
    row = db.scalar(select(ShareLink).where(ShareLink.id == share_id, ShareLink.document_id == document_id))
    if not row: raise HTTPException(404, 'Freigabe nicht gefunden.')
    row.revoked_at = now(); audit(db, user, tenant_id, 'document.share_revoked', document_id); db.commit()
    return {'ok': True}


def public_link(db, token):
    if not re.fullmatch(r'[A-Za-z0-9_-]{50,80}', token): raise HTTPException(404, 'Freigabe nicht verfügbar.')
    row = db.scalar(select(ShareLink).where(ShareLink.token_hash == digest(token), ShareLink.revoked_at.is_(None), ShareLink.expires_at > now()))
    doc = db.get(Document, row.document_id) if row else None
    creator = db.get(User, row.creator_id) if row else None
    if not doc or doc.deleted_at or not creator or not creator.active: raise HTTPException(404, 'Freigabe nicht verfügbar.')
    try: share_permission(db, creator, doc.tenant_id, doc.id)
    except HTTPException: raise HTTPException(404, 'Freigabe nicht verfügbar.')
    return row, doc


def cookie_name(row): return 'dms_share_' + row.id.replace('-', '')


def unlocked(request, row):
    if not row.password_hash: return True
    try: return signer.loads(request.cookies.get(cookie_name(row), ''), max_age=3600) == row.id + ':' + row.token_hash
    except BadSignature: return False


SHARE_HEADERS = {'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Robots-Tag': 'noindex, nofollow, noarchive'}


@router.get('/share/{token}', response_class=HTMLResponse)
def share_page(token: str, db=Depends(get_db)):
    status = 200
    try: public_link(db, token)
    except HTTPException: status = 404
    return HTMLResponse('''<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Dokumentfreigabe</title><link rel="stylesheet" href="/static/style.css"><script src="/static/share.js" defer></script></head><body><main class="share-shell"><section class="card settings-card" id="public-share"><h1>Dokumentfreigabe</h1><p>Freigabe wird geprüft …</p></section></main></body></html>''', headers=SHARE_HEADERS, status_code=status)


@router.get('/api/shares/{token}')
def share_info(token: str, request: Request, db=Depends(get_db)):
    row, doc = public_link(db, token)
    if not unlocked(request, row): return {'locked': True}
    return {'locked': False, 'filename': row.filename, 'version': row.version, 'expires_at': row.expires_at}


class UnlockInput(Input):
    password: str = Field(min_length=1, max_length=256)


@router.post('/api/shares/{token}/unlock')
def unlock_share(token: str, data: UnlockInput, request: Request, response: Response, db=Depends(get_db)):
    row, doc = public_link(db, token)
    # Shared IP bucket prevents bypassing throttling by changing the target link.
    key = digest('share-unlock:' + (request.client.host if request.client else 'unknown'))
    attempt = db.scalar(select(AuthAttempt).where(AuthAttempt.key == key).with_for_update())
    if not attempt or attempt.reset_at <= now():
        if attempt: db.delete(attempt); db.flush()
        attempt = AuthAttempt(key=key, count=0, reset_at=now()+timedelta(minutes=15)); db.add(attempt)
    if attempt.count >= 10: raise HTTPException(429, 'Zu viele Versuche. Später erneut versuchen.')
    attempt.count += 1
    try: db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(429, 'Gleichzeitige Passwortversuche. Später erneut versuchen.')
    if row.password_hash and not passwords.verify(data.password, row.password_hash): raise HTTPException(403, 'Passwort ungültig.')
    response.set_cookie(cookie_name(row), signer.dumps(row.id + ':' + row.token_hash), max_age=3600,
        httponly=True, secure=COOKIE_SECURE, samesite='strict', path='/api/shares/'+token)
    return {'ok': True}


@router.get('/api/shares/{token}/file')
def shared_file(token: str, request: Request, db=Depends(get_db)):
    row, doc = public_link(db, token)
    if not unlocked(request, row): raise HTTPException(403, 'Link-Passwort benötigt.')
    version = db.scalar(select(DocumentVersion).where(DocumentVersion.document_id == doc.id, DocumentVersion.number == row.version))
    path = version_path(doc.tenant_id, doc.id, row.version)
    if not version or not path.is_file(): raise HTTPException(404, 'Freigabe nicht verfügbar.')
    db.execute(update(ShareLink).where(ShareLink.id == row.id).values(downloads=ShareLink.downloads+1))
    audit(db, None, doc.tenant_id, 'document.share_downloaded', doc.id); db.commit()
    return FileResponse(path, media_type=version.mime, filename=row.filename, headers=SHARE_HEADERS)


@router.get('/api/admin/system-status')
def system_status(user=Depends(admin_user), db=Depends(get_db)):
    db.execute(select(1))
    disk = shutil.disk_usage(ROOT)
    heartbeat = db.get(Setting, 'worker.last_tick')
    last = heartbeat.value if heartbeat else None
    from datetime import datetime
    try: age = (now()-datetime.fromisoformat(last)).total_seconds() if last else None
    except ValueError: age = None
    phases = dict(db.execute(select(Document.status, func.count()).where(Document.deleted_at.is_(None)).group_by(Document.status)).all())
    last_backup = db.scalar(select(Audit.created_at).where(Audit.action == 'tenant.backup_exported').order_by(Audit.created_at.desc()).limit(1))
    integrations = db.execute(select(Integration.kind, Integration.enabled, Integration.last_run, Integration.last_status).where(Integration.kind.in_(['imap','folder','caldav']))).all()
    consume = Path(os.getenv('CONSUME_ROOT', '/data/consume'))
    return {'database': 'ok', 'worker': {'healthy': age is not None and age < 90, 'last_tick': last},
        'storage': {'total': disk.total, 'free': disk.free, 'used': disk.used, 'writable': os.access(ROOT, os.W_OK),
            'scanner_available': consume.is_dir() and os.access(consume, os.R_OK)},
        'documents': phases, 'ai_pending': db.scalar(select(func.count()).select_from(Document).where(Document.ai_pending.is_(True), Document.deleted_at.is_(None))),
        'ocr_available': all(shutil.which(x) for x in ['tesseract', 'pdftotext', 'pdftoppm']),
        'ocr_warnings': db.scalar(select(func.count()).select_from(Document).where(Document.ocr_failed.is_(True), Document.deleted_at.is_(None))),
        'last_tenant_backup_export': last_backup,
        'scanner_errors': db.scalar(select(func.count()).select_from(FolderImport).where(FolderImport.status == 'error')),
        'integrations': [{'kind':k, 'enabled':enabled, 'last_run':at, 'last_status':status} for k,enabled,at,status in integrations]}
