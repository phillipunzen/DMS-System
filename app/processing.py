import json
import re
import subprocess
import tempfile
from pathlib import Path
from datetime import date
from datetime import timedelta
from sqlalchemy import select
from PIL import Image, ImageSequence
from .db import Rule, Integration, Audit, Setting, now
from .security import decrypt
from .storage import current_path
from dms_contracts.metadata import INSTRUCTIONS, SCHEMA, validate_metadata
from .privacy import minimise_text

Image.MAX_IMAGE_PIXELS = 40000000


def run(args, timeout=120):
    result = subprocess.run(args, capture_output=True, timeout=timeout, check=True)
    return result.stdout.decode('utf-8', errors='replace')


def extract_text(doc):
    path = current_path(doc)
    if doc.mime == 'text/plain':
        return path.read_text(errors='replace')[:2000000]
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        if doc.mime == 'application/pdf':
            info = run(['pdfinfo', str(path)], 30)
            match = re.search(r'^Pages:\s+(\d+)', info, re.M)
            if not match or int(match.group(1)) > 100:
                raise ValueError('PDF hat mehr als 100 Seiten oder ist nicht lesbar.')
            text = run(['pdftotext', '-layout', str(path), '-'], 60)
            # OCR even on mixed PDFs whose image pages contain little text.
            if len(text.strip()) > 80 * int(match.group(1)):
                return text[:2000000]
            if int(match.group(1)) > 50:
                raise ValueError('Bild-PDFs werden bis 50 Seiten unterstützt.')
            run(['pdftoppm', '-r', '120', '-png', str(path), str(tmp / 'page')], 180)
            images = sorted(tmp.glob('page-*.png'))
        else:
            images = []
            with Image.open(path) as image:
                for index, frame in enumerate(ImageSequence.Iterator(image)):
                    if index >= 50:
                        raise ValueError('Bilddokument hat mehr als 50 Seiten.')
                    target = tmp / f'page-{index:03}.png'
                    frame.convert('RGB').save(target)
                    images.append(target)
        return '\n\n'.join(run(['tesseract', str(p), 'stdout', '-l', 'deu+eng', '--psm', '3'], 120) for p in images)[:2000000]


def classify(db, doc):
    rules = db.scalars(select(Rule).where(Rule.tenant_id == doc.tenant_id, Rule.enabled.is_(True)).order_by(Rule.priority, Rule.id)).all()
    for rule in rules:
        if rule.contains.casefold() in str(getattr(doc, rule.field, '') or '').casefold():
            changed = doc.folder_id != rule.folder_id
            doc.folder_id = rule.folder_id
            return changed
    return False


def basic_metadata(doc):
    text = doc.text or ''
    if re.search(r'\brechnung\b|\binvoice\b', text, re.I):
        doc.doc_type = 'Rechnung'
    elif re.search(r'\bvertrag\b|\bagreement\b', text, re.I):
        doc.doc_type = 'Vertrag'
    elif re.search(r'\blieferschein\b', text, re.I):
        doc.doc_type = 'Lieferschein'
    due = re.search(r'(?:fällig(?:\s+am)?|zahlbar(?:\s+bis)?|zahlungsziel)[\s:]+(\d{1,2})\.(\d{1,2})\.(\d{4})', text, re.I)
    if due and not doc.due_date:
        try:
            doc.due_date = date(int(due[3]), int(due[2]), int(due[1]))
        except ValueError:
            pass
    amount = re.search(r'(?:gesamtbetrag|rechnungsbetrag|summe|gesamt)[^\d\n]{0,20}([\d.]+,\d{2})', text, re.I)
    if amount and not doc.amount:
        doc.amount = amount[1].replace('.', '').replace(',', '.')


def ai_metadata(db, doc, reviewed_text=None):
    import httpx
    blocked = db.scalar(select(Setting.value).where(Setting.key == 'ai_external_blocked'))
    if blocked == 'true':
        return False
    integration = db.scalar(select(Integration).where(Integration.tenant_id == doc.tenant_id, Integration.kind == 'ai', Integration.enabled.is_(True)).execution_options(populate_existing=True))
    if not integration:
        return False
    config = decrypt(integration.config_encrypted)
    if config.get('consent') is not True or doc.deleted_at:
        return False
    if reviewed_text is None and (config.get('privacy_mode', 'manual') != 'automatic' or config.get('automatic_consent') is not True):
        return False
    text = minimise_text(doc.text if reviewed_text is None else reviewed_text, config.get('text_limit', 10000))['text']
    if not text.strip():
        return False
    schema = SCHEMA
    if config.get('provider', 'openai') == 'codex':
        from . import codex_client
        if not codex_client.enabled_for(db, doc.tenant_id):
            raise ValueError('Codex ist für diesen Mandanten nicht freigegeben.')
    db.add(Audit(tenant_id=doc.tenant_id, action='document.ai_requested', detail=doc.id))
    db.commit()
    if config.get('provider', 'openai') == 'codex':
        result = codex_client.request('POST', 'extract', {'text': text, 'model': config.get('model') or None}, timeout=210)['metadata']
    else:
        with httpx.Client(timeout=90) as client:
            response = client.post(config.get('base_url', 'https://api.openai.com/v1').rstrip('/') + '/responses', headers={'Authorization': 'Bearer ' + config['api_key']}, json={'model': config['model'], 'store': False, 'instructions': INSTRUCTIONS, 'input': text, 'text': {'format': {'type': 'json_schema', 'name': 'document_metadata', 'strict': True, 'schema': schema}}})
            response.raise_for_status()
            payload = response.json()
        if payload.get('status') != 'completed':
            raise ValueError('KI-Antwort wurde nicht abgeschlossen.')
        texts = [part['text'] for item in payload.get('output', []) if item.get('type') == 'message' for part in item.get('content', []) if part.get('type') == 'output_text']
        result = json.loads(''.join(texts))
    result = validate_metadata(result)
    if result.get('supplier') and not doc.supplier:
        doc.supplier = result['supplier'][:150]
    if result.get('doc_type') in {'Rechnung', 'Vertrag', 'Lieferschein', 'Sonstiges'}:
        doc.doc_type = result['doc_type']
    if result.get('amount') and re.fullmatch(r'\d{1,12}(\.\d{1,2})?', result['amount']) and not doc.amount:
        doc.amount = result['amount']
    if result.get('due_date') and not doc.due_date:
        try:
            doc.due_date = date.fromisoformat(result['due_date'])
        except ValueError:
            pass
    integration.last_run = now()
    integration.last_status = 'Metadaten extrahiert. Bitte fachlich prüfen.'
    db.add(Audit(tenant_id=doc.tenant_id, action='document.ai_completed', detail=doc.id))
    return True


def process_document(db, doc):
    doc.text = extract_text(doc)
    basic_metadata(doc)
    # OCR text survives an unavailable external AI service.
    db.commit()
    doc.error = None
    try:
        ai_metadata(db, doc)
        doc.ai_pending, doc.ai_retry_at, doc.ai_attempts = False, None, 0
    except Exception:
        # A cloud outage never prevents local classification or access to the scan.
        doc.ai_pending, doc.ai_attempts = True, 1
        doc.ai_retry_at = now() + timedelta(minutes=5)
        doc.error = 'Lokale OCR abgeschlossen. KI-Auswertung ausstehend; Anmeldung und Verbindung prüfen. Automatische Wiederholung folgt.'
    classify(db, doc)
    doc.status = 'ready'
    doc.processed_at = now()


def retry_ai(db, doc):
    try:
        changed = ai_metadata(db, doc)
        if changed:
            from .features import invalidate_review
            invalidate_review(db, doc)
            classify(db, doc)
        doc.ai_pending, doc.ai_retry_at, doc.ai_attempts, doc.error = False, None, 0, None
    except Exception:
        db.rollback()
        doc = db.get(type(doc), doc.id)
        doc.ai_attempts += 1
        doc.ai_retry_at = now() + timedelta(minutes=min(60, 5 * 2 ** min(doc.ai_attempts, 4)))
        doc.error = 'KI-Auswertung ausstehend; Anmeldung, Nutzungslimit und Verbindung prüfen.'
    doc.status = 'ready'
    db.commit()
