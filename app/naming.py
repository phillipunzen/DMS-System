"""Safe, idempotent download names; original version names stay immutable."""
import re
import unicodedata
from pathlib import Path
from sqlalchemy import select, func
from .db import Document, DocumentVersion

FIELDS = {'date', 'year', 'month', 'day', 'sender', 'supplier', 'doc_type', 'title', 'original_name', 'due_date', 'amount', 'id', 'version'}
PLACEHOLDER = re.compile(r'\{([a-z_]+)\}')
INVALID = re.compile(r'[\\/:*?"<>|]')
RESERVED = re.compile(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', re.I)
EXTENSIONS = {'application/pdf': '.pdf', 'text/plain': '.txt', 'image/png': '.png',
    'image/jpeg': '.jpg', 'image/tiff': '.tiff'}


def safe_part(value):
    value = unicodedata.normalize('NFC', str(value))
    value = ''.join(c for c in value if not unicodedata.category(c).startswith('C'))
    return re.sub(r'\s+', ' ', INVALID.sub('-', value)).strip(' .')


def validate_template(template):
    if not template:
        return None
    if any(unicodedata.category(c).startswith('C') for c in template):
        raise ValueError('Namensvorlagen dürfen keine Steuerzeichen enthalten.')
    template = template.strip()
    if not template or INVALID.search(template):
        raise ValueError('Namensvorlagen dürfen keine Pfade, Steuerzeichen oder Zeichen \\ / : * ? " < > | enthalten.')
    fields = PLACEHOLDER.findall(template)
    if any(f not in FIELDS for f in fields) or re.search(r'[{}]', PLACEHOLDER.sub('x', template)):
        raise ValueError('Unbekannter Platzhalter. Erlaubt: ' + ', '.join('{' + f + '}' for f in sorted(FIELDS)))
    if not safe_part(PLACEHOLDER.sub('x', template)):
        raise ValueError('Die Namensvorlage muss einen Dateinamen ergeben.')
    if re.search(r'\.(pdf|txt|png|jpe?g|tiff?)$', template, re.I):
        raise ValueError('Vorlage ohne Dateiendung eingeben; die ursprüngliche Endung wird automatisch ergänzt.')
    return template


def truncate(value, limit):
    return value.encode('utf-8')[:limit].decode('utf-8', errors='ignore').rstrip(' .')


def render_filename(db, doc, template):
    version = db.scalar(select(DocumentVersion).where(DocumentVersion.document_id == doc.id,
        DocumentVersion.tenant_id == doc.tenant_id, DocumentVersion.number == doc.current_version))
    original = version.filename if version else doc.filename
    created = doc.created_at
    values = {'date': created.strftime('%Y-%m-%d') if created else None,
        'year': created.strftime('%Y') if created else None, 'month': created.strftime('%m') if created else None,
        'day': created.strftime('%d') if created else None,
        'sender': doc.supplier, 'supplier': doc.supplier, 'doc_type': doc.doc_type, 'title': doc.title,
        'original_name': Path(original).stem, 'due_date': doc.due_date.isoformat() if doc.due_date else None,
        'amount': doc.amount, 'id': doc.id, 'version': doc.current_version}
    required = PLACEHOLDER.findall(template)
    if any(values[f] is None or not safe_part(values[f]) for f in required):
        return None  # Retry after metadata is available; never fabricate missing values.
    stem = safe_part(PLACEHOLDER.sub(lambda m: safe_part(values[m[1]]), template))
    if not stem:
        return None
    if RESERVED.match(stem):
        stem = '_' + stem
    extension = Path(original).suffix
    if not re.fullmatch(r'\.[A-Za-z0-9]{1,10}', extension):
        extension = EXTENSIONS.get(doc.mime, '')
    # NAS filesystems often limit names by UTF-8 bytes rather than characters.
    for attempt in range(1000):
        suffix = '' if attempt == 0 else '-' + doc.id + (f'-{attempt}' if attempt > 1 else '')
        filename = truncate(stem, 255 - len((suffix + extension).encode())) + suffix + extension
        collision = db.scalar(select(Document.id).where(Document.tenant_id == doc.tenant_id,
            Document.id != doc.id, Document.deleted_at.is_(None), func.lower(Document.filename) == filename.lower()).limit(1))
        if not collision:
            return filename
    return None
