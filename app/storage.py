import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from fastapi import HTTPException
from sqlalchemy import select, func, or_
import magic
from .db import Document, DocumentVersion, Tenant, uid

ROOT = Path(os.getenv('STORAGE_ROOT', '/data/documents')).resolve()
MAX_UPLOAD = int(os.getenv('MAX_UPLOAD_MB', '50')) * 1024 * 1024
ALLOWED = {'application/pdf', 'image/png', 'image/jpeg', 'image/tiff', 'text/plain'}


def path_for(tenant_id, document_id):
    import uuid
    uuid.UUID(tenant_id)
    uuid.UUID(document_id)
    p = ROOT / tenant_id / document_id / 'original'
    if not p.resolve().is_relative_to(ROOT):
        raise ValueError('Ungültiger Speicherpfad')
    return p


def version_path(tenant_id, document_id, number):
    if not isinstance(number, int) or not 1 <= number <= 100000:
        raise ValueError('Ungültige Dokumentversion')
    original = path_for(tenant_id, document_id)
    return original if number == 1 else original.parent / 'versions' / str(number) / 'original'


def current_path(doc):
    return version_path(doc.tenant_id, doc.id, doc.current_version or 1)


def stage_upload(stream):
    ROOT.mkdir(parents=True, exist_ok=True)
    path = None
    try:
        with tempfile.NamedTemporaryFile(dir=ROOT, delete=False) as temp:
            path = Path(temp.name)
            size, sha = 0, hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, 'Datei überschreitet das Upload-Limit.')
                sha.update(chunk); temp.write(chunk)
            temp.flush(); os.fsync(temp.fileno())
        if not size:
            raise HTTPException(422, 'Die Datei ist leer.')
        mime = magic.from_file(str(path), mime=True)
        if mime not in ALLOWED:
            raise HTTPException(415, 'Erlaubt sind PDF, PNG, JPEG, TIFF und Textdateien.')
        return path, size, sha.hexdigest(), mime
    except Exception:
        if path:
            path.unlink(missing_ok=True)
        raise


def save_document(db, tenant_id, user_id, filename, stream, source='upload'):
    ROOT.mkdir(parents=True, exist_ok=True)
    temp_path = None
    destination = None
    try:
        with tempfile.NamedTemporaryFile(dir=ROOT, delete=False) as temp:
            temp_path = Path(temp.name)
            size = 0
            sha = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, 'Datei überschreitet das Upload-Limit.')
                sha.update(chunk)
                temp.write(chunk)
        if not size:
            raise HTTPException(422, 'Die Datei ist leer.')
        mime = magic.from_file(str(temp_path), mime=True)
        if mime not in ALLOWED:
            raise HTTPException(415, 'Erlaubt sind PDF, PNG, JPEG, TIFF und Textdateien.')
        duplicate = db.scalar(select(Document).where(Document.tenant_id == tenant_id, Document.deleted_at.is_(None),
            or_(Document.sha256 == sha.hexdigest(), Document.id.in_(select(DocumentVersion.document_id).where(DocumentVersion.tenant_id == tenant_id, DocumentVersion.sha256 == sha.hexdigest())))))
        if duplicate:
            raise HTTPException(409, 'Dieses Dokument existiert bereits in diesem Dokumentenraum.')
        tenant = db.get(Tenant, tenant_id)
        from .permissions import used_bytes
        used = used_bytes(db, tenant_id)
        if used + size > tenant.quota_mb * 1024 * 1024:
            raise HTTPException(413, 'Das Speicherlimit dieses Mandanten ist erreicht.')
        filename = Path(filename.replace('\\', '/')).name[:255] or 'Dokument'
        doc = Document(id=uid(), tenant_id=tenant_id, uploader_id=user_id, filename=filename, title=Path(filename).stem[:255], mime=mime, size=size, sha256=sha.hexdigest(), source=source)
        doc.review_status = 'unassigned' if tenant.workflow_enabled else 'none'
        destination = path_for(tenant_id, doc.id)
        destination.parent.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination.parent.mkdir(exist_ok=False, mode=0o700)
        shutil.move(temp_path, destination)
        os.chmod(destination, 0o600)
        db.add(doc)
        db.flush()
        db.add(DocumentVersion(tenant_id=tenant_id, document_id=doc.id, number=1, filename=filename, mime=mime, size=size, sha256=doc.sha256, uploader_id=user_id))
        db.flush()
        return doc
    except Exception:
        if destination and destination.parent.exists():
            shutil.rmtree(destination.parent)
        raise
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)
