"""Password-encrypted tenant archives; restores always create an isolated new tenant."""
import hashlib
import json
import os
import secrets
import shutil
import tempfile
import uuid
import zipfile
from datetime import date, datetime
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, File, Form, UploadFile
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask
from pydantic import BaseModel, Field, ConfigDict
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from sqlalchemy import select
from .db import *
from .security import current_user, membership, audit, setting
from .storage import version_path, path_for, ROOT, ALLOWED

router = APIRouter()
MAX_BACKUP = int(os.getenv('MAX_TENANT_BACKUP_MB', '250')) * 1024 * 1024
MAGIC = b'ARCHIVRAUM-BACKUP-1\n'


class BackupInput(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class BackupFolder(BaseModel):
    id: uuid.UUID
    name: str = Field(min_length=1, max_length=150)
    color: str = Field(max_length=20)
    restricted: bool = False


class BackupVersion(BaseModel):
    number: int = Field(ge=1, le=100000)
    filename: str = Field(min_length=1, max_length=255)
    mime: str = Field(max_length=100)
    size: int = Field(gt=0, le=50 * 1024 * 1024)
    sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    note: str = Field(default='', max_length=255)
    created_at: datetime


class BackupDocument(BaseModel):
    id: uuid.UUID
    title: str = Field(min_length=1, max_length=255)
    folder_id: uuid.UUID | None = None
    current_version: int = Field(ge=1, le=100000)
    restricted: bool = False
    text: str = Field(default='', max_length=2000000)
    supplier: str = Field(default='', max_length=150)
    doc_type: str = Field(default='Sonstiges', max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=20)
    amount: str | None = Field(default=None, pattern=r'^\d{1,12}(\.\d{1,2})?$')
    due_date: date | None = None
    paid: bool = False
    deleted_at: datetime | None = None
    created_at: datetime
    versions: list[BackupVersion] = Field(min_length=1, max_length=100000)


class BackupRule(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    field: str = Field(pattern=r'^(text|supplier|doc_type|title|filename)$')
    contains: str = Field(min_length=1, max_length=150)
    folder_id: uuid.UUID
    priority: int
    enabled: bool = True


class Manifest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    format: str
    name: str = Field(min_length=1, max_length=150)
    workflow_enabled: bool = False
    folders: list[BackupFolder] = Field(max_length=10000)
    documents: list[BackupDocument] = Field(max_length=10000)
    rules: list[BackupRule] = Field(default_factory=list, max_length=10000)
    access_lists: dict = Field(default_factory=dict)
    reviews: list[dict] = Field(default_factory=list, max_length=100000)


def key(password, salt):
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(password.encode())


def encrypt_file(source, target, password):
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES(key(password, salt)), modes.GCM(iv)).encryptor()
    header = MAGIC + salt + iv
    encryptor.authenticate_additional_data(header)
    with source.open('rb') as input, target.open('wb') as output:
        output.write(header)
        while chunk := input.read(1024 * 1024): output.write(encryptor.update(chunk))
        output.write(encryptor.finalize()); output.write(encryptor.tag)
    target.chmod(0o600)


def decrypt_file(source, target, password):
    if source.stat().st_size > MAX_BACKUP + 1024 * 1024:
        raise HTTPException(413, 'Sicherung überschreitet die konfigurierte Grenze.')
    with source.open('rb') as input:
        header = input.read(len(MAGIC) + 28)
        if not header.startswith(MAGIC) or len(header) != len(MAGIC) + 28:
            raise ValueError('Format')
        input.seek(-16, 2); tag = input.read(16)
        decryptor = Cipher(algorithms.AES(key(password, header[len(MAGIC):len(MAGIC) + 16])), modes.GCM(header[-12:], tag)).decryptor()
        decryptor.authenticate_additional_data(header)
        input.seek(len(header)); remaining = source.stat().st_size - len(header) - 16
        with target.open('wb') as output:
            while remaining > 0:
                chunk = input.read(min(1024 * 1024, remaining))
                if not chunk: raise ValueError('Truncated')
                remaining -= len(chunk); output.write(decryptor.update(chunk))
            output.write(decryptor.finalize())
        target.chmod(0o600)


@router.get('/api/tenants/{tenant_id}/backup')
def backup_info(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    return {'max_mb': MAX_BACKUP // 1024 // 1024, 'encrypted': True}


@router.post('/api/tenants/{tenant_id}/backup')
def export_tenant(tenant_id: str, data: BackupInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    docs = db.scalars(select(Document).where(Document.tenant_id == tenant_id).with_for_update()).all()
    if any(d.status == 'processing' for d in docs):
        raise HTTPException(409, 'Eine Verarbeitung läuft. Sicherung nach Abschluss erneut starten.')
    directory = Path(tempfile.mkdtemp(prefix='dms-backup-'))
    try:
        folder_rows = db.scalars(select(Folder).where(Folder.tenant_id == tenant_id)).all()
        payload = {'format': 'archivraum-tenant-v1', 'name': tenant.name, 'workflow_enabled': tenant.workflow_enabled,
            'folders': [{k: getattr(f, k) for k in ['id', 'name', 'color', 'restricted']} for f in folder_rows], 'documents': [],
            'rules': [{k: getattr(r, k) for k in ['name', 'field', 'contains', 'folder_id', 'priority', 'enabled']} for r in db.scalars(select(Rule).where(Rule.tenant_id == tenant_id))],
            'access_lists': {'folders': {}, 'documents': {}}, 'reviews': []}
        for model, scope, parent, rows in [(FolderGrant, 'folders', 'folder_id', folder_rows), (DocumentGrant, 'documents', 'document_id', docs)]:
            for item in rows:
                grants = db.execute(select(model, User.email).join(User, model.user_id == User.id).where(getattr(model, parent) == item.id)).all()
                payload['access_lists'][scope][item.id] = [{'email': email, 'can_edit': grant.can_edit} for grant, email in grants]
        total = 0
        with zipfile.ZipFile(directory / 'archive.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for doc in docs:
                item = {k: getattr(doc, k) for k in ['id', 'title', 'folder_id', 'current_version', 'restricted', 'text', 'supplier', 'doc_type', 'tags', 'amount', 'due_date', 'paid', 'deleted_at', 'created_at']}
                versions = db.scalars(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.number)).all()
                item['versions'] = []
                if not versions: raise ValueError('Missing version')
                for v in versions:
                    path = version_path(tenant_id, doc.id, v.number)
                    total += v.size
                    if total > MAX_BACKUP: raise HTTPException(413, 'Dokumente und Versionen überschreiten das Sicherungslimit.')
                    with path.open('rb') as source:
                        if hashlib.file_digest(source, 'sha256').hexdigest() != v.sha256: raise ValueError('Checksum')
                    archive.write(path, 'blobs/' + doc.id + '/' + str(v.number))
                    item['versions'].append({k: getattr(v, k) for k in ['number', 'filename', 'mime', 'size', 'sha256', 'note', 'created_at']})
                payload['documents'].append(item)
            # Review history is exported, but no live assignments or account credentials.
            for review in db.scalars(select(Review).where(Review.tenant_id == tenant_id)):
                record = {k: getattr(review, k) for k in ['document_id', 'version', 'status', 'note', 'created_at', 'decided_at']}
                record['requester'] = db.get(User, review.requester_id).email
                record['reviewer'] = db.get(User, review.reviewer_id).email
                payload['reviews'].append(record)
            manifest = json.dumps(payload, default=lambda x: x.isoformat(), ensure_ascii=False).encode()
            if len(manifest) > 20 * 1024 * 1024: raise HTTPException(413, 'Zu viele Metadaten für diese Sicherung.')
            archive.writestr('manifest.json', manifest)
        if (directory / 'archive.zip').stat().st_size > MAX_BACKUP + 1024 * 1024:
            raise HTTPException(413, 'Sicherungsdatei überschreitet die konfigurierte Grenze.')
        encrypt_file(directory / 'archive.zip', directory / 'archive.dmsbackup', data.password)
        audit(db, user, tenant_id, 'tenant.backup_exported', str(len(docs)) + ' Dokumente'); db.commit()
        return FileResponse(directory / 'archive.dmsbackup', filename='archiv-' + tenant_id + '.dmsbackup', media_type='application/octet-stream', headers={'Cache-Control': 'no-store'}, background=BackgroundTask(shutil.rmtree, directory, True))
    except HTTPException:
        shutil.rmtree(directory, ignore_errors=True); raise
    except Exception:
        shutil.rmtree(directory, ignore_errors=True)
        raise HTTPException(409, 'Sicherung fehlgeschlagen. Originaldateien, Prüfsummen und Speicherplatz prüfen.')


@router.post('/api/tenants/restore-backup')
def restore_tenant(file: UploadFile = File(...), password: str = Form(min_length=12, max_length=256), name: str = Form(min_length=1, max_length=150), user=Depends(current_user), db=Depends(get_db)):
    if not user.admin and setting(db, 'tenant_creation_enabled', 'true') != 'true':
        raise HTTPException(403, 'Erstellen neuer Dokumentenräume ist deaktiviert.')
    destination = None
    with tempfile.TemporaryDirectory(prefix='dms-restore-') as directory:
        tmp = Path(directory)
        try:
            with (tmp / 'input').open('wb') as output:
                size = 0
                while chunk := file.file.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_BACKUP + 1024 * 1024: raise HTTPException(413, 'Sicherung ist zu groß.')
                    output.write(chunk)
            decrypt_file(tmp / 'input', tmp / 'archive.zip', password)
            with zipfile.ZipFile(tmp / 'archive.zip') as archive:
                entries = archive.infolist()
                if len(entries) > 100001 or len({e.filename for e in entries}) != len(entries) or sum(e.file_size for e in entries) > MAX_BACKUP + 20 * 1024 * 1024:
                    raise ValueError('Archive limits')
                if archive.getinfo('manifest.json').file_size > 20 * 1024 * 1024: raise ValueError('Manifest limits')
                manifest = Manifest.model_validate_json(archive.read('manifest.json'))
                if manifest.format != 'archivraum-tenant-v1': raise ValueError('Format')
                folder_ids = [str(f.id) for f in manifest.folders]
                doc_ids = [str(d.id) for d in manifest.documents]
                if len(set(folder_ids)) != len(folder_ids) or len(set(doc_ids)) != len(doc_ids): raise ValueError('Duplicate IDs')
                if len({f.name for f in manifest.folders}) != len(manifest.folders): raise ValueError('Duplicate folders')
                tenant = Tenant(id=uid(), name=name, workflow_enabled=manifest.workflow_enabled)
                db.add(tenant); db.flush()
                db.add(Membership(tenant_id=tenant.id, user_id=user.id, role='owner'))
                destination = ROOT / tenant.id
                destination.mkdir(parents=True, mode=0o700, exist_ok=False)
                mapping = {}
                for f in manifest.folders:
                    new_id = uid(); mapping[str(f.id)] = new_id
                    db.add(Folder(id=new_id, tenant_id=tenant.id, name=f.name, color=f.color, restricted=f.restricted))
                db.flush()
                total = 0
                for imported in manifest.documents:
                    if imported.folder_id and str(imported.folder_id) not in mapping: raise ValueError('Folder')
                    numbers = [v.number for v in imported.versions]
                    if len(set(numbers)) != len(numbers) or sorted(numbers) != list(range(1, max(numbers) + 1)) or imported.current_version != max(numbers): raise ValueError('Versions')
                    current = next(v for v in imported.versions if v.number == imported.current_version)
                    doc = Document(id=uid(), tenant_id=tenant.id, uploader_id=user.id, folder_id=mapping.get(str(imported.folder_id)), title=imported.title,
                        filename=current.filename, mime=current.mime, size=current.size, sha256=current.sha256, current_version=imported.current_version,
                        text=imported.text, supplier=imported.supplier, doc_type=imported.doc_type, tags=imported.tags,
                        amount=imported.amount, due_date=imported.due_date, paid=imported.paid, restricted=imported.restricted,
                        status='ready', source='restore', created_at=imported.created_at.replace(tzinfo=None), deleted_at=imported.deleted_at.replace(tzinfo=None) if imported.deleted_at else None,
                        processed_at=now(), review_status='unassigned' if tenant.workflow_enabled else 'none')
                    db.add(doc); db.flush()
                    for v in imported.versions:
                        if v.mime not in ALLOWED: raise ValueError('Mime')
                        total += v.size
                        if total > MAX_BACKUP or total > tenant.quota_mb * 1024 * 1024: raise HTTPException(413, 'Wiederherstellung überschreitet das Speicherlimit.')
                        blob = 'blobs/' + str(imported.id) + '/' + str(v.number)
                        if archive.getinfo(blob).file_size != v.size: raise ValueError('Size')
                        path = version_path(tenant.id, doc.id, v.number)
                        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                        checksum = hashlib.sha256(); written = 0
                        with archive.open(blob) as source, path.open('xb') as output:
                            while chunk := source.read(1024 * 1024):
                                written += len(chunk)
                                if written > v.size: raise ValueError('Size')
                                output.write(chunk); checksum.update(chunk)
                            output.flush(); os.fsync(output.fileno())
                        path.chmod(0o600)
                        if written != v.size or checksum.hexdigest() != v.sha256: raise ValueError('Checksum')
                        db.add(DocumentVersion(tenant_id=tenant.id, document_id=doc.id, number=v.number, filename=v.filename, mime=v.mime, size=v.size, sha256=v.sha256, uploader_id=user.id, note=v.note, created_at=v.created_at.replace(tzinfo=None)))
                for rule in manifest.rules:
                    if str(rule.folder_id) not in mapping: raise ValueError('Rule folder')
                    db.add(Rule(tenant_id=tenant.id, name=rule.name, field=rule.field, contains=rule.contains, folder_id=mapping[str(rule.folder_id)], priority=rule.priority, enabled=rule.enabled))
                # Preserve archived access and review details for the owner's inspection.
                # Never auto-enrol former users, import secrets or queue cloud processing.
                db.add(Setting(key='restore-history:' + tenant.id, value=json.dumps({'access_lists': manifest.access_lists, 'reviews': manifest.reviews}, ensure_ascii=False)))
                audit(db, user, tenant.id, 'tenant.backup_restored', str(len(manifest.documents)) + ' Dokumente; frühere Freigaben erfordern erneute Prüfung')
                db.commit()
                return {'id': tenant.id, 'name': tenant.name, 'documents': len(manifest.documents)}
        except HTTPException:
            db.rollback()
            if destination: shutil.rmtree(destination, ignore_errors=True)
            raise
        except Exception:
            db.rollback()
            if destination: shutil.rmtree(destination, ignore_errors=True)
            raise HTTPException(422, 'Sicherung ungültig, beschädigt oder Passwort falsch. Es wurde kein Dokumentenraum angelegt.')


@router.get('/api/tenants/{tenant_id}/restore-history')
def restore_history(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    value = setting(db, 'restore-history:' + tenant_id)
    return json.loads(value) if value else {'access_lists': {}, 'reviews': []}
