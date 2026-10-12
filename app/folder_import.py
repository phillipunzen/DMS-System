"""Tenant-scoped scanner inbox with durable import receipts before source removal."""
import errno
import fcntl
import hashlib
import os
import shutil
import stat
import time
import uuid
from pathlib import Path
from fastapi import HTTPException
from sqlalchemy import select
from .db import Audit, Document, DocumentVersion, Folder, FolderImport, Integration, Membership, Tenant, now
from .storage import path_for, save_document

ROOT = Path(os.getenv('CONSUME_ROOT', '/data/consume')).resolve()


def directories(tenant_id):
    uuid.UUID(tenant_id)
    result = {'tenant': ROOT / tenant_id, 'incoming': ROOT / tenant_id / 'eingang',
              'processed': ROOT / tenant_id / 'verarbeitet'}
    # Only the server-controlled mount and a tenant UUID determine these paths.
    for path in result.values():
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            raise ValueError('Unsicherer Importpfad')
        path.mkdir(parents=True, mode=0o750, exist_ok=True)
        if not path.is_dir():
            raise ValueError('Importpfad ist kein Verzeichnis')
    return result


def public_paths(tenant_id):
    uuid.UUID(tenant_id)
    host_root = os.getenv('CONSUME_HOST_PATH', '')
    root = Path(host_root) if host_root else ROOT
    return {'incoming': str(root / tenant_id / 'eingang'),
            'processed': str(root / tenant_id / 'verarbeitet')}


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def source_key(path, info):
    return hashlib.sha256((path.name + repr(signature(info))).encode()).hexdigest()


def open_source(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('Keine reguläre Datei')
    return os.fdopen(fd, 'rb')


def unchanged(path, stream, expected):
    try:
        return signature(os.fstat(stream.fileno())) == expected and signature(path.lstat()) == expected
    except FileNotFoundError:
        return False


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                raise
    finally:
        os.close(fd)


def finalize_source(db, receipt, paths):
    """Retry safely after a crash between DB commit and source deletion/move."""
    source = paths['incoming'] / receipt.filename
    if not source.exists() and not source.is_symlink():
        receipt.status = 'done'
        db.commit()
        return
    with open_source(source) as stream:
        info = os.fstat(stream.fileno())
        if source_key(source, info) != receipt.source_key:
            receipt.status = 'changed'  # A newer scan using the same filename remains untouched.
            db.commit()
            return
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        doc = db.get(Document, receipt.document_id)
        first = db.scalar(select(DocumentVersion).where(DocumentVersion.document_id == receipt.document_id, DocumentVersion.number == 1))
        if not doc or doc.tenant_id != receipt.tenant_id or digest != (first.sha256 if first else doc.sha256):
            raise ValueError('Importbeleg passt nicht zur Quelldatei')
        # Never delete a source unless its stored original is still intact and readable.
        with path_for(doc.tenant_id, doc.id).open('rb') as stored:
            if hashlib.file_digest(stored, 'sha256').hexdigest() != digest:
                raise ValueError('DMS-Original ist nicht verfügbar')
        if receipt.action == 'archive':
            target = paths['processed'] / (receipt.id + '-' + receipt.filename.encode('utf-8')[:180].decode('utf-8', errors='ignore'))
            try:
                with target.open('xb') as output:
                    stream.seek(0)
                    shutil.copyfileobj(stream, output)
                    output.flush()
                    os.fsync(output.fileno())
                target.chmod(0o640)
                sync_directory(paths['processed'])
            except FileExistsError:
                with open_source(target) as previous:
                    if hashlib.file_digest(previous, 'sha256').hexdigest() != digest:
                        raise ValueError('Zieldatei stimmt nicht mit dem Import überein')
            except Exception:
                target.unlink(missing_ok=True)
                raise
        if not unchanged(source, stream, signature(info)):
            receipt.status = 'changed'
            db.commit()
            return
        source.unlink()
        sync_directory(paths['incoming'])
    receipt.status = 'done'
    receipt.error = None
    db.commit()


def import_directory(db, integration, config, retry_errors=False):
    paths = directories(integration.tenant_id)
    # API and background worker are separate processes. The shared file lock spans
    # the per-file DB commits and source cleanup, including on NAS with POSIX locks.
    lock_fd = os.open(paths['tenant'] / '.import.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o640)
    imported = duplicates = failed = waiting = 0
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 'Der Importordner wird bereits geprüft.'
        # Recheck configuration under a DB lock; saving settings uses the same row.
        integration = db.scalar(select(Integration).where(Integration.id == integration.id).with_for_update().execution_options(populate_existing=True))
        if not integration.enabled:
            db.rollback()
            return 'Importordner ist deaktiviert.'
        from .security import decrypt
        config = decrypt(integration.config_encrypted)
        db.commit()
        pending = db.scalars(select(FolderImport).where(FolderImport.integration_id == integration.id, FolderImport.status == 'pending')).all()
        for receipt in pending:
            try:
                finalize_source(db, receipt, paths)
            except Exception:
                db.rollback()
                receipt.error = 'Quelle bleibt erhalten: gespeichertes Original und Dateizugriff prüfen.'
                db.commit()
                failed += 1
        candidates = sorted(paths['incoming'].iterdir(), key=lambda p: p.name)
        attempted = 0
        for source in candidates:
            if source.name.startswith('.') or source.suffix.lower() in {'.tmp', '.part', '.partial', '.crdownload'}:
                continue
            info = source.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue  # No symlinks, subdirectories, sockets or device files.
            if time.time() - info.st_mtime < config.get('settle_seconds', 30):
                waiting += 1
                continue
            key = source_key(source, info)
            receipt = db.scalar(select(FolderImport).where(FolderImport.integration_id == integration.id, FolderImport.source_key == key))
            if receipt:
                if receipt.status != 'error':
                    continue
                if not retry_errors and (now() - receipt.updated_at).total_seconds() < 300:
                    failed += 1
                    continue
            if attempted >= 30:
                break
            attempted += 1
            doc = None
            created_doc = False
            try:
                db.scalar(select(Tenant).where(Tenant.id == integration.tenant_id).with_for_update())
                owner = db.scalar(select(Membership.user_id).where(Membership.tenant_id == integration.tenant_id, Membership.role == 'owner'))
                if not owner:
                    raise ValueError('Kein Mandanteneigentümer')
                with open_source(source) as stream:
                    if signature(os.fstat(stream.fileno())) != signature(info):
                        db.rollback()
                        waiting += 1
                        continue
                    try:
                        doc = save_document(db, integration.tenant_id, owner, source.name, stream, source='scanner')
                        created_doc = True
                    except HTTPException as exc:
                        if exc.status_code != 409:
                            raise
                        stream.seek(0)
                        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                        doc = db.scalar(select(Document).where(Document.tenant_id == integration.tenant_id, Document.sha256 == digest, Document.deleted_at.is_(None)))
                        if not doc:
                            raise ValueError('Duplikat nicht gefunden')
                        # Preserve duplicate sources: only a fresh import may remove its input.
                        raise HTTPException(409, 'Duplikat: bereits im DMS vorhanden. Quelldatei bleibt erhalten.')
                    if not unchanged(source, stream, signature(info)):
                        raise ValueError('Die Quelldatei wurde während des Imports geändert')
                folder_id = config.get('folder_id')
                folder = db.scalar(select(Folder).where(Folder.tenant_id == integration.tenant_id,
                    Folder.id == folder_id if folder_id else Folder.name == 'Eingang'))
                doc.folder_id = folder.id if folder else None
                with path_for(doc.tenant_id, doc.id).open('rb') as stored:
                    os.fsync(stored.fileno())
                sync_directory(path_for(doc.tenant_id, doc.id).parent)
                sync_directory(path_for(doc.tenant_id, doc.id).parent.parent)
                sync_directory(path_for(doc.tenant_id, doc.id).parent.parent.parent)
                if not receipt:
                    receipt = FolderImport(integration_id=integration.id, tenant_id=integration.tenant_id, source_key=key, filename=source.name)
                    db.add(receipt)
                receipt.document_id = doc.id
                receipt.action = config.get('after_import', 'delete')
                receipt.status = 'pending'
                receipt.error = None
                receipt.updated_at = now()
                db.add(Audit(tenant_id=integration.tenant_id, actor_id=owner, action='document.imported', detail=doc.id))
                db.commit()  # Removal is strictly after the durable import transaction.
            except Exception as exc:
                new_doc_id = doc.id if doc and created_doc else None
                db.rollback()
                if new_doc_id and not db.get(Document, new_doc_id):
                    shutil.rmtree(path_for(integration.tenant_id, new_doc_id).parent, ignore_errors=True)
                receipt = db.scalar(select(FolderImport).where(FolderImport.integration_id == integration.id, FolderImport.source_key == key))
                if not receipt:
                    receipt = FolderImport(integration_id=integration.id, tenant_id=integration.tenant_id, source_key=key, filename=source.name)
                    db.add(receipt)
                receipt.status = 'error'
                receipt.error = str(exc.detail)[:255] if isinstance(exc, HTTPException) else 'Import fehlgeschlagen; Datei bleibt erhalten. Speicher und Dateizugriff prüfen.'
                receipt.updated_at = now()
                db.commit()
                if isinstance(exc, HTTPException) and exc.status_code == 409:
                    duplicates += 1
                else:
                    failed += 1
                continue
            imported += 1
            try:
                finalize_source(db, receipt, paths)
            except Exception:
                db.rollback()
                receipt.error = 'Import gespeichert; Quelldatei konnte noch nicht entfernt werden. Dateizugriff prüfen.'
                db.commit()
                failed += 1  # Pending receipt remains retryable; never undo the committed document.
        return f'{imported} importiert, {duplicates} Duplikate, {failed} fehlgeschlagen, {waiting} noch nicht fertig geschrieben.'
    finally:
        os.close(lock_fd)


def current_errors(db, integration):
    incoming = ROOT / integration.tenant_id / 'eingang'
    errors = []
    receipts = db.scalars(select(FolderImport).where(FolderImport.integration_id == integration.id,
        FolderImport.error.is_not(None)).order_by(FolderImport.updated_at.desc()))
    for receipt in receipts:
        source = incoming / receipt.filename
        try:
            if source.is_symlink() or source_key(source, source.lstat()) != receipt.source_key:
                continue
        except FileNotFoundError:
            continue
        errors.append({'filename': receipt.filename, 'error': receipt.error})
        if len(errors) >= 10:
            break
    return errors
