"""Durable deletion intent lives on the document until all archive files are removed."""
import logging
import os
import shutil
import uuid
from datetime import timedelta
from pathlib import Path
from sqlalchemy import select, delete, update, case, or_
from .db import (Document, DocumentVersion, DocumentGrant, Review, Contract, DocumentNote,
    Annotation, ShareLink, CalendarSync, FolderImport, Integration, now)
from .security import audit
from .storage import ROOT


def remove_archive(doc):
    # Recheck storage reachability; a missing NAS must never look like an empty archive.
    root = Path(os.fspath(ROOT))
    if not root.is_dir():
        raise OSError('Archive storage unavailable')
    tenant_id, document_id = str(uuid.UUID(doc.tenant_id)), str(uuid.UUID(doc.id))
    if tenant_id != doc.tenant_id or document_id != doc.id:
        raise ValueError('Invalid archive identifiers')
    tenant = root / tenant_id
    directory = tenant / document_id
    if tenant.is_symlink() or directory.is_symlink():
        raise ValueError('Refusing linked archive directories')
    try:
        # rmtree removes nested symlinks themselves, never their targets.
        shutil.rmtree(directory)
    except FileNotFoundError:
        pass  # A previous attempt removed files but did not finish the database transaction.


def purge_pending(db, limit=5):
    ids = db.scalars(select(Document.id).where(Document.status == 'purging',
        or_(Document.heartbeat_at.is_(None), Document.heartbeat_at < now() - timedelta(seconds=30)))
        .order_by(Document.id).limit(limit)).all()
    for ident in ids:
        try:
            tenant_id = db.scalar(select(Document.tenant_id).where(Document.id == ident, Document.status == 'purging'))
            # Let an in-flight calendar publication commit its receipt before detaching it.
            # Calendar sync locks integrations first; use the same lock order here.
            db.scalars(select(Integration).where(Integration.tenant_id == tenant_id,
                Integration.kind == 'caldav').with_for_update()).all()
            doc = db.scalar(select(Document).where(Document.id == ident, Document.status == 'purging').with_for_update(skip_locked=True))
            if doc is None:
                db.rollback()
                continue
            if doc.deleted_at is None:
                raise ValueError('Deletion requires trash state')
            remove_archive(doc)
            # Calendar deletion can retry even while its provider is offline or disabled.
            db.execute(update(CalendarSync).where(CalendarSync.document_id == doc.id).values(
                event_uid=f'archivraum-{doc.tenant_id}-{doc.id}', document_id=None))
            # Keep scanner receipts to prevent automatic reimport. Unfinished source cleanup
            # is abandoned: removing an archived document does not authorize deleting sources.
            db.execute(update(FolderImport).where(FolderImport.document_id == doc.id).values(document_id=None,
                status=case((FolderImport.status == 'pending', 'done'), else_=FolderImport.status), error=None))
            for model in [ShareLink, Annotation, DocumentNote, Contract, Review, DocumentGrant, DocumentVersion]:
                db.execute(delete(model).where(model.document_id == doc.id))
            audit(db, None, doc.tenant_id, 'document.purged', doc.id)
            db.delete(doc)
            db.commit()
        except Exception as exc:
            db.rollback()
            doc = db.get(Document, ident)
            if doc and doc.status == 'purging':
                doc.heartbeat_at = now()
                doc.error = 'Löschung wartet auf den Speicher. NAS-Verbindung und Schreibrechte prüfen; erneuter Versuch folgt automatisch.'
                db.commit()
            logging.warning('Dokumentlöschung wird wiederholt: %s (%s)', ident, type(exc).__name__)
    return bool(ids)
