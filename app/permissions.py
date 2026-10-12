"""Tenant roles remain the upper bound; document and folder restrictions intersect."""
from fastapi import HTTPException
from sqlalchemy import select, exists, or_, and_, true, func
from .db import Document, Folder, DocumentGrant, FolderGrant, DocumentVersion
from .security import membership


def folder_clause(user_id, edit=False):
    granted = exists(select(FolderGrant.id).where(FolderGrant.folder_id == Folder.id, FolderGrant.user_id == user_id,
        *([FolderGrant.can_edit.is_(True)] if edit else [])))
    return or_(Folder.restricted.is_(False), granted)


def document_clause(user_id, role, edit=False):
    if role == 'owner':
        return true()
    direct = exists(select(DocumentGrant.id).where(DocumentGrant.document_id == Document.id, DocumentGrant.user_id == user_id,
        *([DocumentGrant.can_edit.is_(True)] if edit else [])))
    folder = exists(select(Folder.id).where(Folder.id == Document.folder_id, Folder.tenant_id == Document.tenant_id, folder_clause(user_id, edit)))
    return and_(or_(Document.restricted.is_(False), direct), or_(Document.folder_id.is_(None), folder))


def document_access(db, user, tenant_id, document_id, edit=False, lock=False):
    member = membership(db, user, tenant_id, 'editor' if edit else 'viewer')
    query = select(Document).where(Document.id == document_id, Document.tenant_id == tenant_id, document_clause(user.id, member.role, edit))
    doc = db.scalar(query.with_for_update() if lock else query)
    if not doc:
        raise HTTPException(404, 'Dokument nicht gefunden oder kein Zugriff.')
    return doc


def folder_access(db, user, tenant_id, folder_id, edit=False):
    member = membership(db, user, tenant_id, 'editor' if edit else 'viewer')
    query = select(Folder).where(Folder.id == folder_id, Folder.tenant_id == tenant_id)
    if member.role != 'owner':
        query = query.where(folder_clause(user.id, edit))
    folder = db.scalar(query)
    if not folder:
        raise HTTPException(404, 'Ordner nicht gefunden oder kein Zugriff.')
    return folder


def used_bytes(db, tenant_id, clause=None):
    filters = [Document.tenant_id == tenant_id]
    if clause is not None:
        filters.append(clause)
    current = db.scalar(select(func.coalesce(func.sum(Document.size), 0)).where(*filters))
    historical = db.scalar(select(func.coalesce(func.sum(DocumentVersion.size), 0)).join(Document, DocumentVersion.document_id == Document.id).where(*filters, DocumentVersion.number != Document.current_version))
    return int(current + historical)
