"""Tenant roles remain the upper bound; document and folder restrictions intersect."""
from fastapi import HTTPException
from sqlalchemy import select, exists, or_, and_, true, func
from .db import Document, Folder, DocumentGrant, FolderGrant, DocumentVersion
from .security import membership

# All ancestors participate in access checks. Changing a parent's grants takes
# effect immediately for its entire subtree, without copying stale grants.
_folders = Folder.__table__
_parent = _folders.alias('folder_parent')
FOLDER_ANCESTORS = select(_folders.c.id.label('descendant_id'), _folders.c.id.label('ancestor_id'),
    _folders.c.tenant_id, _folders.c.parent_id).cte('folder_ancestors', recursive=True)
FOLDER_ANCESTORS = FOLDER_ANCESTORS.union_all(select(FOLDER_ANCESTORS.c.descendant_id, _parent.c.id,
    _parent.c.tenant_id, _parent.c.parent_id).join(_parent,
        and_(_parent.c.id == FOLDER_ANCESTORS.c.parent_id, _parent.c.tenant_id == FOLDER_ANCESTORS.c.tenant_id)))


def folder_clause(user_id, edit=False):
    ancestor = _folders.alias('access_ancestor')
    granted = exists(select(FolderGrant.id).where(FolderGrant.folder_id == ancestor.c.id, FolderGrant.user_id == user_id,
        *([FolderGrant.can_edit.is_(True)] if edit else [])))
    denied = exists(select(1).select_from(FOLDER_ANCESTORS.join(ancestor, ancestor.c.id == FOLDER_ANCESTORS.c.ancestor_id)).where(
        FOLDER_ANCESTORS.c.descendant_id == Folder.id, ancestor.c.restricted.is_(True), ~granted).correlate(Folder))
    return ~denied


def document_clause(user_id, role, edit=False):
    if role == 'owner':
        return true()
    direct = exists(select(DocumentGrant.id).where(DocumentGrant.document_id == Document.id, DocumentGrant.user_id == user_id,
        *([DocumentGrant.can_edit.is_(True)] if edit else [])))
    folder = exists(select(Folder.id).where(Folder.id == Document.folder_id, Folder.tenant_id == Document.tenant_id, folder_clause(user_id, edit)))
    return and_(or_(Document.restricted.is_(False), direct), or_(Document.folder_id.is_(None), folder))


def document_access(db, user, tenant_id, document_id, edit=False, lock=False, allow_purging=False):
    member = membership(db, user, tenant_id, 'editor' if edit else 'viewer')
    query = select(Document).where(Document.id == document_id, Document.tenant_id == tenant_id, document_clause(user.id, member.role, edit))
    doc = db.scalar(query.with_for_update() if lock else query)
    if not doc:
        raise HTTPException(404, 'Dokument nicht gefunden oder kein Zugriff.')
    if doc.status == 'purging' and not allow_purging:
        raise HTTPException(409, 'Dokument wird endgültig gelöscht und kann nicht mehr geändert oder wiederhergestellt werden.')
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


def rule_permissions(db, user, tenant_id):
    """Authorize a rule's entire action before mutating a visible document."""
    cache = {}
    def permitted(rule, folder_id=None):
        if folder_id:
            try:
                folder_access(db, user, tenant_id, folder_id, edit=True)
                return True
            except HTTPException:
                return False
        if rule.id not in cache:
            try:
                if rule.folder_id:
                    folder_access(db, user, tenant_id, rule.folder_id, edit=True)
                cache[rule.id] = True
            except HTTPException:
                cache[rule.id] = False
        return cache[rule.id]
    return permitted


def used_bytes(db, tenant_id, clause=None):
    filters = [Document.tenant_id == tenant_id]
    if clause is not None:
        filters.append(clause)
    current = db.scalar(select(func.coalesce(func.sum(Document.size), 0)).where(*filters))
    historical = db.scalar(select(func.coalesce(func.sum(DocumentVersion.size), 0)).join(Document, DocumentVersion.document_id == Document.id).where(*filters, DocumentVersion.number != Document.current_version))
    return int(current + historical)
