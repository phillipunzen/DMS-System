"""Immutable document versions, intersecting access lists, reviews and camera PDFs."""
import hashlib
import io
import os
import shutil
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Literal
from sqlalchemy import select, delete, update
from PIL import Image, ImageOps, UnidentifiedImageError
from .db import *
from .security import current_user, membership, audit
from .permissions import document_access, folder_access, document_clause, used_bytes
from .storage import stage_upload, version_path, save_document, path_for, MAX_UPLOAD

router = APIRouter()


def serialise(doc):
    from .main import doc_data
    return doc_data(doc)


def invalidate_review(db, doc):
    db.execute(update(Review).where(Review.document_id == doc.id, Review.status == 'pending').values(status='superseded', decided_at=now()))
    doc.review_status = 'unassigned' if db.get(Tenant, doc.tenant_id).workflow_enabled else 'none'


def version_data(version):
    return {k: getattr(version, k) for k in ['id', 'number', 'filename', 'mime', 'size', 'sha256', 'note', 'created_at']}


@router.get('/api/tenants/{tenant_id}/documents/{document_id}/versions')
def versions(tenant_id: str, document_id: str, user=Depends(current_user), db=Depends(get_db)):
    doc = document_access(db, user, tenant_id, document_id)
    items = db.scalars(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.number.desc())).all()
    return {'current': doc.current_version, 'items': [version_data(v) for v in items]}


@router.get('/api/tenants/{tenant_id}/documents/{document_id}/versions/{number}/file')
def version_file(tenant_id: str, document_id: str, number: int, user=Depends(current_user), db=Depends(get_db)):
    doc = document_access(db, user, tenant_id, document_id)
    version = db.scalar(select(DocumentVersion).where(DocumentVersion.document_id == doc.id, DocumentVersion.number == number))
    if not version:
        raise HTTPException(404, 'Version nicht gefunden.')
    path = version_path(tenant_id, document_id, number)
    if not path.is_file():
        raise HTTPException(404, 'Versionsdatei fehlt. Speicherverbindung prüfen.')
    audit(db, user, tenant_id, 'version.downloaded', doc.id + ': v' + str(number)); db.commit()
    return FileResponse(path, media_type=version.mime, filename=version.filename, headers={'Cache-Control': 'no-store'})


def create_version(db, user, tenant_id, document_id, stream, filename, note):
    # Serialize quota changes before locking a document to maintain a consistent lock order.
    db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    if doc.status in {'processing', 'queued'} or doc.deleted_at:
        raise HTTPException(409, 'Dokument zunächst fertig verarbeiten oder aus dem Papierkorb wiederherstellen.')
    temp, size, checksum, mime = stage_upload(stream)
    destination = None
    created_directory = False
    try:
        if checksum == doc.sha256:
            raise HTTPException(409, 'Diese Datei entspricht der aktuellen Version.')
        if used_bytes(db, tenant_id) + size > db.get(Tenant, tenant_id).quota_mb * 1024 * 1024:
            raise HTTPException(413, 'Speicherlimit erreicht. Historische Versionen zählen mit.')
        number = doc.current_version + 1
        destination = version_path(tenant_id, doc.id, number)
        try:
            destination.parent.mkdir(parents=True, exist_ok=False, mode=0o700)
        except FileExistsError:
            raise HTTPException(409, 'Versionspfad ist bereits vorhanden. Speicher und Dateikonsistenz prüfen.')
        created_directory = True
        os.replace(temp, destination); destination.chmod(0o600)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
        filename = Path(filename.replace('\\', '/')).name[:255] or 'Dokument'
        db.add(DocumentVersion(tenant_id=tenant_id, document_id=doc.id, number=number, filename=filename, mime=mime, size=size, sha256=checksum, uploader_id=user.id, note=note))
        doc.current_version = number
        doc.filename, doc.mime, doc.size, doc.sha256 = filename, mime, size, checksum
        doc.uploader_id = user.id
        doc.status, doc.error, doc.text = 'queued', None, ''
        doc.processed_at = None
        doc.ai_pending, doc.ai_retry_at, doc.ai_attempts = False, None, 0
        doc.ocr_failed = False
        doc.supplier, doc.doc_type, doc.amount, doc.due_date, doc.paid = '', 'Sonstiges', None, None, False
        invalidate_review(db, doc)
        audit(db, user, tenant_id, 'version.created', doc.id + ': v' + str(number))
        db.commit()
        return serialise(doc)
    except Exception:
        db.rollback()
        if created_directory:
            shutil.rmtree(destination.parent, ignore_errors=True)
        raise
    finally:
        temp.unlink(missing_ok=True)


@router.post('/api/tenants/{tenant_id}/documents/{document_id}/versions')
def upload_version(tenant_id: str, document_id: str, file: UploadFile = File(...), note: str = Form(default='', max_length=255), user=Depends(current_user), db=Depends(get_db)):
    return create_version(db, user, tenant_id, document_id, file.file, file.filename or 'Dokument', note)


@router.post('/api/tenants/{tenant_id}/documents/{document_id}/versions/{number}/restore')
def restore_version(tenant_id: str, document_id: str, number: int, user=Depends(current_user), db=Depends(get_db)):
    doc = document_access(db, user, tenant_id, document_id, edit=True)
    version = db.scalar(select(DocumentVersion).where(DocumentVersion.document_id == doc.id, DocumentVersion.number == number))
    if not version:
        raise HTTPException(404, 'Version nicht gefunden.')
    path = version_path(tenant_id, doc.id, number)
    with path.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != version.sha256:
            raise HTTPException(409, 'Prüfsumme dieser Version stimmt nicht. Wiederherstellung abgebrochen.')
        stream.seek(0)
        return create_version(db, user, tenant_id, document_id, stream, version.filename, 'Wiederhergestellt aus Version ' + str(number))


class GrantInput(BaseModel):
    user_id: str
    can_edit: bool = False


class AccessInput(BaseModel):
    restricted: bool = False
    grants: list[GrantInput] = Field(default_factory=list, max_length=10000)


def resource(db, user, tenant_id, kind, resource_id):
    membership(db, user, tenant_id, 'owner')
    if kind == 'folders':
        return folder_access(db, user, tenant_id, resource_id), FolderGrant, 'folder_id'
    if kind == 'documents':
        return document_access(db, user, tenant_id, resource_id, lock=True), DocumentGrant, 'document_id'
    raise HTTPException(404)


@router.get('/api/tenants/{tenant_id}/{kind}/{resource_id}/access')
def get_access(tenant_id: str, kind: str, resource_id: str, user=Depends(current_user), db=Depends(get_db)):
    item, model, key = resource(db, user, tenant_id, kind, resource_id)
    grants = db.scalars(select(model).where(getattr(model, key) == resource_id)).all()
    return {'restricted': item.restricted, 'grants': [{'user_id': g.user_id, 'can_edit': g.can_edit} for g in grants]}


@router.put('/api/tenants/{tenant_id}/{kind}/{resource_id}/access')
def set_access(tenant_id: str, kind: str, resource_id: str, data: AccessInput, user=Depends(current_user), db=Depends(get_db)):
    db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    item, model, key = resource(db, user, tenant_id, kind, resource_id)
    ids = [g.user_id for g in data.grants]
    member_ids = set(db.scalars(select(Membership.user_id).where(Membership.tenant_id == tenant_id)).all())
    if len(ids) != len(set(ids)) or not set(ids).issubset(member_ids):
        raise HTTPException(422, 'Zugriffslisten dürfen nur eindeutige Mitglieder dieses Dokumentenraums enthalten.')
    item.restricted = data.restricted
    db.execute(delete(model).where(getattr(model, key) == resource_id))
    for grant in data.grants:
        db.add(model(**{key: resource_id, 'user_id': grant.user_id, 'can_edit': grant.can_edit}))
    audit(db, user, tenant_id, kind + '.access_changed', resource_id)
    db.commit()
    return {'ok': True}


class WorkflowInput(BaseModel):
    enabled: bool = False


@router.get('/api/tenants/{tenant_id}/workflow')
def workflow(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id)
    return {'enabled': db.get(Tenant, tenant_id).workflow_enabled}


@router.put('/api/tenants/{tenant_id}/workflow')
def set_workflow(tenant_id: str, data: WorkflowInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    tenant.workflow_enabled = data.enabled
    audit(db, user, tenant_id, 'workflow.configured', 'Aktiviert' if data.enabled else 'Deaktiviert')
    db.commit()
    return {'enabled': data.enabled}


class ReviewInput(BaseModel):
    reviewer_id: str
    note: str = Field(default='', max_length=1000)


class DecisionInput(BaseModel):
    decision: Literal['approved', 'rejected', 'cancelled']
    note: str = Field(default='', max_length=1000)


def review_data(review):
    return {k: getattr(review, k) for k in ['id', 'document_id', 'version', 'requester_id', 'reviewer_id', 'status', 'note', 'created_at', 'decided_at']}


@router.get('/api/tenants/{tenant_id}/reviews')
def review_queue(tenant_id: str, document_id: str = '', user=Depends(current_user), db=Depends(get_db)):
    member = membership(db, user, tenant_id)
    query = select(Review, Document.title).join(Document, Review.document_id == Document.id).where(Review.tenant_id == tenant_id, Document.deleted_at.is_(None), document_clause(user.id, member.role))
    if document_id:
        document_access(db, user, tenant_id, document_id)
        query = query.where(Review.document_id == document_id)
    else:
        query = query.where(Review.status == 'pending')
    return [review_data(r) | {'title': title, 'can_decide': r.reviewer_id == user.id and member.role in {'editor', 'manager', 'owner'}} for r, title in db.execute(query.order_by(Review.created_at.desc()).limit(200))]


@router.get('/api/tenants/{tenant_id}/documents/{document_id}/reviewers')
def reviewers(tenant_id: str, document_id: str, user=Depends(current_user), db=Depends(get_db)):
    doc = document_access(db, user, tenant_id, document_id, edit=True)
    rows = db.execute(select(User, Membership.role).join(Membership, Membership.user_id == User.id).where(Membership.tenant_id == tenant_id, Membership.role.in_(['editor', 'manager', 'owner']), User.active.is_(True)))
    result = []
    for candidate, role in rows:
        if candidate.id in {user.id, doc.uploader_id}:
            continue
        if db.scalar(select(Document.id).where(Document.id == doc.id, document_clause(candidate.id, role))):
            result.append({'id': candidate.id, 'name': candidate.name})
    return result


@router.post('/api/tenants/{tenant_id}/documents/{document_id}/reviews')
def request_review(tenant_id: str, document_id: str, data: ReviewInput, user=Depends(current_user), db=Depends(get_db)):
    db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    if not db.get(Tenant, tenant_id).workflow_enabled:
        raise HTTPException(409, 'Prüfabläufe sind für diesen Dokumentenraum deaktiviert.')
    if doc.status != 'ready' or doc.deleted_at:
        raise HTTPException(409, 'Nur fertig verarbeitete aktive Dokumente können geprüft werden.')
    if db.scalar(select(Review.id).where(Review.document_id == doc.id, Review.status == 'pending')):
        raise HTTPException(409, 'Für dieses Dokument läuft bereits eine Prüfung.')
    reviewer = db.get(User, data.reviewer_id)
    if not reviewer or not reviewer.active or reviewer.id in {user.id, doc.uploader_id}:
        raise HTTPException(422, 'Ein anderes aktives Mitglied muss die Prüfung übernehmen.')
    membership(db, reviewer, tenant_id, 'editor')
    document_access(db, reviewer, tenant_id, doc.id)
    review = Review(tenant_id=tenant_id, document_id=doc.id, version=doc.current_version, requester_id=user.id, reviewer_id=reviewer.id, note=data.note)
    db.add(review); doc.review_status = 'pending'
    audit(db, user, tenant_id, 'review.requested', doc.id); db.commit()
    return review_data(review)


@router.post('/api/tenants/{tenant_id}/reviews/{review_id}/decision')
def decide(tenant_id: str, review_id: str, data: DecisionInput, user=Depends(current_user), db=Depends(get_db)):
    review = db.scalar(select(Review).where(Review.id == review_id, Review.tenant_id == tenant_id))
    if not review:
        membership(db, user, tenant_id)
        raise HTTPException(404, 'Prüfung nicht gefunden.')
    doc = document_access(db, user, tenant_id, review.document_id, lock=True)
    review = db.scalar(select(Review).where(Review.id == review_id).with_for_update().execution_options(populate_existing=True))
    member = membership(db, user, tenant_id, 'editor')
    if not db.get(Tenant, tenant_id).workflow_enabled or review.status != 'pending' or review.version != doc.current_version or doc.status != 'ready' or doc.deleted_at:
        raise HTTPException(409, 'Prüfung ist nicht mehr aktuell oder wurde deaktiviert.')
    if data.decision == 'cancelled':
        if user.id != review.requester_id and member.role != 'owner':
            raise HTTPException(403, 'Nur Antragsteller oder Eigentümer können die Prüfung abbrechen.')
    else:
        membership(db, user, tenant_id, 'editor')
        if user.id != review.reviewer_id or user.id in {review.requester_id, doc.uploader_id}:
            raise HTTPException(403, 'Nur das zugewiesene andere Mitglied kann entscheiden.')
    review.status, review.decided_at = data.decision, now()
    if data.note:
        review.note = data.note
    doc.review_status = 'unassigned' if data.decision == 'cancelled' else data.decision
    audit(db, user, tenant_id, 'review.' + data.decision, doc.id); db.commit()
    return review_data(review)


@router.post('/api/tenants/{tenant_id}/camera-scans')
def camera_scan(tenant_id: str, files: list[UploadFile] = File(...), title: str = Form(default='Kamera-Scan', min_length=1, max_length=200), user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'editor')
    db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    inbox = db.scalar(select(Folder).where(Folder.tenant_id == tenant_id, Folder.name == 'Eingang'))
    if inbox: folder_access(db, user, tenant_id, inbox.id, edit=True)
    if not 1 <= len(files) <= 20:
        raise HTTPException(422, 'Ein Kamera-Scan unterstützt 1 bis 20 Seiten.')
    pages, total_bytes, pixels = [], 0, 0
    try:
        for upload in files:
            raw = upload.file.read(MAX_UPLOAD + 1); total_bytes += len(raw)
            if total_bytes > MAX_UPLOAD:
                raise HTTPException(413, 'Kamera-Scan überschreitet das Upload-Limit.')
            with Image.open(io.BytesIO(raw)) as image:
                if image.format not in {'JPEG', 'PNG', 'WEBP'}:
                    raise HTTPException(415, 'Kamera-Scans benötigen JPEG-, PNG- oder WebP-Bilder.')
                pixels += image.width * image.height
                if pixels > 80000000:
                    raise HTTPException(413, 'Zu viele Bildpunkte für einen Kamera-Scan.')
                page = ImageOps.exif_transpose(image).convert('RGB')
                page.thumbnail((2400, 2400))
                page.info.clear()  # Never carry GPS/EXIF data into the generated PDF.
                pages.append(page)
        output = io.BytesIO()
        pages[0].save(output, format='PDF', save_all=True, append_images=pages[1:], resolution=150, title=title)
        output.seek(0)
        doc = save_document(db, tenant_id, user.id, title + '.pdf', output, source='camera')
        doc.folder_id = inbox.id if inbox else None
        try:
            audit(db, user, tenant_id, 'document.camera_scan', doc.id); db.commit()
        except Exception:
            db.rollback(); shutil.rmtree(path_for(tenant_id, doc.id).parent, ignore_errors=True); raise
        return serialise(doc)
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError):
        raise HTTPException(422, 'Bilddatei ist beschädigt oder zu groß.')
    finally:
        for page in pages: page.close()
