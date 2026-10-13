import json
import os
import secrets
import re
import shutil
from contextlib import asynccontextmanager
from datetime import timedelta, date
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, Depends, Request, Response, HTTPException, UploadFile, File
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import select, func, or_, update, delete, case
from sqlalchemy.exc import IntegrityError
from .db import *
from .security import *
from .schemas import *
from .storage import save_document, path_for, current_path, ROOT, MAX_UPLOAD
from .permissions import document_access, folder_access, document_clause, folder_clause, used_bytes, rule_permissions

STATIC = Path(__file__).parent / 'static'


@asynccontextmanager
async def lifespan(app):
    # Schema migration is performed by the container entrypoint, not each API process.
    # Never touch a remote filesystem on API startup: a persisted NFS mount
    # can still be present while its server/network is down or unresponsive.
    # The NAS helper prepares its directories when activating the share.
    from .storage_control import state as storage_state
    try:
        if storage_state()['mode'] == 'local':
            ROOT.mkdir(parents=True, exist_ok=True)
    except (HTTPException, OSError):
        import logging
        logging.warning('Dokumentenspeicher nicht verfügbar; Administration bleibt erreichbar.')
    with SessionLocal() as db:
        if not db.scalar(select(User.id).where(User.admin.is_(True))):
            email = os.getenv('BOOTSTRAP_ADMIN_EMAIL')
            password = os.getenv('BOOTSTRAP_ADMIN_PASSWORD')
            if email and password:
                user = User(email=email.lower(), name='Serveradministrator', password_hash=strong_password(password), admin=True)
                db.add(user)
                db.commit()
    yield


app = FastAPI(title='Archivraum API', lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=secret, session_cookie='oidc_state', https_only=COOKIE_SECURE, max_age=600)


@app.middleware('http')
async def security_headers(request: Request, call_next):
    host = request.headers.get('host', '').split(':')[0].lower()
    allowed = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
    with SessionLocal() as db:
        internal_health = request.url.path == '/api/health' and request.client and request.client.host == '127.0.0.1'
        if not internal_health and '*' not in allowed and host not in allowed and not db.get(Domain, host):
            return Response('Unbekannte Domain', status_code=400)
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        upload_request = request.method == 'POST' and re.fullmatch(r'/api/tenants/[^/]+/(?:documents(?:/[^/]+/versions)?|camera-scans)', request.url.path)
        restore_request = request.method == 'POST' and request.url.path == '/api/tenants/restore-backup'
        from .tenant_backup import MAX_BACKUP
        body_limit = MAX_BACKUP + 2 * 1024 * 1024 if restore_request else MAX_UPLOAD + 1024 * 1024 if upload_request else 1024 * 1024
        try:
            if int(request.headers.get('content-length', '0')) > body_limit:
                return Response('Anfrage überschreitet das Größenlimit.', status_code=413)
        except ValueError:
            return Response('Ungültige Inhaltslänge.', status_code=400)
        original_receive = request._receive
        received = 0
        async def limited_receive():
            nonlocal received
            message = await original_receive()
            received += len(message.get('body', b''))
            if received > body_limit:
                raise HTTPException(413, 'Anfrage überschreitet das Größenlimit.')
            return message
        request._receive = limited_receive
        origin = request.headers.get('origin')
        if origin and urlparse(origin).netloc.lower() != request.headers.get('host', '').lower():
            return Response('Ungültiger Origin', status_code=403)
        public = request.url.path in {'/api/auth/login', '/api/auth/register', '/api/invitations/accept'} or bool(re.fullmatch(r'/api/shares/[A-Za-z0-9_-]{50,80}/unlock', request.url.path))
        if not public:
            csrf = request.cookies.get('dms_csrf', '')
            if not csrf or not secrets.compare_digest(csrf, request.headers.get('x-csrf-token', '')):
                return Response('CSRF-Prüfung fehlgeschlagen', status_code=403)
    response = await call_next(request)
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'} and received > body_limit:
        response = Response('Anfrage überschreitet das Größenlimit.', status_code=413)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'no-referrer' if request.url.path.startswith(('/share/', '/api/shares/')) else 'same-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
    response.headers['Permissions-Policy'] = 'camera=(self), microphone=(), geolocation=()'
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    return response


def user_data(user):
    return {'id': user.id, 'email': user.email, 'name': user.name, 'admin': user.admin}


def doc_data(doc, full=False):
    keys = ['id', 'title', 'filename', 'mime', 'size', 'folder_id', 'status', 'error', 'supplier', 'doc_type', 'tags', 'amount', 'due_date', 'paid', 'source', 'created_at', 'deleted_at', 'processed_at', 'sha256', 'current_version', 'restricted', 'review_status', 'ai_pending', 'ocr_failed']
    result = {key: getattr(doc, key) for key in keys}
    if full:
        result['text'] = doc.text
    return result


def tenant_doc(db, tenant_id, document_id, lock=False):
    query = select(Document).where(Document.id == document_id, Document.tenant_id == tenant_id)
    doc = db.scalar(query.with_for_update() if lock else query)
    if not doc:
        raise HTTPException(404, 'Dokument nicht gefunden.')
    return doc


def tenant_folder(db, tenant_id, folder_id):
    folder = db.scalar(select(Folder).where(Folder.id == folder_id, Folder.tenant_id == tenant_id))
    if not folder:
        raise HTTPException(404, 'Ordner nicht gefunden.')
    return folder


def api_error():
    raise HTTPException(400, 'Verbindung fehlgeschlagen. Konfiguration und Erreichbarkeit prüfen.')


@app.get('/api/health')
def health(db=Depends(get_db)):
    db.execute(select(1))
    return {'status': 'ok'}


@app.get('/api/public')
def public(request: Request, db=Depends(get_db)):
    domain = db.get(Domain, request.headers.get('host', '').split(':')[0].lower())
    return {'app_name': setting(db, 'app_name', 'Archivraum'), 'registration_enabled': False, 'oidc_enabled': bool(setting(db, 'oidc')), 'ldap_enabled': bool(setting(db, 'ldap')), 'domain_tenant': domain.tenant_id if domain else None, 'max_upload_mb': MAX_UPLOAD // 1024 // 1024}


@app.post('/api/auth/register')
def register(data: RegisterInput, response: Response, db=Depends(get_db)):
    raise HTTPException(403, 'Lokale Konten benötigen eine Einladung. Alternativ über einen eingerichteten LDAP- oder OIDC-Anbieter anmelden.')


@app.post('/api/auth/login')
def authenticate(data: LoginInput, request: Request, response: Response, db=Depends(get_db)):
    from .auth import rate_limit, ldap_authenticate
    email = str(data.email).lower()
    rate_limit(db, email, request.client.host if request.client else 'unknown')
    user = db.scalar(select(User).where(User.email == email))
    if data.method == 'ldap':
        user = ldap_authenticate(db, email, data.password)
    elif not user or not user.password_hash or not passwords.verify(data.password, user.password_hash):
        # Equalize nonexistent-account hash cost.
        if not user or not user.password_hash:
            passwords.hash(data.password)
        raise HTTPException(401, 'Anmeldung fehlgeschlagen.')
    if not user or not user.active:
        raise HTTPException(401, 'Anmeldung fehlgeschlagen.')
    challenge = login(db, user, response)
    audit(db, user, None, 'auth.login', data.method)
    db.commit()
    return challenge or user_data(user)


@app.post('/api/auth/logout')
def logout(request: Request, response: Response, user=Depends(current_user), db=Depends(get_db)):
    db.execute(delete(LoginSession).where(LoginSession.token_hash == digest(request.cookies.get('dms_session', ''))))
    db.commit()
    response.delete_cookie('dms_session')
    response.delete_cookie('dms_csrf')
    return {'ok': True}


@app.get('/api/me')
def me(user=Depends(current_user), db=Depends(get_db)):
    tenants = db.execute(select(Tenant, Membership.role).join(Membership, Tenant.id == Membership.tenant_id).where(Membership.user_id == user.id)).all()
    return {**user_data(user), 'tenants': [{'id': t.id, 'name': t.name, 'role': role, 'quota_mb': t.quota_mb, 'workflow_enabled': t.workflow_enabled} for t, role in tenants], 'tenant_creation_enabled': setting(db, 'tenant_creation_enabled', 'true') == 'true'}


@app.put('/api/me/password')
def change_password(data: PasswordInput, response: Response, user=Depends(current_user), db=Depends(get_db)):
    if not user.password_hash or not passwords.verify(data.current_password, user.password_hash):
        raise HTTPException(400, 'Aktuelles Passwort stimmt nicht.')
    user.password_hash = strong_password(data.password)
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    audit(db, user, None, 'auth.password_changed')
    db.commit()
    db.execute(delete(MFAChallenge).where(MFAChallenge.user_id == user.id))
    db.commit()
    login(db, user, response, mfa_verified=True)
    return {'ok': True}


@app.post('/api/tenants')
def create_tenant(data: TenantInput, user=Depends(current_user), db=Depends(get_db)):
    if not user.admin and setting(db, 'tenant_creation_enabled', 'true') != 'true':
        raise HTTPException(403, 'Mandantenerstellung ist deaktiviert.')
    tenant = Tenant(name=data.name)
    db.add(tenant)
    db.flush()
    db.add(Membership(tenant_id=tenant.id, user_id=user.id, role='owner'))
    for name, color in [('Eingang', 'green'), ('Rechnungen', 'blue'), ('Verträge', 'purple'), ('Korrespondenz', 'orange')]:
        db.add(Folder(tenant_id=tenant.id, name=name, color=color))
    audit(db, user, tenant.id, 'tenant.created', tenant.name)
    db.commit()
    return {'id': tenant.id, 'name': tenant.name, 'role': 'owner'}


@app.put('/api/tenants/{tenant_id}')
def rename_tenant(tenant_id: str, data: TenantInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    db.get(Tenant, tenant_id).name = data.name
    audit(db, user, tenant_id, 'tenant.renamed', data.name)
    db.commit()
    return {'ok': True}


@app.get('/api/tenants/{tenant_id}/folders')
def folders(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id)
    member = membership(db, user, tenant_id)
    visible = select(Folder).where(Folder.tenant_id == tenant_id)
    if member.role != 'owner':
        visible = visible.where(folder_clause(user.id))
    result = []
    for folder in db.scalars(visible.order_by(Folder.name)):
        count = db.scalar(select(func.count()).select_from(Document).where(Document.tenant_id == tenant_id, Document.folder_id == folder.id, Document.deleted_at.is_(None), document_clause(user.id, member.role)))
        result.append({'id': folder.id, 'name': folder.name, 'color': folder.color, 'count': count, 'restricted': folder.restricted})
    return result


@app.post('/api/tenants/{tenant_id}/folders')
def add_folder(tenant_id: str, data: FolderInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'manager')
    folder = Folder(tenant_id=tenant_id, **data.model_dump())
    db.add(folder)
    audit(db, user, tenant_id, 'folder.created', data.name)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Der Ordnername ist bereits vergeben.')
    return {'id': folder.id}


@app.delete('/api/tenants/{tenant_id}/folders/{folder_id}')
def remove_folder(tenant_id: str, folder_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'manager')
    folder = folder_access(db, user, tenant_id, folder_id, edit=True)
    if folder.restricted and db.scalar(select(Document.id).where(Document.folder_id == folder_id)):
        raise HTTPException(409, 'Geschützten Ordner vor dem Löschen leeren.')
    if db.scalar(select(Rule.id).where(Rule.tenant_id == tenant_id, Rule.folder_id == folder_id)):
        raise HTTPException(409, 'Der Ordner wird in einer Regel verwendet.')
    db.execute(update(Document).where(Document.tenant_id == tenant_id, Document.folder_id == folder_id).values(folder_id=None))
    db.execute(delete(FolderGrant).where(FolderGrant.folder_id == folder.id))
    db.delete(folder)
    audit(db, user, tenant_id, 'folder.deleted', folder.name)
    db.commit()
    return {'ok': True}


@app.get('/api/tenants/{tenant_id}/documents')
def documents(tenant_id: str, q: str = '', folder: str = '', doc_type: str = '', status: str = '', review_status: str = '', due: bool = False, trash: bool = False, offset: int = 0, limit: int = 50, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id)
    member = membership(db, user, tenant_id)
    query = select(Document).where(Document.tenant_id == tenant_id, document_clause(user.id, member.role))
    query = query.where(Document.deleted_at.is_not(None) if trash else Document.deleted_at.is_(None))
    if q:
        term = '%' + q[:200].replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        query = query.where(or_(*[getattr(Document, key).ilike(term, escape='\\') for key in ['title', 'filename', 'text', 'supplier', 'doc_type']]))
    if folder:
        query = query.where(Document.folder_id == folder)
    if doc_type:
        query = query.where(Document.doc_type == doc_type)
    if status:
        query = query.where(Document.status == status)
    if review_status:
        query = query.where(Document.review_status == review_status)
    if due:
        query = query.where(Document.due_date.is_not(None), Document.paid.is_(False))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    result = db.scalars(query.order_by(Document.created_at.desc()).offset(max(0, offset)).limit(min(max(1, limit), 100))).all()
    editable = set(db.scalars(select(Document.id).where(Document.id.in_([doc.id for doc in result]),
        Document.tenant_id == tenant_id, document_clause(user.id, member.role, True))).all()) if member.role in {'editor', 'manager', 'owner'} else set()
    return {'total': total, 'items': [doc_data(doc) | {'can_edit': doc.id in editable and doc.status != 'purging'} for doc in result]}


@app.post('/api/tenants/{tenant_id}/documents')
def upload(tenant_id: str, file: UploadFile = File(...), user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'editor')
    # Serialize quota and duplicate checks for this tenant.
    db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    inbox = db.scalar(select(Folder).where(Folder.tenant_id == tenant_id, Folder.name == 'Eingang'))
    if inbox:
        folder_access(db, user, tenant_id, inbox.id, edit=True)
    doc = save_document(db, tenant_id, user.id, file.filename or 'Dokument', file.file)
    doc.folder_id = inbox.id if inbox else None
    audit(db, user, tenant_id, 'document.uploaded', doc.id)
    try:
        db.commit()
    except Exception:
        db.rollback()
        shutil.rmtree(path_for(tenant_id, doc.id).parent, ignore_errors=True)
        raise
    return doc_data(doc)


@app.get('/api/tenants/{tenant_id}/documents/{document_id}')
def document(tenant_id: str, document_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id)
    doc = document_access(db, user, tenant_id, document_id)
    member = membership(db, user, tenant_id)
    editable = member.role in {'editor', 'manager', 'owner'} and db.scalar(select(Document.id).where(Document.id == doc.id, document_clause(user.id, member.role, True))) is not None
    return doc_data(doc, True) | {'can_edit': editable, 'workflow_enabled': db.get(Tenant, tenant_id).workflow_enabled}


@app.get('/api/tenants/{tenant_id}/documents/{document_id}/file')
def document_file(tenant_id: str, document_id: str, download: bool = False, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id)
    doc = document_access(db, user, tenant_id, document_id)
    path = current_path(doc)
    if not path.is_file():
        raise HTTPException(404, 'Datei fehlt im Speicher. NAS-Verbindung prüfen.')
    if download:
        audit(db, user, tenant_id, 'document.downloaded', doc.id)
        db.commit()
    return FileResponse(path, media_type=doc.mime, filename=doc.filename, content_disposition_type='attachment' if download else 'inline', headers={'Cache-Control': 'no-store'})


@app.put('/api/tenants/{tenant_id}/documents/{document_id}')
def edit_document(tenant_id: str, document_id: str, data: DocInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'editor')
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    if doc.status == 'processing':
        raise HTTPException(409, 'Dokument wird gerade verarbeitet. Bitte kurz warten.')
    if data.folder_id:
        folder_access(db, user, tenant_id, data.folder_id, edit=True)
    if any(len(tag) > 80 for tag in data.tags):
        raise HTTPException(422, 'Tags dürfen höchstens 80 Zeichen enthalten.')
    for key, value in data.model_dump().items():
        setattr(doc, key, value)
    from .processing import classify
    classify(db, doc, permitted=rule_permissions(db, user, tenant_id), actor_id=user.id, rename_only=True)
    from .features import invalidate_review
    invalidate_review(db, doc)
    audit(db, user, tenant_id, 'document.updated', doc.id)
    db.commit()
    return doc_data(doc)


@app.delete('/api/tenants/{tenant_id}/documents/{document_id}')
def trash_document(tenant_id: str, document_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'editor')
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    if doc.status == 'processing':
        raise HTTPException(409, 'Dokument wird gerade verarbeitet. Bitte kurz warten.')
    doc.deleted_at = now()
    audit(db, user, tenant_id, 'document.trashed', doc.id)
    db.commit()
    return {'ok': True}


@app.post('/api/tenants/{tenant_id}/documents/{document_id}/restore')
def restore_document(tenant_id: str, document_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'editor')
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    if doc.status == 'processing':
        raise HTTPException(409, 'Dokument wird gerade verarbeitet. Bitte kurz warten.')
    doc.deleted_at = None
    audit(db, user, tenant_id, 'document.restored', doc.id)
    db.commit()
    return {'ok': True}


@app.post('/api/tenants/{tenant_id}/documents/{document_id}/purge', status_code=202)
def purge_document(tenant_id: str, document_id: str, data: PurgeInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'manager')
    # Coordinate with tenant backup snapshots and quota updates.
    db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True, allow_purging=True)
    if not doc.deleted_at:
        raise HTTPException(409, 'Dokument zuerst in den Papierkorb verschieben.')
    if doc.status == 'processing':
        raise HTTPException(409, 'Dokument wird gerade verarbeitet. Bitte kurz warten.')
    if doc.status != 'purging':
        # Persist intent before touching files. A restart or NAS failure resumes the same job.
        doc.status, doc.error, doc.heartbeat_at = 'purging', None, None
        doc.ai_pending, doc.ai_retry_at = False, None
        audit(db, user, tenant_id, 'document.purge_requested', doc.id)
        db.commit()
    return {'status': 'purging'}


@app.post('/api/tenants/{tenant_id}/documents/{document_id}/reprocess')
def reprocess(tenant_id: str, document_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'editor')
    doc = document_access(db, user, tenant_id, document_id, edit=True, lock=True)
    if doc.status == 'processing':
        raise HTTPException(409, 'Verarbeitung läuft bereits.')
    from .features import invalidate_review
    invalidate_review(db, doc)
    doc.ai_pending, doc.ai_retry_at, doc.ai_attempts = False, None, 0
    doc.status, doc.error = 'queued', None
    audit(db, user, tenant_id, 'document.reprocess', doc.id)
    db.commit()
    return {'ok': True}


def reviewed_ai_document(db, user, tenant_id, document_id):
    membership(db, user, tenant_id, 'owner')
    if setting(db, 'ai_external_blocked', 'false') == 'true':
        raise HTTPException(403, 'Der Serveradmin hat externe KI-Übertragungen gesperrt.')
    doc = document_access(db, user, tenant_id, document_id, edit=False, lock=True)
    if doc.deleted_at or doc.status not in {'ready', 'error'} or not (doc.text or '').strip():
        raise HTTPException(409, 'Für die KI-Freigabe wird ein aktives Dokument mit abgeschlossenem OCR-Text benötigt.')
    integration = db.scalar(select(Integration).where(Integration.tenant_id == tenant_id, Integration.kind == 'ai'))
    if not integration or not integration.enabled or decrypt(integration.config_encrypted).get('consent') is not True:
        raise HTTPException(409, 'Aktivieren Sie zuerst die KI-Integration mit Zustimmung zur Textübertragung.')
    if decrypt(integration.config_encrypted).get('provider') == 'codex':
        from . import codex_client
        if not codex_client.enabled_for(db, tenant_id):
            raise HTTPException(403, 'Codex ist für diesen Dokumentenraum nicht freigegeben.')
    return doc, integration


@app.post('/api/tenants/{tenant_id}/documents/{document_id}/ai-preview')
def ai_preview(tenant_id: str, document_id: str, data: AIPreviewInput, user=Depends(current_user), db=Depends(get_db)):
    from .privacy import minimise_text, preview_token
    doc, integration = reviewed_ai_document(db, user, tenant_id, document_id)
    config = decrypt(integration.config_encrypted)
    preview = minimise_text(doc.text if data.text is None else data.text, config.get('text_limit', 10000))
    provider = config.get('provider', 'openai')
    target = 'OpenAI / Codex' if provider == 'codex' else config.get('base_url', 'https://api.openai.com/v1')
    return preview | {'token': preview_token(doc, integration, preview['text']), 'provider': provider, 'target': target}


@app.post('/api/tenants/{tenant_id}/documents/{document_id}/ai')
def reviewed_ai(tenant_id: str, document_id: str, data: AIReviewInput, user=Depends(current_user), db=Depends(get_db)):
    from .privacy import minimise_text, verify_preview
    from .processing import ai_metadata, classify
    doc, integration = reviewed_ai_document(db, user, tenant_id, document_id)
    limit = decrypt(integration.config_encrypted).get('text_limit', 10000)
    if not data.text.strip() or minimise_text(data.text, limit)['text'] != data.text or not verify_preview(doc, integration, data.text, data.token):
        raise HTTPException(409, 'Die Vorschau wurde geändert oder ist abgelaufen. Bitte erneut prüfen.')
    previous = doc.status
    doc.status, doc.heartbeat_at = 'processing', now()
    audit(db, user, tenant_id, 'document.ai_approved', doc.id)
    db.commit()
    try:
        if not ai_metadata(db, doc, reviewed_text=data.text):
            raise ValueError('Freigabe widerrufen')
        from .features import invalidate_review
        invalidate_review(db, doc)
        classify(db, doc)
        doc.ai_pending, doc.ai_retry_at, doc.ai_attempts = False, None, 0
        doc.status, doc.error, doc.processed_at = 'ready', None, now()
        db.commit()
    except Exception:
        db.rollback()
        doc = db.get(Document, document_id)
        doc.status = previous
        audit(db, user, tenant_id, 'document.ai_failed', doc.id)
        db.commit()
        raise HTTPException(503, 'KI-Auswertung fehlgeschlagen. Das Original und der lokale OCR-Text bleiben erhalten.')
    return doc_data(doc)


@app.get('/api/tenants/{tenant_id}/stats')
def stats(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id)
    member = membership(db, user, tenant_id)
    visibility = document_clause(user.id, member.role)
    active = [Document.tenant_id == tenant_id, Document.deleted_at.is_(None), visibility]
    rows = db.execute(select(func.count(),
        func.coalesce(func.sum(case((Document.status.in_(['queued', 'processing']), 1), else_=0)), 0),
        func.coalesce(func.sum(case((Document.status == 'error', 1), else_=0)), 0),
        func.coalesce(func.sum(case(((Document.due_date < date.today()) & (Document.paid.is_(False)), 1), else_=0)), 0),
        func.coalesce(func.sum(case(((Document.due_date.is_not(None)) & (Document.paid.is_(False)), 1), else_=0)), 0)).where(*active)).one()
    types = dict(db.execute(select(Document.doc_type, func.count()).where(*active).group_by(Document.doc_type)).all())
    month = func.date_format(Document.created_at, '%Y-%m') if engine.dialect.name == 'mysql' else func.strftime('%Y-%m', Document.created_at)
    months = dict(db.execute(select(month, func.count()).where(*active).group_by(month)).all())
    used = used_bytes(db, tenant_id, visibility)
    return {'documents': rows[0], 'bytes': used, 'queued': int(rows[1]), 'errors': int(rows[2]), 'overdue': int(rows[3]), 'due': int(rows[4]), 'types': types, 'months': months, 'quota_mb': db.get(Tenant, tenant_id).quota_mb, 'members': db.scalar(select(func.count()).select_from(Membership).where(Membership.tenant_id == tenant_id))}


@app.get('/api/tenants/{tenant_id}/rules')
def rules(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    member = membership(db, user, tenant_id)
    query = select(Rule).outerjoin(Folder, Rule.folder_id == Folder.id).where(Rule.tenant_id == tenant_id)
    if member.role != 'owner':
        query = query.where(or_(Rule.folder_id.is_(None), folder_clause(user.id)))
    return [{key: getattr(r, key) for key in ['id', 'name', 'field', 'contains', 'folder_id', 'filename_template', 'priority', 'enabled']} for r in db.scalars(query.order_by(Rule.priority, Rule.id))]


@app.post('/api/tenants/{tenant_id}/rules')
def add_rule(tenant_id: str, data: RuleInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'manager')
    if data.folder_id:
        folder_access(db, user, tenant_id, data.folder_id, edit=True)
    rule = Rule(tenant_id=tenant_id, **data.model_dump())
    db.add(rule)
    audit(db, user, tenant_id, 'rule.created', data.name)
    db.commit()
    return {'id': rule.id}


@app.put('/api/tenants/{tenant_id}/rules/{rule_id}')
def update_rule(tenant_id: str, rule_id: str, data: RuleInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'manager')
    if data.folder_id:
        folder_access(db, user, tenant_id, data.folder_id, edit=True)
    rule = db.scalar(select(Rule).where(Rule.id == rule_id, Rule.tenant_id == tenant_id))
    if not rule:
        raise HTTPException(404, 'Regel nicht gefunden.')
    if rule.folder_id:
        folder_access(db, user, tenant_id, rule.folder_id, edit=True)
    for key, value in data.model_dump().items():
        setattr(rule, key, value)
    audit(db, user, tenant_id, 'rule.updated', rule.name)
    db.commit()
    return {'ok': True}


@app.delete('/api/tenants/{tenant_id}/rules/{rule_id}')
def remove_rule(tenant_id: str, rule_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'manager')
    rule = db.scalar(select(Rule).where(Rule.id == rule_id, Rule.tenant_id == tenant_id))
    if not rule:
        raise HTTPException(404, 'Regel nicht gefunden.')
    if rule.folder_id:
        folder_access(db, user, tenant_id, rule.folder_id, edit=True)
    db.delete(rule)
    audit(db, user, tenant_id, 'rule.deleted', rule.name)
    db.commit()
    return {'ok': True}


@app.post('/api/tenants/{tenant_id}/rules/apply')
def apply_rules(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    from .processing import classify
    membership(db, user, tenant_id, 'manager')
    member = membership(db, user, tenant_id)
    docs = db.scalars(select(Document).where(Document.tenant_id == tenant_id, Document.deleted_at.is_(None), Document.status.notin_(['processing', 'queued']), document_clause(user.id, member.role, True)).order_by(Document.id).with_for_update()).all()
    changed = 0
    permitted = rule_permissions(db, user, tenant_id)
    for doc in docs:
        changed += int(classify(db, doc, permitted=permitted, actor_id=user.id))
    audit(db, user, tenant_id, 'rules.applied', str(changed))
    db.commit()
    return {'changed': changed}


@app.get('/api/tenants/{tenant_id}/members')
def members(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'manager')
    rows = db.execute(select(User, Membership).join(Membership, Membership.user_id == User.id).where(Membership.tenant_id == tenant_id)).all()
    return [{**user_data(u), 'role': m.role} for u, m in rows]


@app.put('/api/tenants/{tenant_id}/members/{user_id}')
def set_role(tenant_id: str, user_id: str, data: RoleInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    target = db.scalar(select(Membership).where(Membership.tenant_id == tenant_id, Membership.user_id == user_id))
    if not target:
        raise HTTPException(404, 'Mitglied nicht gefunden.')
    if target.role == 'owner' and data.role != 'owner' and db.scalar(select(func.count()).select_from(Membership).where(Membership.tenant_id == tenant_id, Membership.role == 'owner')) <= 1:
        raise HTTPException(409, 'Mindestens ein Eigentümer muss erhalten bleiben.')
    target.role = data.role
    audit(db, user, tenant_id, 'member.role_changed', f'{user_id}: {data.role}')
    db.commit()
    return {'ok': True}


@app.delete('/api/tenants/{tenant_id}/members/{user_id}')
def remove_member(tenant_id: str, user_id: str, user=Depends(current_user), db=Depends(get_db)):
    actor = membership(db, user, tenant_id, 'manager')
    db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    target = db.scalar(select(Membership).where(Membership.tenant_id == tenant_id, Membership.user_id == user_id))
    if not target:
        raise HTTPException(404, 'Mitglied nicht gefunden.')
    if ROLES[actor.role] <= ROLES[target.role]:
        raise HTTPException(403, 'Nur Mitglieder mit niedrigerer Rolle können entfernt werden.')
    db.execute(delete(FolderGrant).where(FolderGrant.user_id == user_id, FolderGrant.folder_id.in_(select(Folder.id).where(Folder.tenant_id == tenant_id))))
    db.execute(delete(DocumentGrant).where(DocumentGrant.user_id == user_id, DocumentGrant.document_id.in_(select(Document.id).where(Document.tenant_id == tenant_id))))
    for pending in db.scalars(select(Review).where(Review.tenant_id == tenant_id, Review.reviewer_id == user_id, Review.status == 'pending')):
        pending.status, pending.decided_at = 'cancelled', now()
        db.get(Document, pending.document_id).review_status = 'unassigned'
    db.delete(target)
    audit(db, user, tenant_id, 'member.removed', user_id)
    db.commit()
    return {'ok': True}


@app.post('/api/tenants/{tenant_id}/invitations')
def invite(tenant_id: str, data: InviteInput, user=Depends(current_user), db=Depends(get_db)):
    actor = membership(db, user, tenant_id, 'manager')
    if ROLES[actor.role] <= ROLES[data.role]:
        raise HTTPException(403, 'Diese Rolle kann nur ein Eigentümer einladen.')
    token = secrets.token_urlsafe(40)
    invitation = Invitation(tenant_id=tenant_id, email=str(data.email).lower(), role=data.role, token_hash=digest(token), expires_at=now() + timedelta(days=7))
    db.add(invitation)
    audit(db, user, tenant_id, 'invitation.created', invitation.email)
    db.commit()
    return {'token': token, 'expires_at': invitation.expires_at, 'path': '/?invite=' + token}


@app.get('/api/invitations/{token}')
def invitation_info(token: str, db=Depends(get_db)):
    inv = db.scalar(select(Invitation).where(Invitation.token_hash == digest(token), Invitation.used_at.is_(None), Invitation.expires_at > now()))
    if not inv:
        raise HTTPException(404, 'Einladung ist ungültig oder abgelaufen.')
    return {'tenant': db.get(Tenant, inv.tenant_id).name, 'email': inv.email, 'role': inv.role, 'existing_user': bool(db.scalar(select(User.id).where(User.email == inv.email)))}


@app.post('/api/invitations/accept')
def accept(data: AcceptInput, request: Request, response: Response, db=Depends(get_db)):
    inv = db.scalar(select(Invitation).where(Invitation.token_hash == digest(data.token)).with_for_update())
    if not inv or inv.used_at or inv.expires_at < now():
        raise HTTPException(404, 'Einladung ist ungültig oder abgelaufen.')
    user = db.scalar(select(User).where(User.email == inv.email))
    if user:
        signed_in = current_user(request, db)
        if signed_in.id != user.id:
            raise HTTPException(403, 'Bitte mit dem eingeladenen Konto anmelden.')
    else:
        if not data.name.strip():
            raise HTTPException(422, 'Bitte Namen angeben.')
        user = User(email=inv.email, name=data.name, password_hash=strong_password(data.password))
        db.add(user)
        db.flush()
    if not db.scalar(select(Membership.id).where(Membership.user_id == user.id, Membership.tenant_id == inv.tenant_id)):
        db.add(Membership(user_id=user.id, tenant_id=inv.tenant_id, role=inv.role))
    inv.used_at = now()
    audit(db, user, inv.tenant_id, 'invitation.accepted')
    db.commit()
    login(db, user, response, mfa_verified=True)
    return {'ok': True}


@app.get('/api/tenants/{tenant_id}/audit')
def tenant_audit(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    rows = db.execute(select(Audit, User.name).outerjoin(User, User.id == Audit.actor_id).where(Audit.tenant_id == tenant_id).order_by(Audit.created_at.desc()).limit(100)).all()
    return [{'id': a.id, 'action': a.action, 'detail': a.detail, 'at': a.created_at, 'actor': name or 'System'} for a, name in rows]


@app.get('/api/tenants/{tenant_id}/integrations')
def integrations(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    from .folder_import import public_paths, current_errors
    result = []
    for i in db.scalars(select(Integration).where(Integration.tenant_id == tenant_id, Integration.kind != 'scanner')):
        result.append(integration_data(i))
        if i.kind == 'folder':
            result[-1]['paths'] = public_paths(tenant_id)
            result[-1]['errors'] = current_errors(db, i)
    if not any(i['kind'] == 'folder' for i in result):
        result.append({'kind': 'folder', 'enabled': False, 'config': {'after_import': 'delete', 'settle_seconds': 30}, 'paths': public_paths(tenant_id), 'errors': []})
    return result


def integration_data(integration):
    config = decrypt(integration.config_encrypted)
    return {'id': integration.id, 'kind': integration.kind, 'enabled': integration.enabled,
            'name': config.get('name') or config.get('username') or 'E-Mail-Postfach',
            'config': {k: ('••••••••' if k in {'password', 'api_key'} and v else v) for k, v in config.items()},
            'last_run': integration.last_run, 'last_status': integration.last_status}


def mailbox_for(db, tenant_id, mailbox_id):
    row = db.scalar(select(Integration).where(Integration.id == mailbox_id,
        Integration.tenant_id == tenant_id, Integration.kind == 'imap').with_for_update())
    if not row:
        raise HTTPException(404, 'Postfach nicht gefunden.')
    return row


def configure_mailbox(db, tenant_id, row, data):
    from .integrations import validate_config
    name = data.name.strip()
    if not name:
        raise HTTPException(422, 'Geben Sie einen Namen für das Postfach an.')
    config = data.config.copy()
    old = decrypt(row.config_encrypted) if row else {}
    if config.get('password') == '••••••••':
        config['password'] = old.get('password', '')
    config['name'] = name
    validate_config('imap', config, data.enabled)
    if row is None:
        ident = uid()
        row = Integration(id=ident, tenant_id=tenant_id, kind='imap', account_key=ident)
        db.add(row)
    row.enabled = data.enabled
    row.config_encrypted = encrypt(config)
    return row


@app.get('/api/tenants/{tenant_id}/mailboxes')
def mailboxes(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    return [integration_data(row) for row in db.scalars(select(Integration).where(
        Integration.tenant_id == tenant_id, Integration.kind == 'imap').order_by(Integration.id))]


@app.post('/api/tenants/{tenant_id}/mailboxes', status_code=201)
def add_mailbox(tenant_id: str, data: MailboxInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    row = configure_mailbox(db, tenant_id, None, data)
    audit(db, user, tenant_id, 'mailbox.created', row.id)
    db.commit()
    return integration_data(row)


@app.put('/api/tenants/{tenant_id}/mailboxes/{mailbox_id}')
def update_mailbox(tenant_id: str, mailbox_id: str, data: MailboxInput, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    row = configure_mailbox(db, tenant_id, mailbox_for(db, tenant_id, mailbox_id), data)
    audit(db, user, tenant_id, 'mailbox.configured', row.id)
    db.commit()
    return integration_data(row)


@app.post('/api/tenants/{tenant_id}/mailboxes/{mailbox_id}/run')
def run_mailbox(tenant_id: str, mailbox_id: str, user=Depends(current_user), db=Depends(get_db)):
    from .integrations import run_integration_once
    membership(db, user, tenant_id, 'owner')
    row = mailbox_for(db, tenant_id, mailbox_id)
    if not row.enabled:
        raise HTTPException(400, 'Postfach ist pausiert.')
    status = run_integration_once(db, row)
    audit(db, user, tenant_id, 'mailbox.run', mailbox_id)
    db.commit()
    return {'status': status}


@app.delete('/api/tenants/{tenant_id}/mailboxes/{mailbox_id}')
def remove_mailbox(tenant_id: str, mailbox_id: str, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    row = mailbox_for(db, tenant_id, mailbox_id)
    db.execute(delete(MailImport).where(MailImport.integration_id == row.id))
    db.delete(row)
    audit(db, user, tenant_id, 'mailbox.deleted', mailbox_id)
    db.commit()
    return {'ok': True}


@app.put('/api/tenants/{tenant_id}/integrations/{kind}')
def save_integration(tenant_id: str, kind: str, data: IntegrationInput, user=Depends(current_user), db=Depends(get_db)):
    from .integrations import validate_config
    membership(db, user, tenant_id, 'owner')
    if kind not in {'ai', 'imap', 'caldav', 'folder'}:
        raise HTTPException(404, 'Unbekannte Integration.')
    integration = db.scalar(select(Integration).where(Integration.tenant_id == tenant_id, Integration.kind == kind, Integration.account_key == '').with_for_update())
    old = decrypt(integration.config_encrypted) if integration else {}
    config = data.config.copy()
    for key in {'password', 'api_key'}:
        if config.get(key) == '••••••••':
            config[key] = old.get(key, '')
    validate_config(kind, config, data.enabled)
    if kind == 'ai' and config.get('provider') == 'codex' and data.enabled:
        from . import codex_client
        if not codex_client.enabled_for(db, tenant_id):
            raise HTTPException(403, 'Der Serveradmin muss Codex zuerst für diesen Dokumentenraum freigeben.')
        # Configuration may be activated before login; failed jobs are retried automatically.
    if kind == 'folder':
        if config.get('folder_id'):
            tenant_folder(db, tenant_id, config['folder_id'])
        if data.enabled:
            from .folder_import import directories
            directories(tenant_id)
    if not integration:
        integration = Integration(tenant_id=tenant_id, kind=kind)
        db.add(integration)
    integration.enabled = data.enabled
    integration.config_encrypted = encrypt(config)
    audit(db, user, tenant_id, 'integration.configured', kind)
    db.commit()
    return {'ok': True}


@app.post('/api/tenants/{tenant_id}/integrations/{kind}/run')
def run_integration(tenant_id: str, kind: str, user=Depends(current_user), db=Depends(get_db)):
    from .integrations import run_integration_once
    membership(db, user, tenant_id, 'owner')
    integration = db.scalar(select(Integration).where(Integration.tenant_id == tenant_id, Integration.kind == kind, Integration.account_key == ''))
    if not integration or not integration.enabled or kind not in {'imap', 'caldav', 'folder'}:
        raise HTTPException(400, 'Integration ist nicht aktiv.')
    result = run_integration_once(db, integration, retry_errors=True)
    audit(db, user, tenant_id, 'integration.run', kind)
    db.commit()
    return {'status': result}


@app.get('/api/admin')
def admin_dashboard(user=Depends(admin_user), db=Depends(get_db)):
    tenants = db.scalars(select(Tenant).order_by(Tenant.created_at.desc())).all()
    from .storage_control import storage_summary
    return {'settings': {'app_name': setting(db, 'app_name', 'Archivraum'), 'registration_enabled': False, 'tenant_creation_enabled': setting(db, 'tenant_creation_enabled', 'true') == 'true', 'ai_external_blocked': setting(db, 'ai_external_blocked', 'false') == 'true'}, 'tenants': [{'id': t.id, 'name': t.name, 'quota_mb': t.quota_mb, 'members': db.scalar(select(func.count()).select_from(Membership).where(Membership.tenant_id == t.id)), 'bytes': used_bytes(db, t.id)} for t in tenants], 'users': [user_data(u) | {'active': u.active} for u in db.scalars(select(User).order_by(User.created_at.desc()))], 'domains': [{'host': d.host, 'tenant_id': d.tenant_id} for d in db.scalars(select(Domain))], 'system': {'database': engine.dialect.name, **storage_summary(), 'max_upload_mb': MAX_UPLOAD // 1024 // 1024, 'cookie_secure': COOKIE_SECURE}}


@app.put('/api/admin/settings')
def update_settings(data: SettingsInput, user=Depends(admin_user), db=Depends(get_db)):
    for key, value in data.model_dump().items():
        if value is None:
            continue
        db.merge(Setting(key=key, value=str(value).lower() if isinstance(value, bool) else value))
    audit(db, user, None, 'server.settings_changed')
    db.commit()
    return {'ok': True}


@app.post('/api/admin/domains')
def add_domain(data: DomainInput, user=Depends(admin_user), db=Depends(get_db)):
    if data.tenant_id and not db.get(Tenant, data.tenant_id):
        raise HTTPException(404, 'Mandant nicht gefunden.')
    db.merge(Domain(host=data.host.lower(), tenant_id=data.tenant_id))
    audit(db, user, None, 'server.domain_added', data.host)
    db.commit()
    return {'ok': True}


@app.delete('/api/admin/domains/{host}')
def delete_domain(host: str, user=Depends(admin_user), db=Depends(get_db)):
    domain = db.get(Domain, host)
    if domain:
        db.delete(domain)
    audit(db, user, None, 'server.domain_deleted', host)
    db.commit()
    return {'ok': True}


@app.put('/api/admin/tenants/{tenant_id}/quota')
def set_quota(tenant_id: str, data: QuotaInput, user=Depends(admin_user), db=Depends(get_db)):
    tenant = db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(404, 'Mandant nicht gefunden.')
    tenant.quota_mb = data.quota_mb
    audit(db, user, None, 'server.quota_changed', tenant_id)
    db.commit()
    return {'ok': True}


@app.post('/api/admin/users/{user_id}/toggle')
def toggle_user(user_id: str, user=Depends(admin_user), db=Depends(get_db)):
    target = db.get(User, user_id)
    if not target or target.admin:
        raise HTTPException(400, 'Administratorkonten können hier nicht gesperrt werden.')
    target.active = not target.active
    db.execute(delete(LoginSession).where(LoginSession.user_id == user_id))
    db.execute(delete(MFAChallenge).where(MFAChallenge.user_id == user_id))
    audit(db, user, None, 'server.user_toggled', user_id)
    db.commit()
    return {'ok': True}


@app.get('/api/admin/auth/{kind}')
def auth_config(kind: str, user=Depends(admin_user), db=Depends(get_db)):
    if kind not in {'ldap', 'oidc'}:
        raise HTTPException(404)
    value = setting(db, kind)
    config = decrypt(value) if value else {}
    return {k: '••••••••' if k in {'bind_password', 'client_secret'} and v else v for k, v in config.items()}


@app.put('/api/admin/auth/{kind}')
def save_auth(kind: str, data: IntegrationInput, user=Depends(admin_user), db=Depends(get_db)):
    from .auth import validate_auth
    if kind not in {'ldap', 'oidc'}:
        raise HTTPException(404)
    old = decrypt(setting(db, kind)) if setting(db, kind) else {}
    config = data.config.copy()
    for key in {'bind_password', 'client_secret'}:
        if config.get(key) == '••••••••':
            config[key] = old.get(key, '')
    validate_auth(kind, config, data.enabled)
    db.merge(Setting(key=kind, value=encrypt(config) if data.enabled else ''))
    audit(db, user, None, 'server.auth_configured', kind)
    db.commit()
    return {'ok': True}


from .oidc import (router as oidc_router, client_for as oidc_client, claims_error,
                   ERRORS as OIDC_ERRORS, error_code, test_user, save_result, check, account_check)
app.include_router(oidc_router)


@app.get('/api/auth/oidc')
async def oidc_start(request: Request, db=Depends(get_db)):
    client, config = oidc_client(db)
    request.session.clear()
    return await client.authorize_redirect(request, config['redirect_uri'])


@app.get('/api/auth/oidc/callback')
async def oidc_callback(request: Request, db=Depends(get_db)):
    from .auth import external_user
    marker = request.session.get('oidc_test')
    reason = None
    try:
        tester = test_user(request, db, marker) if marker else None
        client, config = oidc_client(db)
        token = await client.authorize_access_token(request)
        info = token.get('userinfo')
        reason = claims_error(info, config)
        if reason:
            raise ValueError('claims')
        if marker:
            checks = [check('token', 'Anmeldung und Token', 'success', 'Rückleitung, Client-Secret, PKCE, Signatur und ID-Token-Prüfung erfolgreich.'),
                      check('email', 'E-Mail-Adresse', 'success', 'E-Mail-Adresse vorhanden. Bestätigung ist erforderlich und erfüllt.' if config.get('require_verified_email', False) else 'E-Mail-Adresse vorhanden. Eine Bestätigung ist nicht erforderlich.'),
                      account_check(db, info, tester)]
            save_result(request, marker, checks)
            return RedirectResponse('/?oidc_test=1')
        user = external_user(db, 'oidc:' + info['iss'], info['sub'], info['email'], info.get('name') or info['email'], request)
        response = RedirectResponse('/')
        challenge = login(db, user, response)
        if challenge:
            response.headers['location'] = '/?mfa=1'
        request.session.clear()
        return response
    except Exception as exc:
        db.rollback()
        reason = reason or ('state' if marker and isinstance(exc, ValueError) and str(exc) == 'state' else error_code(exc))
        if marker:
            save_result(request, marker, [check('signin', 'Anmeldetest', 'error', OIDC_ERRORS[reason])])
            return RedirectResponse('/?oidc_test=1')
        # Preserve outstanding state after an unrelated callback; Authlib consumes the matching state.
        suffix = '' if reason == 'state' else '&reason=' + reason
        return RedirectResponse('/?auth_error=1' + suffix)


@app.get('/')
def index():
    return FileResponse(STATIC / 'index.html', headers={'Cache-Control': 'no-cache'})


@app.get('/manifest.webmanifest')
def manifest(db=Depends(get_db)):
    from fastapi.responses import JSONResponse
    name = setting(db, 'app_name', 'Archivraum')
    return JSONResponse({'id': '/', 'name': name, 'short_name': name[:24], 'lang': 'de', 'start_url': '/', 'scope': '/', 'display': 'standalone', 'background_color': '#f5f7fb', 'theme_color': '#4f46e5', 'icons': [{'src': '/static/icon-192.png', 'sizes': '192x192', 'type': 'image/png', 'purpose': 'any'}, {'src': '/static/icon-512.png', 'sizes': '512x512', 'type': 'image/png', 'purpose': 'any'}]}, media_type='application/manifest+json', headers={'Cache-Control': 'no-cache'})


@app.get('/sw.js')
def service_worker():
    return FileResponse(STATIC / 'sw.js', media_type='application/javascript', headers={'Cache-Control': 'no-cache', 'Service-Worker-Allowed': '/'})


app.mount('/static', StaticFiles(directory=STATIC), name='static')


@app.get('/api/tenants/{tenant_id}/codex')
def tenant_codex(tenant_id: str, user=Depends(current_user), db=Depends(get_db)):
    from . import codex_client
    membership(db, user, tenant_id, 'owner')
    allowed = codex_client.enabled_for(db, tenant_id)
    if not allowed:
        return {'allowed': False, 'connected': False, 'models': []}
    status = codex_client.status()
    models = []
    if status.get('connected'):
        try:
            models = codex_client.request('GET', 'models')['models']
        except HTTPException:
            pass
    return {'allowed': True, 'connected': status.get('connected', False), 'models': models}


@app.get('/api/admin/codex')
def admin_codex(user=Depends(admin_user), db=Depends(get_db)):
    from . import codex_client
    return codex_client.status() | {'allowed_tenants': codex_client.allowed_tenants(db)}


@app.post('/api/admin/codex/login')
def codex_login(user=Depends(admin_user), db=Depends(get_db)):
    from . import codex_client
    result = codex_client.request('POST', 'login', timeout=35)
    audit(db, user, None, 'codex.login_started')
    db.commit()
    return result


@app.post('/api/admin/codex/logout')
def codex_logout(user=Depends(admin_user), db=Depends(get_db)):
    from . import codex_client
    result = codex_client.request('POST', 'logout')
    audit(db, user, None, 'codex.disconnected')
    db.commit()
    return result


@app.put('/api/admin/codex/tenants')
def codex_tenants(data: CodexTenantsInput, user=Depends(admin_user), db=Depends(get_db)):
    ids = sorted(set(data.tenant_ids))
    if len(ids) != db.scalar(select(func.count()).select_from(Tenant).where(Tenant.id.in_(ids))):
        raise HTTPException(404, 'Dokumentenraum nicht gefunden.')
    db.merge(Setting(key='codex.allowed_tenants', value=json.dumps(ids)))
    audit(db, user, None, 'codex.tenants_changed', str(len(ids)) + ' Mandanten freigegeben')
    db.commit()
    return {'ok': True}


from .mfa import router as mfa_router
from .features import router as features_router
from .tenant_backup import router as backup_router
app.include_router(mfa_router)
app.include_router(features_router)
app.include_router(backup_router)
from .workspace_tools import router as workspace_router
app.include_router(workspace_router)

from .storage_api import router as storage_router
app.include_router(storage_router)
from .storage_control import StorageGateMiddleware
app.add_middleware(StorageGateMiddleware)
