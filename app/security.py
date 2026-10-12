import hashlib
import json
import os
import secrets
from datetime import timedelta
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, Request, Response
from pwdlib import PasswordHash
from sqlalchemy import select
from .db import User, LoginSession, Membership, Audit, Setting, UserMFA, MFAChallenge, now, get_db

passwords = PasswordHash.recommended()
secret = os.environ.get('SECRET_KEY', '')
if len(secret) < 32:
    raise RuntimeError('SECRET_KEY muss mindestens 32 Zeichen enthalten.')
import base64
fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'true').lower() == 'true'
ROLES = {'viewer': 0, 'editor': 1, 'manager': 2, 'owner': 3}


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def encrypt(data):
    return fernet.encrypt(json.dumps(data).encode()).decode()


def decrypt(data):
    return json.loads(fernet.decrypt(data.encode()))


def setting(db, key, default=''):
    s = db.get(Setting, key)
    return s.value if s else default


def audit(db, user, tenant, action, detail=''):
    db.add(Audit(actor_id=user.id if user else None, tenant_id=tenant, action=action, detail=detail[:255]))


def current_user(request: Request, db=Depends(get_db)):
    token = request.cookies.get('dms_session', '')
    session = db.get(LoginSession, digest(token)) if token else None
    user = db.get(User, session.user_id) if session and session.expires_at > now() else None
    if not user or not user.active:
        raise HTTPException(401, 'Bitte anmelden.')
    return user


def admin_user(user=Depends(current_user)):
    if not user.admin:
        raise HTTPException(403, 'Serveradministrator erforderlich.')
    return user


def membership(db, user, tenant_id, minimum='viewer'):
    member = db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.tenant_id == tenant_id))
    if not member or ROLES.get(member.role, -1) < ROLES[minimum]:
        raise HTTPException(403, 'Keine Berechtigung für diesen Mandanten.')
    return member


def login(db, user, response: Response, mfa_verified=False):
    factor = db.get(UserMFA, user.id)
    if factor and factor.enabled and not mfa_verified:
        token = secrets.token_urlsafe(48)
        db.add(MFAChallenge(token_hash=digest(token), user_id=user.id, expires_at=now() + timedelta(minutes=5)))
        db.commit()
        response.delete_cookie('dms_session')
        response.set_cookie('dms_mfa', token, max_age=300, httponly=True, secure=COOKIE_SECURE, samesite='lax', path='/')
        response.set_cookie('dms_csrf', secrets.token_urlsafe(32), max_age=300, secure=COOKIE_SECURE, samesite='lax', path='/')
        return {'mfa_required': True}
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    db.add(LoginSession(token_hash=digest(token), user_id=user.id, expires_at=now() + timedelta(hours=12)))
    db.commit()
    response.set_cookie('dms_session', token, max_age=43200, httponly=True, secure=COOKIE_SECURE, samesite='lax', path='/')
    response.set_cookie('dms_csrf', csrf, max_age=43200, secure=COOKIE_SECURE, samesite='lax', path='/')


def strong_password(password):
    if len(password) < 12 or len(password) > 256:
        raise HTTPException(422, 'Das Passwort muss 12 bis 256 Zeichen enthalten.')
    return passwords.hash(password)
