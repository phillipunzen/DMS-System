"""RFC 6238 TOTP, hashed recovery codes and restricted login challenges."""
import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from datetime import timedelta
from urllib.parse import quote, urlencode
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from .db import UserMFA, MFAChallenge, User, LoginSession, now, get_db
from .security import current_user, encrypt, decrypt, digest, passwords, audit, setting, COOKIE_SECURE
from .auth import rate_limit

router = APIRouter()


class MFAInput(BaseModel):
    password: str = Field(default='', max_length=256)
    code: str = Field(default='', max_length=40)


def totp(seed, counter, digits=6):
    key = base64.b32decode(seed + '=' * (-len(seed) % 8))
    value = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = value[-1] & 15
    return str((struct.unpack('>I', value[offset:offset + 4])[0] & 0x7fffffff) % (10 ** digits)).zfill(digits)


def current_counter():
    return int(time.time()) // 30


def verify_factor(factor, code, recovery=True):
    code = code.strip().replace(' ', '')
    seed = decrypt(factor.secret_encrypted)['secret']
    current = current_counter()
    if len(code) == 6 and code.isascii() and code.isdigit():
        for counter in [current, current - 1, current + 1]:
            if counter > factor.last_counter and hmac.compare_digest(totp(seed, counter), code):
                factor.last_counter = counter
                return True
    if recovery:
        hashed = digest(code.replace('-', '').lower())
        for saved in factor.recovery_hashes:
            if hmac.compare_digest(saved, hashed):
                factor.recovery_hashes = [s for s in factor.recovery_hashes if s != saved]
                return True
    return False


def check_password(user, password):
    if user.password_hash and not passwords.verify(password, user.password_hash):
        raise HTTPException(400, 'Aktuelles Passwort stimmt nicht.')


def limited(db, request, user_id):
    rate_limit(db, 'mfa:' + user_id, 'mfa:' + (request.client.host if request.client else 'unknown'))


def recovery_codes(factor):
    values = [secrets.token_hex(8) for _ in range(10)]
    factor.recovery_hashes = [digest(v) for v in values]
    return ['-'.join(v[i:i + 4] for i in range(0, 16, 4)) for v in values]


@router.get('/api/me/mfa')
def status(user=Depends(current_user), db=Depends(get_db)):
    factor = db.get(UserMFA, user.id)
    return {'enabled': bool(factor and factor.enabled), 'recovery_remaining': len(factor.recovery_hashes) if factor and factor.enabled else 0, 'password_required': bool(user.password_hash)}


@router.post('/api/me/mfa/setup')
def setup(data: MFAInput, request: Request, user=Depends(current_user), db=Depends(get_db)):
    limited(db, request, user.id)
    check_password(user, data.password)
    factor = db.scalar(select(UserMFA).where(UserMFA.user_id == user.id).with_for_update())
    if factor and factor.enabled:
        raise HTTPException(409, 'Zwei-Faktor-Anmeldung ist bereits aktiviert.')
    seed = base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
    if not factor:
        factor = UserMFA(user_id=user.id, secret_encrypted=encrypt({'secret': seed}))
        db.add(factor)
    factor.secret_encrypted = encrypt({'secret': seed})
    factor.pending_until = now() + timedelta(minutes=10)
    factor.last_counter = -1
    factor.recovery_hashes = []
    db.commit()
    issuer = setting(db, 'app_name', 'Archivraum')
    uri = 'otpauth://totp/' + quote(issuer + ':' + user.email, safe='') + '?' + urlencode({'secret': seed, 'issuer': issuer, 'algorithm': 'SHA1', 'digits': 6, 'period': 30})
    import qrcode
    image = qrcode.make(uri); output = io.BytesIO(); image.save(output, format='PNG')
    return {'secret': seed, 'qr': 'data:image/png;base64,' + base64.b64encode(output.getvalue()).decode(), 'expires_at': factor.pending_until}


@router.post('/api/me/mfa/enable')
def enable(data: MFAInput, request: Request, response: Response, user=Depends(current_user), db=Depends(get_db)):
    limited(db, request, user.id)
    factor = db.scalar(select(UserMFA).where(UserMFA.user_id == user.id).with_for_update())
    if not factor or factor.enabled or not factor.pending_until or factor.pending_until < now():
        raise HTTPException(409, 'Einrichtung fehlt oder ist abgelaufen. Bitte neu beginnen.')
    if not verify_factor(factor, data.code, recovery=False):
        raise HTTPException(400, 'Authenticator-Code ist ungültig.')
    factor.enabled = True; factor.pending_until = None
    codes = recovery_codes(factor)
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    db.execute(delete(MFAChallenge).where(MFAChallenge.user_id == user.id))
    audit(db, user, None, 'auth.mfa_enabled')
    from .security import login
    login(db, user, response, mfa_verified=True)
    return {'recovery_codes': codes}


@router.post('/api/me/mfa/disable')
def disable(data: MFAInput, request: Request, response: Response, user=Depends(current_user), db=Depends(get_db)):
    limited(db, request, user.id); check_password(user, data.password)
    factor = db.scalar(select(UserMFA).where(UserMFA.user_id == user.id).with_for_update())
    if not factor or not factor.enabled or not verify_factor(factor, data.code):
        raise HTTPException(400, 'Authenticator- oder Wiederherstellungscode ist ungültig.')
    db.delete(factor)
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    db.execute(delete(MFAChallenge).where(MFAChallenge.user_id == user.id))
    audit(db, user, None, 'auth.mfa_disabled')
    from .security import login
    login(db, user, response, mfa_verified=True)
    return {'ok': True}


@router.post('/api/me/mfa/recovery')
def regenerate(data: MFAInput, request: Request, user=Depends(current_user), db=Depends(get_db)):
    limited(db, request, user.id); check_password(user, data.password)
    factor = db.scalar(select(UserMFA).where(UserMFA.user_id == user.id).with_for_update())
    if not factor or not factor.enabled or not verify_factor(factor, data.code):
        raise HTTPException(400, 'Authenticator- oder Wiederherstellungscode ist ungültig.')
    codes = recovery_codes(factor)
    audit(db, user, None, 'auth.mfa_recovery_regenerated'); db.commit()
    return {'recovery_codes': codes}


@router.post('/api/auth/mfa/verify')
def verify(data: MFAInput, request: Request, response: Response, db=Depends(get_db)):
    token = request.cookies.get('dms_mfa', '')
    limited(db, request, digest(token))
    challenge = db.scalar(select(MFAChallenge).where(MFAChallenge.token_hash == digest(token)).with_for_update())
    if not challenge or challenge.expires_at < now() or challenge.attempts >= 5:
        raise HTTPException(401, 'Anmeldung ist abgelaufen. Bitte erneut mit Passwort anmelden.')
    factor = db.scalar(select(UserMFA).where(UserMFA.user_id == challenge.user_id).with_for_update())
    user = db.get(User, challenge.user_id)
    challenge.attempts += 1
    if not user or not user.active or not factor or not factor.enabled or not verify_factor(factor, data.code):
        db.commit()
        raise HTTPException(401, 'Code ungültig oder bereits verwendet.')
    db.delete(challenge)
    audit(db, user, None, 'auth.mfa_login')
    from .security import login
    login(db, user, response, mfa_verified=True)
    response.delete_cookie('dms_mfa')
    return {'ok': True}


@router.post('/api/auth/mfa/cancel')
def cancel(request: Request, response: Response, db=Depends(get_db)):
    db.execute(delete(MFAChallenge).where(MFAChallenge.token_hash == digest(request.cookies.get('dms_mfa', '')))); db.commit()
    response.delete_cookie('dms_mfa')
    return {'ok': True}
