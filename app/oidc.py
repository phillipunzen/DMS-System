"""OIDC diagnostics: no account creation, linking or replacement of the admin session."""
import json
import secrets
import time
from urllib.parse import urlparse
import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from .db import get_db, User, Identity
from .security import admin_user, current_user, setting, decrypt, digest, COOKIE_SECURE

router = APIRouter()
MASK = '••••••••'


def client_for(db):
    value = setting(db, 'oidc')
    if not value:
        raise HTTPException(400, 'OIDC ist nicht konfiguriert oder aktiviert.')
    config = decrypt(value)
    oauth = OAuth()
    oauth.register(name='provider', client_id=config['client_id'], client_secret=config['client_secret'],
                   server_metadata_url=config['discovery_url'], client_kwargs={
                       'scope': 'openid profile email', 'code_challenge_method': 'S256',
                       'timeout': 10, 'trust_env': False})
    return oauth.create_client('provider'), config


def check(key, label, status, message):
    return {'key': key, 'label': label, 'status': status, 'message': message}


def report(checks):
    return {'ok': not any(c['status'] == 'error' for c in checks), 'checks': checks}


def claims_error(info, config):
    if not info or not isinstance(info.get('sub'), str) or not info['sub'] or not info.get('iss'):
        return 'claims_missing'
    if not isinstance(info.get('email'), str) or not info['email'].strip() or len(info['email']) > 254 or '@' not in info['email']:
        return 'email_missing'
    if config.get('require_verified_email', False) and info.get('email_verified') is not True:
        return 'email_unverified'
    return None


ERRORS = {
    'claims_missing': 'Im signierten ID-Token fehlen Benutzerkennung oder Aussteller.',
    'email_missing': 'Der Anbieter liefert keine gültige E-Mail-Adresse. Den Scope email und die Zuordnung der E-Mail-Adresse prüfen.',
    'email_unverified': 'Der Anbieter bestätigt die E-Mail-Adresse nicht (email_verified). E-Mail-Bestätigung in den OIDC-Einstellungen ausschalten oder beim Anbieter einrichten.',
    'invalid_client': 'Client-ID oder Client-Secret wird vom Anbieter abgelehnt. Zugangsdaten und vertraulichen Client prüfen.',
    'access_denied': 'Der Anbieter hat die Anmeldung abgelehnt oder sie wurde abgebrochen.',
    'invalid_grant': 'Der Anmeldungscode wurde abgelehnt. Redirect-URI, PKCE und Ablaufzeit beim Anbieter prüfen.',
    'state': 'Die Rückleitung gehört nicht zum gestarteten Anmeldeversuch. Gleiche Domain verwenden und Cookies zulassen; den Test neu starten.',
    'network': 'Der Anbieter ist vom DMS aus nicht erreichbar oder sein TLS-Zertifikat wird nicht akzeptiert.',
    'token': 'Die Tokenprüfung ist fehlgeschlagen. Signaturschlüssel, Aussteller, Client-ID, Nonce und Serverzeit prüfen.',
    'existing_account': 'Bestehendes Konto zuerst lokal anmelden und anschließend unter Konto mit OIDC verknüpfen.',
    'registration_disabled': 'Für dieses neue Konto ist eine Einladung oder eine aktivierte Registrierung erforderlich.',
    'account_disabled': 'Das zugeordnete DMS-Konto ist gesperrt.',
    'configuration': 'OIDC-Konfiguration fehlt, wurde während des Tests geändert oder die Admin-Sitzung ist abgelaufen.',
}


def error_code(exc):
    code = getattr(exc, 'error', '')
    if code in {'invalid_client', 'access_denied', 'invalid_grant'}:
        return code
    if code == 'mismatching_state':
        return 'state'
    if isinstance(exc, httpx.HTTPError):
        return 'network'
    if isinstance(exc, HTTPException):
        return {409: 'existing_account', 403: 'registration_disabled', 401: 'account_disabled'}.get(exc.status_code, 'configuration')
    return 'token'


def account_check(db, info, user):
    identity = db.scalar(select(Identity).where(Identity.provider == 'oidc:' + info['iss'], Identity.subject == info['sub']))
    if identity:
        target = db.get(User, identity.user_id)
        return check('account', 'DMS-Konto', 'success' if target and target.active else 'error',
                     'Eine aktive OIDC-Verknüpfung ist vorhanden.' if target and target.active else ERRORS['account_disabled'])
    target = db.scalar(select(User).where(User.email == info['email'].lower()))
    if target:
        allowed = target.active and target.id == user.id
        return check('account', 'DMS-Konto', 'success' if allowed else 'error',
                     'Dieses lokal angemeldete Konto kann unter Konto mit OIDC verknüpft werden.' if allowed else ERRORS['existing_account'])
    return check('account', 'DMS-Konto', 'success',
                 'Nach erfolgreicher OIDC-Anmeldung wird automatisch ein Konto angelegt. Zugriff auf bestehende Dokumentenräume erfordert eine Mitgliedschaft.')


class TestInput(BaseModel):
    config: dict = Field(default_factory=dict)
    browser_origin: str = Field(max_length=2048)


def valid_https(value):
    if not isinstance(value, str):
        return False
    try:
        url = urlparse(value)
    except ValueError:
        return False
    return url.scheme == 'https' and bool(url.hostname) and not url.username and not url.password and not url.fragment


async def fetch_json(client, url):
    async with client.stream('GET', url) as response:
        response.raise_for_status()
        if response.is_redirect:
            raise ValueError('redirect')
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > 1024 * 1024:
                raise ValueError('size')
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError('object')
        return data


@router.post('/api/admin/auth/oidc/test')
async def test_config(data: TestInput, request: Request, user=Depends(admin_user), db=Depends(get_db)):
    try:
        origin = urlparse(data.browser_origin)
    except ValueError:
        raise HTTPException(422, 'Browseradresse ist ungültig.') from None
    if origin.scheme not in {'http', 'https'} or origin.netloc.lower() != request.headers.get('host', '').lower() or origin.path not in {'', '/'} or origin.query or origin.fragment or origin.username:
        raise HTTPException(422, 'Browseradresse ist ungültig.')
    cfg = data.config.copy()
    if cfg.get('client_secret') == MASK:
        cfg['client_secret'] = decrypt(setting(db, 'oidc')).get('client_secret', '') if setting(db, 'oidc') else ''
    checks = []
    expected = data.browser_origin.rstrip('/') + '/api/auth/oidc/callback'
    redirect_ok = cfg.get('redirect_uri') == expected
    checks.append(check('redirect', 'Weiterleitungsadresse', 'success' if redirect_ok else 'error',
                        'Die Redirect-URI passt zur aktuellen Browseradresse. Beim Anbieter exakt dieselbe URI hinterlegen.' if redirect_ok else 'Die Redirect-URI muss zur aktuellen Browseradresse passen: ' + expected))
    checks.append(check('cookies', 'Browser und Cookies', 'error' if origin.scheme == 'http' and COOKIE_SECURE else 'success' if origin.scheme == 'https' else 'warning',
                        'COOKIE_SECURE=true erfordert HTTPS; über HTTP wird die OIDC-Sitzung nicht zurückgesendet.' if origin.scheme == 'http' and COOKIE_SECURE else 'HTTPS ist aktiv.' if origin.scheme == 'https' else 'HTTP-Testbetrieb: Für den Produktivbetrieb HTTPS verwenden.'))
    if not valid_https(cfg.get('discovery_url')) or not cfg.get('client_id') or not cfg.get('client_secret'):
        checks.append(check('config', 'Pflichtfelder', 'error', 'HTTPS-Discovery-URL, Client-ID und Client-Secret sind erforderlich.'))
        return report(checks)
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
            metadata = await fetch_json(client, cfg['discovery_url'])
            if not all(valid_https(metadata.get(k)) for k in ('issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri')):
                raise ValueError('endpoints')
            if 'code' not in metadata.get('response_types_supported', []):
                raise ValueError('flow')
            if 'code_challenge_methods_supported' in metadata and 'S256' not in metadata['code_challenge_methods_supported']:
                raise ValueError('pkce')
            if 'scopes_supported' in metadata and not all(s in metadata['scopes_supported'] for s in ('openid', 'profile', 'email')):
                raise ValueError('scopes')
            checks.append(check('discovery', 'Anbieter und Anmeldung', 'success', 'Discovery erreichbar; HTTPS-Endpunkte, Authorization Code und angebotene Scopes/PKCE geprüft.'))
            jwks = await fetch_json(client, metadata['jwks_uri'])
            if not any(isinstance(k, dict) and k.get('kty') in {'RSA', 'EC', 'OKP'} and k.get('use', 'sig') == 'sig' for k in jwks.get('keys', [])):
                raise ValueError('keys')
            checks.append(check('keys', 'Signaturschlüssel', 'success', 'Öffentliche Signaturschlüssel sind erreichbar. Die tatsächliche Signatur wird beim Anmeldetest geprüft.'))
    except (httpx.HTTPError, ValueError, TypeError):
        checks.append(check('provider', 'Anbieterkonfiguration', 'error', 'Discovery oder Signaturschlüssel sind nicht erreichbar oder ungeeignet. TLS, Discovery-URL, HTTPS-Endpunkte, Scopes und Signaturschlüssel beim Anbieter prüfen. Bei Authentik einen Signaturschlüssel im Provider auswählen.'))
    checks.append(check('signin', 'Client-Secret und Benutzerangaben', 'pending', 'Noch nicht geprüft. Konfiguration speichern und anschließend Anmeldung testen.'))
    return report(checks)


@router.post('/api/admin/auth/oidc/test/start')
async def test_start(request: Request, user=Depends(admin_user), db=Depends(get_db)):
    client, cfg = client_for(db)
    state = secrets.token_urlsafe(32)
    request.session.clear()
    request.session['oidc_test'] = {'state': state, 'user_id': user.id, 'created': time.time(), 'config': digest(setting(db, 'oidc'))}
    try:
        response = await client.authorize_redirect(request, cfg['redirect_uri'], state=state, response_mode='query')
    except Exception as exc:
        request.session.clear()
        raise HTTPException(400, ERRORS[error_code(exc)]) from None
    return {'url': response.headers['location']}


def test_user(request, db, marker):
    if time.time() - marker.get('created', 0) > 600 or marker.get('state') != request.query_params.get('state'):
        raise ValueError('state')
    user = current_user(request, db)
    if not user.admin or user.id != marker.get('user_id') or digest(setting(db, 'oidc')) != marker.get('config'):
        raise HTTPException(400)
    return user


def save_result(request, marker, checks):
    request.session.clear()
    request.session['oidc_test_result'] = {'user_id': marker.get('user_id'), 'created': time.time(), 'report': report(checks)}


@router.get('/api/admin/auth/oidc/test/result')
def test_result(request: Request, user=Depends(admin_user)):
    result = request.session.pop('oidc_test_result', None)
    if not result or result.get('user_id') != user.id or time.time() - result.get('created', 0) > 600:
        raise HTTPException(404, 'Kein aktuelles Testergebnis vorhanden. Den Anmeldetest erneut starten.')
    return result['report']
