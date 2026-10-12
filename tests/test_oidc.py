import base64
import hashlib
import time
from urllib.parse import parse_qs, urlparse
import httpx
import pytest
from authlib.jose import JsonWebKey, jwt
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from app.main import app
from app.db import SessionLocal, Setting, User, Identity, LoginSession
from app.security import encrypt, setting

ISSUER = 'https://authentik.example.com'
CONFIG = {'discovery_url': ISSUER+'/.well-known/openid-configuration', 'client_id': 'dms-client',
          'client_secret': 'private-client-secret', 'redirect_uri': 'http://localhost/api/auth/oidc/callback'}


@pytest.fixture
def provider(monkeypatch):
    key = JsonWebKey.generate_key('RSA', 2048, is_private=True, options={'kid': 'test'})
    wrong_key = JsonWebKey.generate_key('RSA', 2048, is_private=True, options={'kid': 'test'})
    state = {'verified': False, 'email': 'oidc-new@example.com', 'nonce': '', 'challenge': '', 'invalid_signature': False, 'invalid_nonce': False, 'invalid_client': False, 'bad_keys': False, 'discovery_status': 200}
    def handler(request):
        if request.url.path == '/.well-known/openid-configuration':
            return httpx.Response(state['discovery_status'], json={'issuer': ISSUER, 'authorization_endpoint': ISSUER+'/authorize', 'token_endpoint': ISSUER+'/token', 'jwks_uri': ISSUER+'/jwks', 'response_types_supported': ['code'], 'scopes_supported': ['openid', 'profile', 'email'], 'code_challenge_methods_supported': ['S256'], 'id_token_signing_alg_values_supported': ['RS256'], 'subject_types_supported': ['public']})
        if request.url.path == '/jwks':
            return httpx.Response(200, json={'keys': [] if state['bad_keys'] else [key.as_dict(is_private=False)]})
        if request.url.path == '/token':
            if state['invalid_client']:
                return httpx.Response(400, json={'error': 'invalid_client', 'error_description': 'private-client-secret MUST NEVER BE SHOWN'})
            body = parse_qs(request.content.decode())
            verifier = body['code_verifier'][0]
            assert base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=') == state['challenge']
            claims = {'iss': ISSUER, 'sub': 'authentik-user', 'aud': 'dms-client', 'exp': int(time.time())+600, 'iat': int(time.time()), 'nonce': 'wrong' if state['invalid_nonce'] else state['nonce'], 'email': state['email'], 'name': 'Test user'}
            if state['verified'] is not None:
                claims['email_verified'] = state['verified']
            signed = jwt.encode({'alg': 'RS256', 'kid': 'test'}, claims, wrong_key if state['invalid_signature'] else key).decode()
            return httpx.Response(200, json={'access_token': 'private-access-token', 'token_type': 'Bearer', 'id_token': signed})
        raise AssertionError(str(request.url))
    original = httpx.AsyncClient.__init__
    def patched(self, *args, **kwargs):
        kwargs['transport'] = httpx.MockTransport(handler)
        return original(self, *args, **kwargs)
    monkeypatch.setattr(httpx.AsyncClient, '__init__', patched)
    return state


def configure(verified=False):
    with SessionLocal() as db:
        db.merge(Setting(key='oidc', value=encrypt({**CONFIG, 'require_verified_email': verified})))
        db.merge(Setting(key='registration_enabled', value='true'))
        db.commit()


def snapshot():
    with SessionLocal() as db:
        return [db.scalar(select(func.count()).select_from(model)) for model in (User, Identity, LoginSession)]


def start_test(admin, provider):
    result = admin.post('/api/admin/auth/oidc/test/start', json={})
    assert result.status_code == 200, result.text
    params = parse_qs(urlparse(result.json()['url']).query)
    assert params['code_challenge_method'] == ['S256']
    provider.update(nonce=params['nonce'][0], challenge=params['code_challenge'][0])
    return params['state'][0]


def finish_test(admin, state):
    response = admin.get('/api/auth/oidc/callback', params={'code': 'valid', 'state': state}, follow_redirects=False)
    assert response.headers['location'] == '/?oidc_test=1', response.text
    return admin.get('/api/admin/auth/oidc/test/result').json()


def test_config_uses_masked_saved_secret_without_mutation(admin, provider):
    configure()
    with SessionLocal() as db:
        before = setting(db, 'oidc')
    result = admin.post('/api/admin/auth/oidc/test', json={'config': {**CONFIG, 'client_secret': '••••••••'}, 'browser_origin': 'http://localhost'})
    assert result.status_code == 200
    assert result.json()['ok']
    assert any(c['key'] == 'signin' and c['status'] == 'pending' for c in result.json()['checks'])
    assert 'private-client-secret' not in result.text
    with SessionLocal() as db:
        assert setting(db, 'oidc') == before


@pytest.mark.parametrize('changes', [{'redirect_uri': 'http://another-host/api/auth/oidc/callback'}, {'discovery_url': 'http://authentik.example.com/discovery'}, {'client_secret': ''}])
def test_config_reports_invalid_settings(admin, provider, changes):
    result = admin.post('/api/admin/auth/oidc/test', json={'config': {**CONFIG, **changes}, 'browser_origin': 'http://localhost'})
    assert result.status_code == 200
    assert not result.json()['ok']


@pytest.mark.parametrize('failure', ['bad_keys', 'discovery_status'])
def test_config_reports_provider_failure(admin, provider, failure):
    provider[failure] = True if failure == 'bad_keys' else 404
    response = admin.post('/api/admin/auth/oidc/test', json={'config': CONFIG, 'browser_origin': 'http://localhost'})
    assert response.status_code == 200
    assert not response.json()['ok']


def test_diagnostics_require_admin_csrf_and_same_host(admin, alice):
    data = {'config': CONFIG, 'browser_origin': 'http://localhost'}
    assert alice.post('/api/admin/auth/oidc/test', json=data).status_code == 403
    assert alice.post('/api/admin/auth/oidc/test/start', json={}).status_code == 403
    assert alice.get('/api/admin/auth/oidc/test/result').status_code == 403
    assert admin.post('/api/admin/auth/oidc/test', json={**data, 'browser_origin': 'https://foreign.example'}).status_code == 422
    assert admin.post('/api/admin/auth/oidc/test', json=data, headers={'X-CSRF-Token': ''}).status_code == 403


@pytest.mark.parametrize('verified', [False, None])
def test_real_diagnostic_accepts_unverified_email_and_preserves_session(admin, provider, verified):
    configure()
    provider['verified'] = verified
    before = snapshot()
    cookie = admin.cookies['dms_session']
    uid = admin.get('/api/me').json()['id']
    result = finish_test(admin, start_test(admin, provider))
    assert result['ok'], result
    assert snapshot() == before
    assert admin.cookies['dms_session'] == cookie
    assert admin.get('/api/me').json()['id'] == uid
    assert 'private-client-secret' not in str(result) and 'private-access-token' not in str(result)
    assert admin.get('/api/admin/auth/oidc/test/result').status_code == 404


def test_optional_email_confirmation_reports_specific_error(admin, provider):
    configure(verified=True)
    result = finish_test(admin, start_test(admin, provider))
    assert not result['ok']
    assert 'email_verified' in result['checks'][0]['message']
    assert snapshot()[1] == 0


@pytest.mark.parametrize('failure', ['invalid_client', 'invalid_signature', 'invalid_nonce'])
def test_real_diagnostic_rejects_bad_credentials_tokens(admin, provider, failure):
    configure()
    before = snapshot()
    provider[failure] = True
    result = finish_test(admin, start_test(admin, provider))
    assert not result['ok']
    assert 'private-client-secret' not in str(result)
    assert snapshot() == before


def test_real_diagnostic_rejects_wrong_state_without_account_changes(admin, provider):
    configure()
    before = snapshot()
    start_test(admin, provider)
    result = finish_test(admin, 'wrong-state')
    assert not result['ok']
    assert 'Rückleitung' in result['checks'][0]['message']
    assert snapshot() == before


def test_real_diagnostic_detects_configuration_changed_mid_flow(admin, provider):
    configure()
    state = start_test(admin, provider)
    configure(verified=True)
    result = finish_test(admin, state)
    assert not result['ok']
    assert 'Konfiguration' in result['checks'][0]['message']


def test_test_requires_enabled_saved_configuration(admin):
    assert admin.post('/api/admin/auth/oidc/test/start', json={}).status_code == 400


@pytest.mark.parametrize('verified', [False, None])
def test_regular_login_accepts_email_without_verification(provider, verified):
    configure()
    provider['verified'] = verified
    client = TestClient(app, base_url='http://localhost')
    start = client.get('/api/auth/oidc', follow_redirects=False)
    params = parse_qs(urlparse(start.headers['location']).query)
    provider.update(nonce=params['nonce'][0], challenge=params['code_challenge'][0])
    response = client.get('/api/auth/oidc/callback', params={'code': 'valid', 'state': params['state'][0]}, follow_redirects=False)
    assert response.headers['location'] == '/'
    assert client.get('/api/me').json()['email'] == 'oidc-new@example.com'


def test_unverified_email_does_not_take_over_existing_local_account(admin, provider):
    configure()
    provider['email'] = 'admin@example.com'
    client = TestClient(app, base_url='http://localhost')
    start = client.get('/api/auth/oidc', follow_redirects=False)
    params = parse_qs(urlparse(start.headers['location']).query)
    provider.update(nonce=params['nonce'][0], challenge=params['code_challenge'][0])
    response = client.get('/api/auth/oidc/callback', params={'code': 'valid', 'state': params['state'][0]}, follow_redirects=False)
    assert response.headers['location'] == '/?auth_error=1&reason=existing_account'
    assert client.get('/api/me').status_code == 401
    assert snapshot()[1] == 0


def test_email_confirmation_cannot_be_saved_as_truthy_string(admin):
    response = admin.put('/api/admin/auth/oidc', json={'enabled': True, 'config': {**CONFIG, 'require_verified_email': 'false'}})
    assert response.status_code == 422


def test_legacy_config_and_missing_email_confirmation(provider):
    configure()
    with SessionLocal() as db:
        db.merge(Setting(key='oidc', value=encrypt(CONFIG)))
        db.commit()
    provider['verified'] = None
    client = TestClient(app, base_url='http://localhost')
    start = client.get('/api/auth/oidc', follow_redirects=False)
    params = parse_qs(urlparse(start.headers['location']).query)
    provider.update(nonce=params['nonce'][0], challenge=params['code_challenge'][0])
    response = client.get('/api/auth/oidc/callback', params={'code': 'valid', 'state': params['state'][0]}, follow_redirects=False)
    assert response.headers['location'] == '/'


@pytest.mark.parametrize('email', ['', None])
def test_email_address_still_required(admin, provider, email):
    configure()
    provider['email'] = email
    result = finish_test(admin, start_test(admin, provider))
    assert not result['ok']
    assert 'E-Mail-Adresse' in result['checks'][0]['message']
    assert snapshot()[1] == 0


def test_verified_email_can_still_be_required_and_pass(admin, provider):
    configure(verified=True)
    provider['verified'] = True
    result = finish_test(admin, start_test(admin, provider))
    assert result['ok'], result


def test_diagnostic_rejects_lost_admin_session(admin, provider):
    configure()
    state = start_test(admin, provider)
    admin.cookies.delete('dms_session')
    response = admin.get('/api/auth/oidc/callback', params={'code': 'valid', 'state': state}, follow_redirects=False)
    assert response.headers['location'] == '/?oidc_test=1'
    assert admin.get('/api/me').status_code == 401
    assert snapshot()[1] == 0
