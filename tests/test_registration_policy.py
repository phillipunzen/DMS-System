"""Invitation-only local accounts and authenticated directory provisioning."""
from types import SimpleNamespace
from datetime import timedelta
import ssl
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, func
from app.main import app
from app.db import SessionLocal, Setting, User, Identity, Membership, Invitation, now
from app.security import encrypt


@pytest.mark.parametrize('legacy_setting', [None, 'false', 'true'])
def test_local_registration_requires_invitation_even_with_legacy_flag(admin, legacy_setting):
    if legacy_setting is not None:
        with SessionLocal() as db:
            db.merge(Setting(key='registration_enabled', value=legacy_setting))
            db.commit()
    client = TestClient(app, base_url='http://localhost')
    assert client.get('/api/public').json()['registration_enabled'] is False
    assert admin.get('/api/admin').json()['settings']['registration_enabled'] is False
    result = client.post('/api/auth/register', json={
        'email': 'new@example.com', 'name': 'New', 'password': 'secure-long-password'})
    assert result.status_code == 403
    assert client.get('/api/me').status_code == 401
    with SessionLocal() as db:
        assert db.scalar(select(User).where(User.email == 'new@example.com')) is None


def test_admin_cannot_enable_public_local_registration(admin):
    assert admin.put('/api/admin/settings', json={
        'app_name': 'DMS', 'registration_enabled': True}).status_code == 422
    assert admin.put('/api/admin/settings', json={'app_name': 'DMS'}).status_code == 200


def test_local_invitation_creates_account_and_limits_access_to_invited_space(alice):
    tid = alice.post('/api/tenants', json={'name': 'Invited space'}).json()['id']
    invite = alice.post(f'/api/tenants/{tid}/invitations', json={
        'email': 'new@example.com', 'role': 'viewer'}).json()
    client = TestClient(app, base_url='http://localhost')
    result = client.post('/api/invitations/accept', json={
        'token': invite['token'], 'name': 'New', 'password': 'secure-long-password'})
    assert result.status_code == 200
    me = client.get('/api/me').json()
    assert not me['admin'] and len(me['tenants']) == 1
    assert me['tenants'][0]['id'] == tid and me['tenants'][0]['role'] == 'viewer'


def test_expired_invitation_cannot_create_local_account(alice):
    tid = alice.post('/api/tenants', json={'name': 'Invited space'}).json()['id']
    invite = alice.post(f'/api/tenants/{tid}/invitations', json={
        'email': 'new@example.com', 'role': 'viewer'}).json()
    with SessionLocal() as db:
        entry = db.scalar(select(Invitation).where(Invitation.email == 'new@example.com'))
        entry.expires_at = now() - timedelta(seconds=1)
        db.commit()
    client = TestClient(app, base_url='http://localhost')
    result = client.post('/api/invitations/accept', json={
        'token': invite['token'], 'name': 'New', 'password': 'secure-long-password'})
    assert result.status_code == 404
    with SessionLocal() as db:
        assert db.scalar(select(User).where(User.email == 'new@example.com')) is None


@pytest.fixture
def directory(monkeypatch):
    cfg = {'host': 'ldap.example.com', 'port': 636, 'transport': 'ldaps',
           'base_dn': 'DC=example,DC=com', 'bind_dn': 'CN=reader',
           'bind_password': 'bind-secret', 'filter': '(mail={email})'}
    with SessionLocal() as db:
        db.merge(Setting(key='ldap', value=encrypt(cfg)))
        db.commit()
    state = {'found': True}
    class Connection:
        def __init__(self, server, user, password, **kwargs):
            assert server.ssl and server.tls.validate == ssl.CERT_REQUIRED
            if user == cfg['bind_dn']:
                assert password == cfg['bind_password']
            elif password != 'directory-password':
                raise ValueError('Invalid credentials')
            self.entries = []
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def search(self, base, query, **kwargs):
            assert query == '(mail=directory@example.com)'
            self.entries = [SimpleNamespace(entry_dn='CN=Directory User,DC=example,DC=com',
                mail=SimpleNamespace(value='directory@example.com'),
                displayName=SimpleNamespace(value='Directory User'))] if state['found'] else []
    monkeypatch.setattr('app.auth.Connection', Connection)
    return state


def test_ldap_provisions_without_invitation_and_reuses_identity(directory):
    client = TestClient(app, base_url='http://localhost')
    data = {'email': 'directory@example.com', 'password': 'directory-password', 'method': 'ldap'}
    assert client.post('/api/auth/login', json=data).status_code == 200
    me = client.get('/api/me').json()
    assert not me['admin'] and me['tenants'] == []
    assert client.post('/api/auth/login', json=data).status_code == 200
    assert client.get('/api/me').json()['id'] == me['id']
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 1
        assert db.scalar(select(func.count()).select_from(Identity)) == 1
        assert db.scalar(select(func.count()).select_from(Membership)) == 0
        assert db.get(User, me['id']).password_hash is None
        db.get(User, me['id']).active = False
        db.commit()
    assert client.post('/api/auth/login', json=data).status_code == 401


@pytest.mark.parametrize('failure', ['wrong_password', 'not_found'])
def test_failed_ldap_authentication_cannot_provision_account(directory, failure):
    directory['found'] = failure != 'not_found'
    client = TestClient(app, base_url='http://localhost')
    result = client.post('/api/auth/login', json={'email': 'directory@example.com',
        'password': 'wrong' if failure == 'wrong_password' else 'directory-password', 'method': 'ldap'})
    assert result.status_code == 401
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0
        assert db.scalar(select(func.count()).select_from(Identity)) == 0
