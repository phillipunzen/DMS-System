import os
import tempfile
from pathlib import Path

TMP = tempfile.TemporaryDirectory()
os.environ['DATABASE_URL'] = os.environ['DATABASE_URL'].replace('/dms?', '/dms_test?') if os.getenv('TEST_MARIADB') == 'true' else 'sqlite:///' + TMP.name + '/test.db'
os.environ['STORAGE_ROOT'] = TMP.name + '/documents'
os.environ['SECRET_KEY'] = 'test-secret-' * 6
os.environ['COOKIE_SECURE'] = 'false'
os.environ['ALLOWED_HOSTS'] = 'localhost'
os.environ.pop('BOOTSTRAP_ADMIN_EMAIL', None)
os.environ.pop('BOOTSTRAP_ADMIN_PASSWORD', None)

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import Base, engine, SessionLocal, User
from app.security import strong_password


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


def account(email, admin=False):
    with SessionLocal() as db:
        user = User(email=email, name=email.split('@')[0], admin=admin, password_hash=strong_password('a-secure-test-password'))
        db.add(user)
        db.commit()
    client = TestClient(app, base_url='http://localhost')
    r = client.post('/api/auth/login', json={'email':email, 'password':'a-secure-test-password'})
    assert r.status_code == 200, r.text
    client.headers['X-CSRF-Token'] = client.cookies['dms_csrf']
    return client


@pytest.fixture
def alice():
    return account('alice@example.com')


@pytest.fixture
def bob():
    return account('bob@example.com')


@pytest.fixture
def admin():
    return account('admin@example.com', True)
