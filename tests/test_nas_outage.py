"""An offline or stale NAS must not take administration down or consume jobs."""
import errno
import importlib
import json
from unittest.mock import Mock
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app import storage_control
from app.db import SessionLocal, Document
from app.main import app

main = importlib.import_module('app.main')


def nas_state(tmp_path, monkeypatch):
    data = {'mode': 'nas', 'mount': '/data/nas/offline', 'source': 'nas:/exports/dms', 'fstype': 'nfs', 'subdirectory': 'archivraum'}
    (tmp_path/'active.json').write_text(json.dumps(data))
    monkeypatch.setattr(storage_control, 'MANAGED', True)
    monkeypatch.setattr(storage_control, 'STATE_ROOT', tmp_path)
    return data


@pytest.mark.parametrize('error', [errno.ENETUNREACH, errno.ESTALE, errno.ETIMEDOUT])
def test_api_start_never_probes_active_nas(admin, tmp_path, monkeypatch, error):
    data = nas_state(tmp_path, monkeypatch)
    inaccessible = Mock()
    inaccessible.mkdir.side_effect = OSError(error, 'offline NAS')
    monkeypatch.setattr(main, 'ROOT', inaccessible)
    # The entry is present, but all actual NAS I/O would fail or block.
    monkeypatch.setattr(storage_control, 'mounted', lambda *args: True)
    with TestClient(app, base_url='http://localhost', cookies=dict(admin.cookies)) as client:
        assert client.get('/api/health').status_code == 200
        assert client.get('/').status_code == 200
        assert client.get('/api/me').status_code == 200
        assert client.get('/api/admin/auth/oidc').status_code == 200
    inaccessible.mkdir.assert_not_called()
    assert json.loads((tmp_path/'active.json').read_text()) == data


def test_start_and_admin_work_with_unmounted_nas(admin, tmp_path, monkeypatch):
    nas_state(tmp_path, monkeypatch)
    monkeypatch.setattr(storage_control, 'mounted', lambda *args: False)
    with TestClient(app, base_url='http://localhost', cookies=dict(admin.cookies)) as client:
        assert client.get('/api/health').status_code == 200
        assert client.get('/api/admin/auth/oidc').status_code == 200
        with pytest.raises(HTTPException) as failure:
            storage_control.root('documents')
        assert failure.value.status_code == 503


def test_local_storage_permission_failure_keeps_admin_reachable(admin, monkeypatch):
    directory = Mock()
    directory.mkdir.side_effect = PermissionError(errno.EACCES, 'read-only local directory')
    monkeypatch.setattr(main, 'ROOT', directory)
    with TestClient(app, base_url='http://localhost', cookies=dict(admin.cookies)) as client:
        assert client.get('/api/health').status_code == 200
        assert client.get('/api/admin/auth/oidc').status_code == 200
    directory.mkdir.assert_called_once()


def queued_document(alice):
    tid = alice.post('/api/tenants', json={'name': 'Outage regression'}).json()['id']
    result = alice.post(f'/api/tenants/{tid}/documents', files={'file': ('synthetic.txt', b'Original evidence for outage recovery', 'text/plain')})
    assert result.status_code == 200, result.text
    return tid, result.json()['id']


@pytest.mark.parametrize('error', [errno.ENETUNREACH, errno.ESTALE, errno.ETIMEDOUT])
def test_network_failure_returns_503_without_using_local_original(alice, tmp_path, monkeypatch, error):
    tid, did = queued_document(alice)
    nas_state(tmp_path, monkeypatch)
    def inaccessible(doc):
        raise OSError(error, 'private NAS path must not appear in response')
    monkeypatch.setattr(main, 'current_path', inaccessible)
    response = alice.get(f'/api/tenants/{tid}/documents/{did}/file')
    assert response.status_code == 503, response.text
    assert 'Kein lokaler Ersatzspeicher' in response.json()['detail']
    assert 'private NAS path' not in response.text
    assert response.headers['cache-control'] == 'no-store'
    assert alice.get('/api/me').status_code == 200


@pytest.mark.parametrize('error', [errno.ENETUNREACH, errno.ESTALE, errno.ETIMEDOUT])
def test_worker_leaves_queued_documents_unchanged_when_nas_offline(alice, tmp_path, monkeypatch, error):
    _, did = queued_document(alice)
    data = nas_state(tmp_path, monkeypatch)
    location = Mock()
    location.is_dir.side_effect = OSError(error, 'offline')
    monkeypatch.setattr(storage_control, 'root', lambda kind: location)
    from app.worker import tick
    with pytest.raises(HTTPException) as failure:
        tick()
    assert failure.value.status_code == 503
    with SessionLocal() as db:
        doc = db.get(Document, did)
        assert doc.status == 'queued'
        assert not doc.ocr_failed
        assert doc.text in {'', None}
        assert doc.processed_at is None
    assert json.loads((tmp_path/'active.json').read_text()) == data
    # Once the same NAS is reachable, normal processing can resume.
    location.is_dir.side_effect = None
    location.is_dir.return_value = True
    storage_control.require_worker_storage()


def test_stream_error_after_response_start_is_not_replaced(tmp_path, monkeypatch):
    nas_state(tmp_path, monkeypatch)
    messages = []
    async def failing_app(scope, receive, send):
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        raise OSError(errno.ENETUNREACH, 'connection lost while streaming')
    async def send(message):
        messages.append(message)
    async def receive():
        return {'type': 'http.request', 'body': b''}
    import asyncio
    with pytest.raises(OSError):
        asyncio.run(storage_control.StorageGateMiddleware(failing_app)({'type': 'http', 'path': '/api/file'}, receive, send))
    assert len(messages) == 1
