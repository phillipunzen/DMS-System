import asyncio
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from app import codex_client
from app.db import SessionLocal, Document, Integration, Setting
from app.processing import process_document
from app.security import encrypt
from dms_contracts.metadata import validate_metadata
from codex_service.runtime import CodexRuntime, CodexError, DISABLED_FEATURES
from codex_service import server
from codex_service.usage import normalize_usage

RESULT = {'supplier': 'Scanner GmbH', 'doc_type': 'Rechnung', 'amount': '123.45', 'due_date': '2026-12-01'}


def tenant(client):
    r = client.post('/api/tenants', json={'name': 'Codex-Test'})
    assert r.status_code == 200, r.text
    return r.json()['id']


def config(client, tid, enabled=True, consent=True):
    return client.put(f'/api/tenants/{tid}/integrations/ai', json={'enabled': enabled, 'config': {'provider': 'codex', 'model': '', 'consent': consent, 'privacy_mode': 'automatic', 'automatic_consent': True}})


def test_codex_admin_controls_and_tenant_scope(alice, bob, admin, monkeypatch):
    a = tenant(alice); b = tenant(bob)
    quota = {'status': 'ready', 'buckets': [{'id': 'codex', 'primary': {'used_percent': 25}}]}
    monkeypatch.setattr(codex_client, 'status', lambda: {'available': True, 'connected': True, 'email': 'private@example.com', 'plan': 'pro', 'usage': quota})
    monkeypatch.setattr(codex_client, 'request', lambda *args, **kwargs: {'models': [{'id': 'account-model', 'name': 'Account model', 'default': True}]})
    for suffix in ['', '/login', '/logout', '/tenants']:
        method = 'GET' if not suffix else 'PUT' if suffix == '/tenants' else 'POST'
        kwargs = {'json': {'tenant_ids': [a]}} if suffix == '/tenants' else {}
        assert alice.request(method, '/api/admin/codex' + suffix, **kwargs).status_code == 403
    assert config(alice, a).status_code == 403
    assert admin.put('/api/admin/codex/tenants', json={'tenant_ids': [a]}).status_code == 200
    assert config(alice, a).status_code == 200
    assert config(bob, b).status_code == 403
    public = alice.get(f'/api/tenants/{a}/codex').json()
    assert public['connected'] and public['models'][0]['id'] == 'account-model'
    assert 'email' not in public and 'plan' not in public and 'usage' not in public
    assert bob.get(f'/api/tenants/{a}/codex').status_code == 403
    assert admin.get('/api/admin/codex').json()['email'] == 'private@example.com'
    assert admin.get('/api/admin/codex').json()['usage'] == quota
    assert admin.put('/api/admin/codex/tenants', json={'tenant_ids': ['nonexistent']}).status_code == 404
    assert alice.get(f'/api/tenants/{a}/codex').json()['allowed']
    assert admin.put('/api/admin/codex/tenants', json={'tenant_ids': []}).status_code == 200
    assert alice.get(f'/api/tenants/{a}/codex').json()['allowed'] is False


def test_codex_opt_in_login_requirement_and_no_custom_commands(alice, admin, monkeypatch):
    tid = tenant(alice)
    assert admin.put('/api/admin/codex/tenants', json={'tenant_ids': [tid]}).status_code == 200
    monkeypatch.setattr(codex_client, 'status', lambda: {'available': True, 'connected': False})
    assert config(alice, tid).status_code == 200
    assert config(alice, tid, enabled=False).status_code == 200
    assert config(alice, tid, consent=False).status_code == 422
    for extra in [{'command': 'cat /data/documents'}, {'api_key': 'key'}, {'model': '--dangerously-bypass-approvals-and-sandbox'}, {'model': {'id': 'x'}}]:
        cfg = {'provider': 'codex', 'consent': True, 'model': ''} | extra
        assert alice.put(f'/api/tenants/{tid}/integrations/ai', json={'enabled': False, 'config': cfg}).status_code == 422


def test_codex_processing_only_sends_current_document_text_and_preserves_original(alice, admin, monkeypatch):
    tid = tenant(alice)
    admin.put('/api/admin/codex/tenants', json={'tenant_ids': [tid]})
    monkeypatch.setattr(codex_client, 'status', lambda: {'connected': True})
    assert config(alice, tid).status_code == 200
    uploaded = alice.post(f'/api/tenants/{tid}/documents', files={'file': ('rechnung.txt', b'Rechnung\nCodex metadata extraction')}).json()
    calls = []
    def extract(method, path, data, **kwargs):
        calls.append(data)
        assert method == 'POST' and path == 'extract'
        assert set(data) == {'text', 'model'}
        assert 'Codex metadata extraction' in data['text']
        return {'metadata': RESULT.copy()}
    monkeypatch.setattr(codex_client, 'request', extract)
    with SessionLocal() as db:
        doc = db.get(Document, uploaded['id'])
        process_document(db, doc); db.commit()
        assert doc.supplier == 'Scanner GmbH' and doc.status == 'ready'
    assert len(calls) == 1
    assert alice.get(f'/api/tenants/{tid}/documents/{uploaded["id"]}/file').content == b'Rechnung\nCodex metadata extraction'
    admin.put('/api/admin/codex/tenants', json={'tenant_ids': []})
    with SessionLocal() as db:
        process_document(db, db.get(Document, uploaded['id']))
        assert db.get(Document, uploaded['id']).ai_pending
    assert len(calls) == 1


def test_codex_failure_keeps_ocr_text(alice, admin, monkeypatch):
    tid = tenant(alice)
    admin.put('/api/admin/codex/tenants', json={'tenant_ids': [tid]})
    monkeypatch.setattr(codex_client, 'status', lambda: {'connected': True})
    assert config(alice, tid).status_code == 200
    doc_id = alice.post(f'/api/tenants/{tid}/documents', files={'file': ('ocr.txt', b'OCR text stays readable')}).json()['id']
    monkeypatch.setattr(codex_client, 'request', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('expired auth')))
    with SessionLocal() as db:
        process_document(db, db.get(Document, doc_id))
        db.commit()
        assert db.get(Document, doc_id).ai_pending and db.get(Document, doc_id).status == 'ready'
        assert db.get(Document, doc_id).text == 'OCR text stays readable'


def test_codex_gateway_rejects_unauthenticated_and_oversized_requests(monkeypatch):
    monkeypatch.setenv('CODEX_SERVICE_TOKEN', 'private-service-token-' * 3)
    client = TestClient(server.app)
    for endpoint in ['/v1/status', '/v1/models', '/v1/extract', '/v1/login', '/v1/logout']:
        assert client.post(endpoint, json={}).status_code == 403
    client.headers['X-Codex-Token'] = 'private-service-token-' * 3
    assert client.post('/v1/extract', json={'text': 'x' * 30001}).status_code == 422
    assert client.post('/v1/extract', json={'text': 'x'}, headers={'Content-Length': '33554433'}).status_code == 413
    async def extract(text, model):
        return RESULT
    monkeypatch.setattr(server.runtime, 'extract', extract)
    r = client.post('/v1/extract', json={'text': 'A valid document'})
    assert r.json() == {'metadata': RESULT} and r.headers['cache-control'] == 'no-store'


def test_codex_ephemeral_jobs_never_resume_or_enable_tools(monkeypatch):
    runtime = CodexRuntime()
    requests = []
    starts = []
    async def status():
        return {'connected': True}
    async def request(method, params=None, **kwargs):
        requests.append((method, params))
        if method == 'thread/start':
            thread_id = 'thread-' + str(len(starts))
            starts.append(params)
            return {'thread': {'id': thread_id}}
        if method == 'turn/start':
            queue = runtime.events[params['threadId']]
            queue.put_nowait({'method': 'item/completed', 'params': {'turnId': 'turn', 'item': {'type': 'agentMessage', 'phase': 'final_answer', 'text': json.dumps(RESULT)}}})
            queue.put_nowait({'method': 'turn/completed', 'params': {'turn': {'id': 'turn', 'status': 'completed'}}})
            return {'turn': {'id': 'turn'}}
        return {}
    monkeypatch.setattr(runtime, 'status', status)
    monkeypatch.setattr(runtime, 'request', request)
    async def run():
        assert await runtime.extract('Tenant A secret document') == RESULT
        assert await runtime.extract('Tenant B different document') == RESULT
    asyncio.run(run())
    assert starts[0]['cwd'] != starts[1]['cwd']
    assert all(p['ephemeral'] and p['sandbox'] == 'read-only' and p['approvalPolicy'] == 'never' for p in starts)
    assert not any(method == 'thread/resume' for method, _ in requests)
    assert all(not Path(p['cwd']).exists() for p in starts)
    turns = [p for m, p in requests if m == 'turn/start']
    assert turns[0]['input'][0]['text'] != turns[1]['input'][0]['text']
    assert all(p['sandboxPolicy'] == {'type': 'readOnly', 'networkAccess': False} for p in turns)
    assert {'apps', 'plugins', 'shell_tool', 'unified_exec', 'browser_use', 'multi_agent'}.issubset(DISABLED_FEATURES)
    assert not runtime.events


def test_codex_login_only_returns_official_device_url_and_no_tokens(monkeypatch):
    runtime = CodexRuntime()
    calls = []
    async def request(method, params=None, **kwargs):
        calls.append((method, params))
        if method == 'account/login/start':
            return {'loginId': 'login', 'verificationUrl': 'https://auth.openai.com/codex/device', 'userCode': 'ABCD-1234'}
        return {}
    monkeypatch.setattr(runtime, 'request', request)
    result = asyncio.run(runtime.start_login())
    assert result['user_code'] == 'ABCD-1234' and not any('token' in k.lower() for k in result)
    assert calls == [('account/login/start', {'type': 'chatgptDeviceCode'})]
    asyncio.run(runtime.cancel_login())
    assert runtime.login is None
    async def malicious(*args, **kwargs):
        return {'loginId': 'login', 'verificationUrl': 'https://malicious.test', 'userCode': 'X'}
    monkeypatch.setattr(runtime, 'request', malicious)
    with pytest.raises(CodexError):
        asyncio.run(runtime.start_login())


def test_codex_metadata_is_validated_before_use():
    assert validate_metadata(RESULT.copy()) == RESULT
    for bad in [[], {}, RESULT | {'amount': ['123']}, RESULT | {'doc_type': 'Dangerous'}, RESULT | {'due_date': 'not-a-date'}]:
        with pytest.raises(ValueError):
            validate_metadata(bad)


def test_codex_quota_multiple_buckets_and_unknown_values():
    normalized = normalize_usage({'ordinaryUsageAllowed': False, 'accountId': 'never-exposed',
        'rateLimits': {'primary': {'usedPercent': 99}},
        'rateLimitsByLimitId': {'codex': {'limitName': 'Codex',
            'primary': {'usedPercent': 0, 'windowDurationMins': 300, 'resetsAt': 1900000000},
            'secondary': {'usedPercent': 100, 'windowDurationMins': 10080},
            'credits': {'hasCredits': True, 'unlimited': False, 'balance': '12.50', 'token': 'never-exposed'}},
            'other': {'primary': {'usedPercent': None}, 'secondary': None}}})
    a, b = normalized['buckets']
    assert a['primary'] == {'used_percent': 0, 'remaining_percent': 100, 'duration_minutes': 300, 'resets_at': 1900000000}
    assert a['secondary']['remaining_percent'] == 0 and a['secondary']['resets_at'] is None
    assert a['credits'] == {'balance': '12.50', 'has_credits': True, 'unlimited': False}
    assert b['primary']['remaining_percent'] is None and b['secondary'] is None
    assert normalized['ordinary_usage_allowed'] is False
    assert 'never-exposed' not in json.dumps(normalized)
    for invalid in [None, True, '25', float('nan'), float('inf'), -1, 101]:
        assert normalize_usage({'rateLimits': {'primary': {'usedPercent': invalid}}})['buckets'][0]['primary']['remaining_percent'] is None
    assert normalize_usage({})['buckets'] == []


def test_codex_quota_cache_refresh_and_account_change(monkeypatch):
    runtime = CodexRuntime()
    account = {'type': 'chatgpt', 'email': 'first@example.com', 'planType': 'plus'}
    reads = []
    async def request(method, params=None, **kwargs):
        if method == 'account/read':
            return {'account': account.copy()}
        reads.append(method)
        assert method == 'account/rateLimits/read'
        return {'rateLimits': {'primary': {'usedPercent': len(reads) * 10}}}
    monkeypatch.setattr(runtime, 'request', request)
    async def run():
        assert 'usage' not in await runtime.status()  # Document jobs do not wait on quota reads.
        first = await runtime.status(include_usage=True)
        second = await runtime.status(include_usage=True)
        assert first['usage'] == second['usage'] and len(reads) == 1
        runtime.usage_deadline = 0
        assert (await runtime.status(include_usage=True))['usage']['buckets'][0]['primary']['used_percent'] == 20
        account['email'] = 'second@example.com'
        assert (await runtime.status(include_usage=True))['usage']['buckets'][0]['primary']['used_percent'] == 30
        account.clear()
        assert (await runtime.status(include_usage=True))['usage']['status'] == 'disconnected'
        assert runtime.usage_cache is None
    asyncio.run(run())


@pytest.mark.parametrize('failure', [CodexError('provider detail'), TimeoutError()])
def test_codex_quota_failure_preserves_connection_and_never_shows_old_values(monkeypatch, failure):
    runtime = CodexRuntime()
    fail = False
    async def request(method, params=None, **kwargs):
        if method == 'account/read':
            return {'account': {'type': 'chatgpt', 'email': 'a@example.com'}}
        if fail:
            raise failure
        return {'rateLimits': {'primary': {'usedPercent': 12}}}
    monkeypatch.setattr(runtime, 'request', request)
    async def run():
        nonlocal fail
        assert (await runtime.status(include_usage=True))['usage']['status'] == 'ready'
        runtime.usage_deadline = 0
        fail = True
        status = await runtime.status(include_usage=True)
        assert status['available'] and status['connected']
        assert status['usage']['status'] == 'unavailable' and status['usage']['buckets'] == []
        assert 'provider detail' not in json.dumps(status)
        await runtime.logout()
    # Logout itself succeeds; only quota reads fail.
    original = request
    async def with_logout(method, *args, **kwargs):
        return {} if method == 'account/logout' else await original(method, *args, **kwargs)
    monkeypatch.setattr(runtime, 'request', with_logout)
    asyncio.run(run())
    assert runtime.usage_cache is None
