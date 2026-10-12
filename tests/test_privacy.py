import json
import time
from pathlib import Path
import pytest
import httpx
from sqlalchemy import select
from app import codex_client
from app.db import SessionLocal, Document, Integration, Membership, Setting, Audit
from app.security import encrypt, decrypt
from app.processing import process_document, ai_metadata
from app.privacy import minimise_text, preview_token
from app.storage import path_for

TEXT = 'Rechnung\nKontakt: anna@example.org\nDE89 3704 0044 0532 0130 00\n+49 (30) 12345678\nKundennummer: 987654321\nGesamtbetrag: 125,50 EUR\nfällig am 01.12.2026\nAnna Beispiel, Beispielstraße 1'
RESULT = {'supplier': 'Lieferant GmbH', 'doc_type': 'Rechnung', 'amount': '125.50', 'due_date': '2026-12-01'}


def setup(alice, admin, monkeypatch, provider='codex', **options):
    tid = alice.post('/api/tenants', json={'name': 'Datenschutz'}).json()['id']
    admin.put('/api/admin/codex/tenants', json={'tenant_ids': [tid]})
    monkeypatch.setattr(codex_client, 'status', lambda: {'connected': True})
    config = {'provider': provider, 'model': '', 'consent': True} | options
    if provider == 'openai':
        config |= {'api_key': 'private-key', 'model': 'test-model'}
    r = alice.put(f'/api/tenants/{tid}/integrations/ai', json={'enabled': True, 'config': config})
    assert r.status_code == 200, r.text
    doc_id = alice.post(f'/api/tenants/{tid}/documents', files={'file': ('privat.txt', TEXT.encode())}).json()['id']
    return tid, doc_id


def local_ocr(doc_id):
    with SessionLocal() as db:
        process_document(db, db.get(Document, doc_id))
        db.commit()


def test_masking_preserves_invoice_data_and_masks_before_clipping():
    result = minimise_text(TEXT)
    for secret in ['anna@example.org', '3704', '12345678', '987654321']:
        assert secret not in result['text']
    for value in ['125,50', '01.12.2026', 'Rechnung']:
        assert value in result['text']
    assert minimise_text(result['text'])['text'] == result['text']
    assert 'Anna Beispiel' in result['text']  # Never claim names are fully anonymised.
    boundary = minimise_text('x' * 995 + ' anna@example.org', 1000)
    assert boundary['truncated'] and boundary['text'].endswith('[EMA')
    assert 'anna' not in boundary['text']
    assert 'anna' not in minimise_text('a\u200bnna@example.org')['text']


@pytest.mark.parametrize('provider', ['codex', 'openai'])
def test_manual_is_default_and_scanning_never_contacts_ai(alice, admin, monkeypatch, provider):
    tid, doc_id = setup(alice, admin, monkeypatch, provider)
    def forbidden(*args, **kwargs):
        raise AssertionError('No external calls during local OCR')
    monkeypatch.setattr(codex_client, 'request', forbidden)
    monkeypatch.setattr(httpx.Client, 'post', forbidden)
    local_ocr(doc_id)
    with SessionLocal() as db:
        doc = db.get(Document, doc_id)
        assert doc.status == 'ready' and doc.text == TEXT
        assert doc.amount == '125.50' and str(doc.due_date) == '2026-12-01'
        config = decrypt(db.scalar(select(Integration).where(Integration.tenant_id == tid)).config_encrypted)
        assert config['privacy_mode'] == 'manual'
        original = path_for(tid, doc_id)
        assert original.read_text() == TEXT
        assert original.stat().st_mode & 0o777 == 0o600
        assert original.parent.stat().st_mode & 0o777 == 0o700


def test_exact_reviewed_text_requires_owner_and_signed_preview(alice, bob, admin, monkeypatch):
    tid, doc_id = setup(alice, admin, monkeypatch)
    local_ocr(doc_id)
    url = f'/api/tenants/{tid}/documents/{doc_id}'
    calls = []
    def extract(method, path, data, **kwargs):
        calls.append(data)
        return {'metadata': RESULT}
    monkeypatch.setattr(codex_client, 'request', extract)
    preview = alice.post(url + '/ai-preview', json={})
    assert preview.status_code == 200 and preview.headers['cache-control'] == 'no-store'
    p = preview.json()
    assert not calls and 'anna@example.org' not in p['text']
    assert bob.post(url + '/ai-preview', json={}).status_code == 403
    with SessionLocal() as db:
        db.add(Membership(tenant_id=tid, user_id=bob.get('/api/me').json()['id'], role='editor')); db.commit()
    assert bob.post(url + '/ai', json={'text': p['text'], 'token': p['token'], 'confirmed': True}).status_code == 403
    assert alice.post(url + '/ai', json={'text': p['text'], 'token': p['token'], 'confirmed': False}).status_code == 422
    assert alice.post(url + '/ai', json={'text': p['text'] + '\nChanged', 'token': p['token'], 'confirmed': True}).status_code == 409
    draft = p['text'].replace('Anna Beispiel, Beispielstraße 1', '[EMPFÄNGER ENTFERNT]')
    p = alice.post(url + '/ai-preview', json={'text': draft}).json()
    assert alice.post(url + '/ai', json={'text': p['text'], 'token': p['token'], 'confirmed': True}).status_code == 200
    assert calls == [{'text': p['text'], 'model': None}]
    assert 'Anna Beispiel' not in calls[0]['text']
    assert alice.get(url + '/file').content == TEXT.encode()
    assert alice.get(url).json()['text'] == TEXT
    # Consuming the preview changes the document revision; replay is rejected.
    assert alice.post(url + '/ai', json={'text': p['text'], 'token': p['token'], 'confirmed': True}).status_code == 409
    with SessionLocal() as db:
        audits = db.scalars(select(Audit).where(Audit.tenant_id == tid)).all()
        assert any(a.action == 'document.ai_approved' and a.actor_id for a in audits)
        assert all('anna@example.org' not in a.detail and 'Anna Beispiel' not in a.detail for a in audits)


@pytest.mark.parametrize('change', ['text', 'config', 'disabled', 'trash', 'revoked', 'expired', 'blocked'])
def test_stale_or_revoked_review_never_transmits(alice, admin, monkeypatch, change):
    tid, doc_id = setup(alice, admin, monkeypatch)
    local_ocr(doc_id)
    url = f'/api/tenants/{tid}/documents/{doc_id}'
    p = alice.post(url + '/ai-preview', json={}).json()
    with SessionLocal() as db:
        doc = db.get(Document, doc_id)
        integration = db.scalar(select(Integration).where(Integration.tenant_id == tid))
        if change == 'text': doc.text += '\nNew OCR'
        if change == 'config': integration.config_encrypted = encrypt(decrypt(integration.config_encrypted) | {'text_limit': 1000})
        if change == 'disabled': integration.enabled = False
        if change == 'trash': doc.deleted_at = __import__('datetime').datetime.now()
        if change == 'expired':
            monkeypatch.setattr(time, 'time', lambda: 1000)
            p['token'] = preview_token(doc, integration, p['text'])
            monkeypatch.setattr(time, 'time', lambda: 2000)
        if change == 'blocked': db.merge(Setting(key='ai_external_blocked', value='true'))
        db.commit()
    if change == 'revoked': admin.put('/api/admin/codex/tenants', json={'tenant_ids': []})
    calls = []
    monkeypatch.setattr(codex_client, 'request', lambda *args, **kwargs: calls.append(args))
    assert alice.post(url + '/ai', json={'text': p['text'], 'token': p['token'], 'confirmed': True}).status_code in {403, 409}
    assert not calls


def test_automatic_requires_separate_consent_and_masks_payload(alice, admin, monkeypatch):
    tid, doc_id = setup(alice, admin, monkeypatch, privacy_mode='automatic', automatic_consent=True, text_limit=1000)
    calls = []
    monkeypatch.setattr(codex_client, 'request', lambda method, path, data, **kwargs: calls.append(data) or {'metadata': RESULT})
    local_ocr(doc_id)
    assert len(calls) == 1 and len(calls[0]['text']) <= 1000
    assert calls[0]['text'] == minimise_text(TEXT, 1000)['text']
    cfg = {'provider': 'codex', 'model': '', 'consent': True, 'privacy_mode': 'automatic'}
    assert alice.put(f'/api/tenants/{tid}/integrations/ai', json={'enabled': True, 'config': cfg}).status_code == 422
    for bad in [0, 10001, True, '1000']:
        assert alice.put(f'/api/tenants/{tid}/integrations/ai', json={'enabled': True, 'config': cfg | {'automatic_consent': True, 'text_limit': bad}}).status_code == 422
    with SessionLocal() as db:
        db.merge(Setting(key='ai_external_blocked', value='true')); db.commit()
    local_ocr(doc_id)
    assert len(calls) == 1


def test_failed_review_keeps_local_archive_and_safe_error(alice, admin, monkeypatch):
    tid, doc_id = setup(alice, admin, monkeypatch)
    local_ocr(doc_id)
    url = f'/api/tenants/{tid}/documents/{doc_id}'
    p = alice.post(url + '/ai-preview', json={}).json()
    monkeypatch.setattr(codex_client, 'request', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError(TEXT)))
    r = alice.post(url + '/ai', json={'text': p['text'], 'token': p['token'], 'confirmed': True})
    assert r.status_code == 503 and 'anna@example.org' not in r.text
    doc = alice.get(url).json()
    assert doc['status'] == 'ready' and doc['text'] == TEXT
    assert alice.get(url + '/file').content == TEXT.encode()


def test_legacy_ai_configuration_does_not_implicitly_auto_send(alice, admin, monkeypatch):
    tid, doc_id = setup(alice, admin, monkeypatch)
    with SessionLocal() as db:
        integration = db.scalar(select(Integration).where(Integration.tenant_id == tid))
        integration.config_encrypted = encrypt({'provider': 'codex', 'model': '', 'consent': True})
        db.commit()
    monkeypatch.setattr(codex_client, 'request', lambda *a, **kw: pytest.fail('Legacy consent is not automatic consent'))
    local_ocr(doc_id)


def test_server_block_survives_updates_from_older_clients(alice, admin):
    assert alice.put('/api/admin/settings', json={'app_name': 'Archiv', 'ai_external_blocked': True}).status_code == 403
    assert admin.put('/api/admin/settings', json={'app_name': 'Archiv', 'ai_external_blocked': True}).status_code == 200
    assert admin.put('/api/admin/settings', json={'app_name': 'Neuer Name'}).status_code == 200
    assert admin.get('/api/admin').json()['settings']['ai_external_blocked'] is True
