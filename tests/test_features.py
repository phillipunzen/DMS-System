import base64
import io
import json
import time
from datetime import timedelta
from pathlib import Path
import pytest
from PIL import Image
from sqlalchemy import select, func
from fastapi.testclient import TestClient
from app.main import app
from app.db import SessionLocal, Document, DocumentVersion, Membership, UserMFA, MFAChallenge, Tenant, Integration, Review, Setting, now
from app.storage import version_path
from app.processing import process_document
from app.security import decrypt, login
from app.mfa import totp
from app import codex_client
from app.tenant_backup import encrypt_file, decrypt_file

PASSWORD = 'a-secure-test-password'
BACKUP_PASSWORD = 'a-different-backup-password'


def tenant(client):
    return client.post('/api/tenants', json={'name': 'Funktionsprüfung'}).json()['id']


def upload(client, tid, text=b'Rechnung\nGesamtbetrag: 125,50 EUR\nOriginalfassung', name='rechnung.txt'):
    response = client.post(f'/api/tenants/{tid}/documents', files={'file': (name, text)})
    assert response.status_code == 200, response.text
    doc_id = response.json()['id']
    with SessionLocal() as db:
        process_document(db, db.get(Document, doc_id)); db.commit()
    return doc_id


def add_member(client, tid, role='editor'):
    user_id = client.get('/api/me').json()['id']
    with SessionLocal() as db:
        db.add(Membership(tenant_id=tid, user_id=user_id, role=role)); db.commit()
    return user_id


def update(client, tid, doc_id, **values):
    doc = client.get(f'/api/tenants/{tid}/documents/{doc_id}').json()
    body = {k: doc.get(k) for k in ['title', 'folder_id', 'supplier', 'doc_type', 'tags', 'amount', 'due_date', 'paid']}
    return client.put(f'/api/tenants/{tid}/documents/{doc_id}', json=body | values)


def process(doc_id):
    with SessionLocal() as db:
        process_document(db, db.get(Document, doc_id)); db.commit()


def test_versions_are_immutable_restorable_and_count_against_quota(alice, bob):
    tid = tenant(alice); doc_id = upload(alice, tid)
    url = f'/api/tenants/{tid}/documents/{doc_id}'
    original = alice.get(url + '/file').content
    changed = b'Rechnung\nGesamtbetrag: 250,00 EUR\nKorrigierte Fassung'
    r = alice.post(url + '/versions', files={'file': ('neu.txt', changed)}, data={'note': 'Korrektur'})
    assert r.status_code == 200 and r.json()['current_version'] == 2, r.text
    process(doc_id)
    assert alice.get(url + '/file').content == changed
    assert alice.get(url + '/versions/1/file').content == original
    assert alice.get(url + '/versions/2/file').content == changed
    assert alice.get(f'/api/tenants/{tid}/stats').json()['bytes'] == len(original) + len(changed)
    assert bob.get(url + '/versions').status_code == 403
    assert alice.post(url + '/versions/1/restore').status_code == 200
    process(doc_id)
    versions = alice.get(url + '/versions').json()
    assert versions['current'] == 3 and len(versions['items']) == 3
    assert alice.get(url + '/file').content == original
    assert alice.get(url + '/versions/2/file').content == changed
    assert alice.post(url + '/versions', files={'file': ('gleich.txt', original)}).status_code == 409


def test_historical_version_quota_and_failed_upload_do_not_damage_original(alice, admin):
    tid = tenant(alice)
    admin.put(f'/api/admin/tenants/{tid}/quota', json={'quota_mb': 1})
    data = b'First version\n' + b'A' * 700000
    doc_id = upload(alice, tid, data)
    url = f'/api/tenants/{tid}/documents/{doc_id}'
    assert alice.post(url + '/versions', files={'file': ('second.txt', b'Other version\n' + b'B' * 700000)}).status_code == 413
    assert alice.get(url + '/file').content == data
    assert alice.get(url + '/versions').json()['current'] == 1
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(DocumentVersion).where(DocumentVersion.document_id == doc_id)) == 1
    assert not version_path(tid, doc_id, 2).exists()


def test_document_and_folder_permissions_intersect_everywhere(alice, bob):
    tid = tenant(alice); uid = add_member(bob, tid); doc_id = upload(alice, tid)
    doc_url = f'/api/tenants/{tid}/documents/{doc_id}'
    folder_id = alice.get(doc_url).json()['folder_id']
    folder_url = f'/api/tenants/{tid}/folders/{folder_id}'
    assert alice.put(folder_url + '/access', json={'restricted': True, 'grants': []}).status_code == 200
    for suffix in ['', '/file', '/versions', '/versions/1/file']:
        assert bob.get(doc_url + suffix).status_code == 404
    assert not bob.get(f'/api/tenants/{tid}/documents?q=Originalfassung').json()['items']
    assert bob.get(f'/api/tenants/{tid}/stats').json()['documents'] == 0
    assert folder_id not in [f['id'] for f in bob.get(f'/api/tenants/{tid}/folders').json()]
    assert alice.put(folder_url + '/access', json={'restricted': True, 'grants': [{'user_id': uid, 'can_edit': False}]}).status_code == 200
    assert bob.get(doc_url + '/file').status_code == 200
    assert bob.put(doc_url, json={'title': 'Nicht erlaubt'}).status_code == 404
    assert bob.post(doc_url + '/versions', files={'file': ('hack.txt', b'A different text')}).status_code == 404
    assert bob.post(doc_url + '/reprocess').status_code == 404
    assert bob.delete(doc_url).status_code == 404
    # A document-level allow does not override a folder-level deny.
    alice.put(doc_url + '/access', json={'restricted': True, 'grants': [{'user_id': uid, 'can_edit': True}]})
    alice.put(folder_url + '/access', json={'restricted': True, 'grants': []})
    assert bob.get(doc_url).status_code == 404
    # Both restrictions must be satisfied, with tenant roles as the upper bound.
    alice.put(folder_url + '/access', json={'restricted': True, 'grants': [{'user_id': uid, 'can_edit': True}]})
    assert bob.get(doc_url).json()['can_edit']
    assert update(bob, tid, doc_id, title='Erlaubte Änderung').status_code == 200
    alice.put(f'/api/tenants/{tid}/members/{uid}', json={'role': 'viewer'})
    assert bob.get(doc_url + '/file').status_code == 200
    assert bob.put(doc_url, json={'title': 'Trotz Leserechten'}).status_code == 403
    assert alice.get(doc_url + '/file').status_code == 200
    assert alice.delete(folder_url).status_code == 409


def test_acl_only_accepts_tenant_members_and_removal_revokes_grants(alice, bob, admin):
    tid = tenant(alice); doc_id = upload(alice, tid)
    url = f'/api/tenants/{tid}/documents/{doc_id}/access'
    foreign = admin.get('/api/me').json()['id']
    assert alice.put(url, json={'restricted': True, 'grants': [{'user_id': foreign}]}).status_code == 422
    uid = add_member(bob, tid)
    assert bob.put(url, json={'restricted': True}).status_code == 403
    alice.put(url, json={'restricted': True, 'grants': [{'user_id': uid}]})
    assert alice.delete(f'/api/tenants/{tid}/members/{uid}').status_code == 200
    add_member(bob, tid)
    assert bob.get(f'/api/tenants/{tid}/documents/{doc_id}').status_code == 404


def test_workflow_is_optional_four_eyes_and_invalidated_by_changes(alice, bob):
    tid = tenant(alice); uid = add_member(bob, tid); doc_id = upload(alice, tid)
    url = f'/api/tenants/{tid}/documents/{doc_id}'
    assert alice.post(url + '/reviews', json={'reviewer_id': uid}).status_code == 409
    assert bob.put(f'/api/tenants/{tid}/workflow', json={'enabled': True}).status_code == 403
    alice.put(f'/api/tenants/{tid}/workflow', json={'enabled': True})
    assert alice.post(url + '/reviews', json={'reviewer_id': alice.get('/api/me').json()['id']}).status_code == 422
    assert bob.get(url + '/reviewers').json() == []  # Uploader cannot review their own version.
    requested = alice.post(url + '/reviews', json={'reviewer_id': uid, 'note': 'Bitte Betrag prüfen'}).json()
    review_url = f'/api/tenants/{tid}/reviews/{requested["id"]}/decision'
    assert alice.post(review_url, json={'decision': 'approved'}).status_code == 403
    assert alice.post(url + '/reviews', json={'reviewer_id': uid}).status_code == 409
    assert bob.post(review_url, json={'decision': 'approved', 'note': 'Geprüft'}).status_code == 200
    assert alice.get(url).json()['review_status'] == 'approved'
    update(alice, tid, doc_id, amount='150.00')
    assert alice.get(url).json()['review_status'] == 'unassigned'
    requested = alice.post(url + '/reviews', json={'reviewer_id': uid}).json()
    assert alice.post(url + '/versions', files={'file': ('new.txt', b'Rechnung\nNew version that needs approval')}).status_code == 200
    assert bob.post(f'/api/tenants/{tid}/reviews/{requested["id"]}/decision', json={'decision': 'approved'}).status_code == 409
    process(doc_id)
    assert not bob.get(f'/api/tenants/{tid}/reviews').json()
    assert alice.get(url).json()['review_status'] == 'unassigned'


def test_review_queue_respects_new_permissions_and_disabled_workflows(alice, bob):
    tid = tenant(alice); uid = add_member(bob, tid); doc_id = upload(alice, tid)
    alice.put(f'/api/tenants/{tid}/workflow', json={'enabled': True})
    url = f'/api/tenants/{tid}/documents/{doc_id}'
    review = alice.post(url + '/reviews', json={'reviewer_id': uid}).json()
    alice.put(url + '/access', json={'restricted': True, 'grants': []})
    assert bob.get(f'/api/tenants/{tid}/reviews').json() == []
    assert bob.post(f'/api/tenants/{tid}/reviews/{review["id"]}/decision', json={'decision': 'approved'}).status_code == 404
    alice.put(url + '/access', json={'restricted': False})
    alice.put(f'/api/tenants/{tid}/workflow', json={'enabled': False})
    assert bob.post(f'/api/tenants/{tid}/reviews/{review["id"]}/decision', json={'decision': 'approved'}).status_code == 409


def photo(colour, exif=False):
    output = io.BytesIO()
    image = Image.new('RGB', (600, 800), colour)
    metadata = Image.Exif(); metadata[270] = 'Private camera metadata'; metadata[274] = 6
    image.save(output, format='JPEG', exif=metadata if exif else b'')
    return output.getvalue()


def test_camera_import_creates_multi_page_pdf_without_exif(alice, bob):
    tid = tenant(alice)
    photos = [('files', ('1.jpg', photo('white', True), 'image/jpeg')), ('files', ('2.jpg', photo('red'), 'image/jpeg'))]
    response = alice.post(f'/api/tenants/{tid}/camera-scans', files=photos, data={'title': 'Mobiler Scan'})
    assert response.status_code == 200, response.text
    doc = response.json()
    content = alice.get(f'/api/tenants/{tid}/documents/{doc["id"]}/file').content
    assert content.startswith(b'%PDF') and b'Private camera metadata' not in content
    assert doc['source'] == 'camera'
    import subprocess
    info = subprocess.check_output(['pdfinfo', '-'], input=content).decode()
    assert 'Pages:           2' in info
    assert bob.post(f'/api/tenants/{tid}/camera-scans', files=photos).status_code == 403
    assert alice.post(f'/api/tenants/{tid}/camera-scans', files={'files': ('invalid.jpg', b'not an image')}).status_code == 422


def test_encrypted_backup_roundtrip_all_versions_and_isolated_restore(alice, bob):
    tid = tenant(alice); uid = add_member(bob, tid); doc_id = upload(alice, tid)
    url = f'/api/tenants/{tid}/documents/{doc_id}'
    original = alice.get(url + '/file').content
    new = b'Rechnung\nGesamtbetrag: 300,00 EUR\nNeue Fassung'
    alice.post(url + '/versions', files={'file': ('v2.txt', new)}); process(doc_id)
    alice.put(url + '/access', json={'restricted': True, 'grants': [{'user_id': uid}]})
    assert bob.post(f'/api/tenants/{tid}/backup', json={'password': BACKUP_PASSWORD}).status_code == 403
    exported = alice.post(f'/api/tenants/{tid}/backup', json={'password': BACKUP_PASSWORD})
    assert exported.status_code == 200 and exported.headers['cache-control'] == 'no-store'
    data = exported.content
    assert b'Originalfassung' not in data and new not in data and b'Funktionspr' not in data
    restored = alice.post('/api/tenants/restore-backup', files={'file': ('archive.dmsbackup', data)}, data={'password': BACKUP_PASSWORD, 'name': 'Wiederhergestellt'})
    assert restored.status_code == 200, restored.text
    new_tid = restored.json()['id']; assert new_tid != tid
    docs = alice.get(f'/api/tenants/{new_tid}/documents').json()['items']
    assert len(docs) == 1 and docs[0]['id'] != doc_id and docs[0]['current_version'] == 2
    new_url = f'/api/tenants/{new_tid}/documents/{docs[0]["id"]}'
    assert alice.get(new_url + '/file').content == new
    assert alice.get(new_url + '/versions/1/file').content == original
    assert len(alice.get(f'/api/tenants/{new_tid}/members').json()) == 1
    assert bob.get(f'/api/tenants/{new_tid}/documents').status_code == 403
    assert 'bob@example.com' in json.dumps(alice.get(f'/api/tenants/{new_tid}/restore-history').json())
    assert not [c for c in alice.get(f'/api/tenants/{new_tid}/integrations').json() if c['enabled']]
    assert alice.get(url + '/file').content == new


@pytest.mark.parametrize('failure', ['password', 'tamper', 'format'])
def test_failed_restore_is_atomic(alice, failure):
    tid = tenant(alice); upload(alice, tid)
    data = alice.post(f'/api/tenants/{tid}/backup', json={'password': BACKUP_PASSWORD}).content
    password = BACKUP_PASSWORD
    if failure == 'password': password = 'an-incorrect-password'
    if failure == 'tamper': data = data[:-1] + bytes([data[-1] ^ 1])
    if failure == 'format': data = b'not a DMS backup'
    result = alice.post('/api/tenants/restore-backup', files={'file': ('archive.dmsbackup', data)}, data={'password': password, 'name': 'Failed restore'})
    assert result.status_code == 422
    assert len(alice.get('/api/me').json()['tenants']) == 1


def test_totp_rfc6238_vectors():
    seed = base64.b32encode(b'12345678901234567890').decode()
    for timestamp, expected in [(59, '94287082'), (1111111109, '07081804'), (1111111111, '14050471'), (1234567890, '89005924'), (2000000000, '69279037'), (20000000000, '65353130')]:
        assert totp(seed, timestamp // 30, digits=8) == expected


def csrf(client):
    client.headers['X-CSRF-Token'] = client.cookies['dms_csrf']


def test_mfa_activation_challenge_replay_recovery_and_revoked_sessions(alice, monkeypatch):
    timestamp = 2000000010
    monkeypatch.setattr('app.mfa.current_counter', lambda: timestamp // 30)
    setup = alice.post('/api/me/mfa/setup', json={'password': PASSWORD})
    assert setup.status_code == 200 and setup.json()['qr'].startswith('data:image/png;base64,')
    seed = setup.json()['secret']
    user_id = alice.get('/api/me').json()['id']
    assert not alice.get('/api/me/mfa').json()['enabled']
    enabled = alice.post('/api/me/mfa/enable', json={'code': totp(seed, timestamp // 30)})
    assert enabled.status_code == 200 and len(enabled.json()['recovery_codes']) == 10
    csrf(alice)
    codes = enabled.json()['recovery_codes']
    with SessionLocal() as db:
        stored = db.get(UserMFA, user_id)
        assert seed not in stored.secret_encrypted and codes[0].replace('-', '') not in stored.recovery_hashes
    alice.post('/api/auth/logout'); alice.cookies.clear()
    response = alice.post('/api/auth/login', json={'email': 'alice@example.com', 'password': PASSWORD})
    assert response.json()['mfa_required'] and 'dms_session' not in alice.cookies
    csrf(alice)
    assert alice.get('/api/me').status_code == 401
    # The setup code was consumed; it cannot be reused for login.
    assert alice.post('/api/auth/mfa/verify', json={'code': totp(seed, timestamp // 30)}).status_code == 401
    assert alice.post('/api/auth/mfa/verify', json={'code': codes[0]}).status_code == 200
    csrf(alice)
    assert alice.get('/api/me').status_code == 200
    assert alice.get('/api/me/mfa').json()['recovery_remaining'] == 9
    alice.post('/api/auth/logout'); alice.cookies.clear()
    alice.post('/api/auth/login', json={'email': 'alice@example.com', 'password': PASSWORD}); csrf(alice)
    assert alice.post('/api/auth/mfa/verify', json={'code': codes[0]}).status_code == 401
    timestamp += 30
    assert alice.post('/api/auth/mfa/verify', json={'code': totp(seed, timestamp // 30)}).status_code == 200
    csrf(alice)
    assert alice.post('/api/me/mfa/disable', json={'password': 'wrong', 'code': codes[1]}).status_code == 400
    assert alice.post('/api/me/mfa/disable', json={'password': PASSWORD, 'code': codes[1]}).status_code == 200
    csrf(alice)
    assert not alice.get('/api/me/mfa').json()['enabled']


def test_mfa_challenge_has_five_attempt_limit_and_setup_is_password_protected(alice, monkeypatch):
    assert alice.post('/api/me/mfa/setup', json={'password': 'wrong'}).status_code == 400
    timestamp = 2000000010; monkeypatch.setattr('app.mfa.current_counter', lambda: timestamp // 30)
    seed = alice.post('/api/me/mfa/setup', json={'password': PASSWORD}).json()['secret']
    codes = alice.post('/api/me/mfa/enable', json={'code': totp(seed, timestamp // 30)}).json()['recovery_codes']
    csrf(alice); alice.post('/api/auth/logout'); alice.cookies.clear()
    alice.post('/api/auth/login', json={'email': 'alice@example.com', 'password': PASSWORD}); csrf(alice)
    for _ in range(5): assert alice.post('/api/auth/mfa/verify', json={'code': 'invalid'}).status_code == 401
    assert alice.post('/api/auth/mfa/verify', json={'code': codes[0]}).status_code == 401
    assert alice.get('/api/me').status_code == 401


def test_automatic_ai_is_retried_without_blocking_ocr(alice, admin, monkeypatch):
    tid = tenant(alice)
    admin.put('/api/admin/codex/tenants', json={'tenant_ids': [tid]})
    cfg = {'provider': 'codex', 'model': '', 'consent': True, 'privacy_mode': 'automatic', 'automatic_consent': True}
    assert alice.put(f'/api/tenants/{tid}/integrations/ai', json={'enabled': True, 'config': cfg}).status_code == 200
    monkeypatch.setattr(codex_client, 'request', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('service unavailable')))
    doc_id = upload(alice, tid)
    url = f'/api/tenants/{tid}/documents/{doc_id}'
    assert alice.get(url).json()['status'] == 'ready' and alice.get(url).json()['ai_pending']
    with SessionLocal() as db:
        db.get(Document, doc_id).ai_retry_at = now() - timedelta(seconds=1); db.commit()
    calls = []
    monkeypatch.setattr(codex_client, 'request', lambda method, path, data, **kw: calls.append(data) or {'metadata': {'supplier': 'Lieferant', 'doc_type': 'Rechnung', 'amount': '125.50', 'due_date': None}})
    from app.worker import tick
    assert tick()
    assert len(calls) == 1 and not alice.get(url).json()['ai_pending']
    assert alice.get(url).json()['supplier'] == 'Lieferant'


def test_version_collision_never_deletes_existing_files(alice):
    tid = tenant(alice); doc_id = upload(alice, tid)
    collision = version_path(tid, doc_id, 2)
    collision.parent.mkdir(parents=True)
    collision.write_bytes(b'existing immutable version data')
    response = alice.post(f'/api/tenants/{tid}/documents/{doc_id}/versions', files={'file': ('new.txt', b'new version')})
    assert response.status_code == 409
    assert collision.read_bytes() == b'existing immutable version data'
    assert alice.get(f'/api/tenants/{tid}/documents/{doc_id}').json()['current_version'] == 1


def test_demoted_reviewer_cannot_approve(alice, bob):
    tid = tenant(alice); bob_id = add_member(bob, tid)
    doc_id = upload(alice, tid)
    alice.put(f'/api/tenants/{tid}/workflow', json={'enabled': True})
    review = alice.post(f'/api/tenants/{tid}/documents/{doc_id}/reviews', json={'reviewer_id': bob_id}).json()
    with SessionLocal() as db:
        db.scalar(select(Membership).where(Membership.user_id == bob_id, Membership.tenant_id == tid)).role = 'viewer'
        db.commit()
    assert not bob.get(f'/api/tenants/{tid}/reviews').json()[0]['can_decide']
    assert bob.post(f'/api/tenants/{tid}/reviews/{review["id"]}/decision', json={'decision': 'approved'}).status_code == 403
    assert alice.get(f'/api/tenants/{tid}/documents/{doc_id}').json()['review_status'] == 'pending'
