import json
import zipfile
from datetime import date, datetime
from urllib.parse import unquote
import pytest
from sqlalchemy import select, func
from app.db import SessionLocal, Document, DocumentVersion, Membership, Audit
from app.processing import process_document, classify, retry_ai
from app.storage import current_path
from app.tenant_backup import decrypt_file, encrypt_file


def workspace(client):
    response = client.post('/api/tenants', json={'name': 'Namensregeln'})
    assert response.status_code == 200
    return response.json()['id']


def upload(client, tid, content=b'Rechnung\nOriginal scan content', filename='Scan_001.txt'):
    response = client.post(f'/api/tenants/{tid}/documents', files={'file': (filename, content)})
    assert response.status_code == 200, response.text
    return response.json()


def rule(client, tid, template=None, **kwargs):
    data = {'name': 'Benennen', 'field': 'all', 'filename_template': template} | kwargs
    response = client.post(f'/api/tenants/{tid}/rules', json=data)
    assert response.status_code == 200, response.text
    return response.json()['id']


def process(doc_id):
    with SessionLocal() as db:
        process_document(db, db.get(Document, doc_id)); db.commit()


@pytest.mark.parametrize(('imported_at', 'expected'), [
    (datetime(2026, 2, 3, 12), 'Absender GmbH - 2026 - 02 - 03.txt'),
    (datetime(2024, 2, 29, 12), 'Absender GmbH - 2024 - 02 - 29.txt'),
    (datetime(2026, 12, 31, 23, 30), 'Absender GmbH - 2026 - 12 - 31.txt'),
])
def test_sender_year_month_day_schema_waits_for_sender_and_uses_utc_import_date(alice, imported_at, expected):
    tid = workspace(alice);url = f'/api/tenants/{tid}'
    rule(alice, tid, '{sender} - {year} - {month} - {day}')
    raw = b'Archive original retained'
    doc = upload(alice, tid, raw)
    with SessionLocal() as db:
        saved = db.get(Document, doc['id'])
        saved.created_at = imported_at;saved.due_date = date(2027, 1, 1)
        process_document(db, saved);db.commit()
    current = alice.get(url + '/documents/' + doc['id']).json()
    assert current['filename'] == 'Scan_001.txt'  # Wait instead of inventing a sender.
    payload = {key: current[key] for key in ['title', 'supplier', 'folder_id', 'doc_type', 'tags', 'amount', 'due_date', 'paid']}
    payload['supplier'] = 'Absender GmbH'
    response = alice.put(url + '/documents/' + doc['id'], json=payload)
    assert response.status_code == 200 and response.json()['filename'] == expected
    downloaded = alice.get(url + '/documents/' + doc['id'] + '/file?download=true')
    assert downloaded.content == raw and expected in unquote(downloaded.headers['content-disposition'])
    assert alice.post(url + '/rules/apply').json()['changed'] == 0
    with SessionLocal() as db:
        assert db.scalar(select(DocumentVersion.filename).where(DocumentVersion.document_id == doc['id'])) == 'Scan_001.txt'


def test_folder_and_filename_actions_run_independently_after_ai(alice, monkeypatch):
    tid = workspace(alice); url = f'/api/tenants/{tid}'
    folder = alice.get(url + '/folders').json()[1]['id']
    rule(alice, tid, folder_id=folder, field='doc_type', contains='rechnung', priority=10)
    rule(alice, tid, '{date}_{supplier}_{doc_type}', field='filename', contains='scan_', priority=20)
    rule(alice, tid, 'Fallback', priority=30)
    raw = b'Rechnung\nThe original content stays readable'
    doc = upload(alice, tid, raw)
    def extract(db, doc):
        doc.supplier = 'Example GmbH'
        return True
    monkeypatch.setattr('app.processing.ai_metadata', extract)
    process(doc['id'])
    processed = alice.get(url + '/documents/' + doc['id']).json()
    expected = doc['created_at'][:10] + '_Example GmbH_Rechnung.txt'
    assert processed['filename'] == expected and processed['folder_id'] == folder
    assert processed['title'] == doc['title'] and processed['current_version'] == 1
    response = alice.get(url + '/documents/' + doc['id'] + '/file?download=true')
    assert response.content == raw and expected in unquote(response.headers['content-disposition'])
    with SessionLocal() as db:
        stored = db.get(Document, doc['id'])
        path = current_path(stored)
        assert stored.sha256 == doc['sha256'] and path.read_bytes() == raw
        assert db.scalar(select(DocumentVersion.filename).where(DocumentVersion.document_id == stored.id)) == 'Scan_001.txt'
        assert classify(db, stored) is False
        db.commit()
        assert db.scalar(select(func.count()).select_from(Audit).where(Audit.action == 'document.renamed')) == 1


def test_missing_metadata_waits_then_renames_on_edit_and_ai_retry(alice, monkeypatch):
    tid = workspace(alice); url = f'/api/tenants/{tid}'
    folders = alice.get(url + '/folders').json()
    rule(alice, tid, '{supplier}_{due_date}_{original_name}', folder_id=folders[1]['id'])
    doc = upload(alice, tid); process(doc['id'])
    current = alice.get(url + '/documents/' + doc['id']).json()
    assert current['filename'] == 'Scan_001.txt'
    payload = {k: current[k] for k in ['title', 'supplier', 'folder_id', 'doc_type', 'tags', 'amount', 'due_date', 'paid']}
    payload.update(supplier='Supplier', due_date='2026-12-01', folder_id=folders[0]['id'])
    edited = alice.put(url + '/documents/' + doc['id'], json=payload).json()
    assert edited['filename'] == 'Supplier_2026-12-01_Scan_001.txt'
    assert edited['folder_id'] == folders[0]['id']  # Explicit manual folder selection wins on edits.
    second = upload(alice, tid, b'Rechnung\nSecond scan', 'Scan_002.txt'); process(second['id'])
    def extract(db, doc):
        doc.supplier = 'AI Supplier'; doc.due_date = date(2027, 1, 2)
        return True
    monkeypatch.setattr('app.processing.ai_metadata', extract)
    with SessionLocal() as db:
        retry_ai(db, db.get(Document, second['id']))
    assert alice.get(url + '/documents/' + second['id']).json()['filename'] == 'AI Supplier_2027-01-02_Scan_002.txt'


def test_same_names_are_unique_stable_and_scoped_to_tenant(alice, bob):
    tid = workspace(alice); other = workspace(bob)
    rule(alice, tid, 'Archive'); rule(bob, other, 'Archive')
    a = upload(alice, tid, b'First document'); b = upload(alice, tid, b'Second document')
    c = upload(bob, other, b'Third document')
    for doc in [a, b, c]: process(doc['id'])
    get = lambda client, room, doc: client.get(f'/api/tenants/{room}/documents/{doc["id"]}').json()['filename']
    assert get(alice, tid, a) == 'Archive.txt'
    assert get(alice, tid, b) == 'Archive-' + b['id'] + '.txt'
    assert get(bob, other, c) == 'Archive.txt'
    assert alice.post(f'/api/tenants/{tid}/rules/apply').json()['changed'] == 0
    assert alice.get(f'/api/tenants/{tid}/documents/{a["id"]}/file').content == b'First document'
    assert alice.get(f'/api/tenants/{tid}/documents/{b["id"]}/file').content == b'Second document'


def test_names_sanitize_metadata_and_fit_utf8_nas_limits(alice):
    tid = workspace(alice); rule(alice, tid, '{supplier}_{original_name}')
    a = upload(alice, tid, b'First'); b = upload(alice, tid, b'Second')
    with SessionLocal() as db:
        for doc in [a, b]:
            stored = db.get(Document, doc['id'])
            stored.supplier = '../../NAS\\share:*?"<>|\n' + 'Ü' * 120
            process_document(db, stored)
        db.commit()
    for doc in [a, b]:
        filename = alice.get(f'/api/tenants/{tid}/documents/{doc["id"]}').json()['filename']
        assert len(filename.encode()) <= 255 and filename.endswith('.txt')
        assert not any(c in filename for c in '/\\:*?"<>|\n') and not filename.startswith('.')
    assert alice.post(f'/api/tenants/{tid}/rules/apply').json()['changed'] == 0


@pytest.mark.parametrize('template', ['../{supplier}', '/etc/passwd', '{supplier.__class__}', '{supplier!r}', '{date:%Y}', '{unknown}', '{supplier', '{supplier}.pdf', '..', '\nName'])
def test_invalid_templates_are_rejected(alice, template):
    tid = workspace(alice)
    assert alice.post(f'/api/tenants/{tid}/rules', json={'name': 'Invalid', 'field': 'all', 'filename_template': template}).status_code == 422
    assert alice.get(f'/api/tenants/{tid}/rules').json() == []


def test_rule_validation_priority_pause_edit_and_delete(alice):
    tid = workspace(alice); url = f'/api/tenants/{tid}/rules'
    for data in [{'field': 'all'}, {'field': 'text', 'filename_template': 'Name'}, {'field': 'all', 'filename_template': ' '}]:
        assert alice.post(url, json={'name': 'Invalid'} | data).status_code == 422
    low = rule(alice, tid, 'Low', priority=200)
    high = rule(alice, tid, 'High', priority=10, enabled=False)
    doc = upload(alice, tid); process(doc['id'])
    assert alice.get(f'/api/tenants/{tid}/documents/{doc["id"]}').json()['filename'] == 'Low.txt'
    assert alice.put(url + '/' + high, json={'name': 'High', 'field': 'all', 'filename_template': 'High', 'priority': 10, 'enabled': True}).status_code == 200
    assert alice.post(url + '/apply').json()['changed'] == 1
    assert alice.post(url + '/apply').json()['changed'] == 0
    assert alice.delete(url + '/' + high).status_code == 200
    assert [r['id'] for r in alice.get(url).json()] == [low]


def test_manager_apply_respects_folder_and_document_edit_permissions(alice, bob):
    tid = workspace(alice); other = workspace(bob); url = f'/api/tenants/{tid}'
    with SessionLocal() as db:
        db.add(Membership(tenant_id=tid, user_id=bob.get('/api/me').json()['id'], role='manager')); db.commit()
    foreign = bob.get(f'/api/tenants/{other}/folders').json()[0]['id']
    assert alice.post(url + '/rules', json={'name': 'Cross tenant', 'field': 'all', 'filename_template': 'Name', 'folder_id': foreign}).status_code == 404
    private = alice.get(url + '/folders').json()[1]['id']
    doc = upload(alice, tid); process(doc['id'])
    blocked = rule(alice, tid, 'Private', folder_id=private, priority=10)
    assert alice.put(url + '/folders/' + private + '/access', json={'restricted': True, 'grants': []}).status_code == 200
    assert blocked not in [r['id'] for r in bob.get(url + '/rules').json()]
    assert bob.post(url + '/rules/apply').json()['changed'] == 0
    assert alice.get(url + '/documents/' + doc['id']).json()['filename'] == 'Scan_001.txt'
    assert bob.put(url + '/rules/' + blocked, json={'name': 'Escape', 'field': 'all', 'filename_template': 'Escape'}).status_code == 404
    rule(alice, tid, 'Public', priority=20)
    assert bob.post(url + '/rules/apply').json()['changed'] == 1
    protected = upload(alice, tid, b'Private document'); process(protected['id'])
    bob_id = bob.get('/api/me').json()['id']
    alice.put(url + '/documents/' + protected['id'] + '/access', json={'restricted': True, 'grants': [{'user_id': bob_id, 'can_edit': False}]})
    rule(alice, tid, 'Next', priority=5)
    assert bob.post(url + '/rules/apply').json()['changed'] == 1
    assert alice.get(url + '/documents/' + protected['id']).json()['filename'].startswith('Private')
    assert bob.delete(f'/api/tenants/{other}/rules/{blocked}').status_code == 404
    with SessionLocal() as db:
        member = db.scalar(select(Membership).where(Membership.tenant_id == tid, Membership.user_id == bob_id)); member.role = 'viewer'; db.commit()
    assert bob.post(url + '/rules', json={'name': 'Denied', 'field': 'all', 'filename_template': 'X'}).status_code == 403
    assert bob.post(url + '/rules/apply').status_code == 403


def test_new_versions_use_their_original_names_and_extensions(alice):
    tid = workspace(alice); rule(alice, tid, 'v{version}_{original_name}')
    doc = upload(alice, tid); process(doc['id']); url = f'/api/tenants/{tid}/documents/{doc["id"]}'
    assert alice.get(url).json()['filename'] == 'v1_Scan_001.txt'
    assert alice.post(url + '/versions', files={'file': ('Updated.TXT', b'A different version')}).status_code == 200
    process(doc['id'])
    assert alice.get(url).json()['filename'] == 'v2_Updated.TXT'
    assert [v['filename'] for v in alice.get(url + '/versions').json()['items']] == ['Updated.TXT', 'Scan_001.txt']
    assert alice.post(f'/api/tenants/{tid}/rules/apply').json()['changed'] == 0


def test_backup_preserves_download_names_and_optional_rule_actions(alice):
    tid = workspace(alice); folder = alice.get(f'/api/tenants/{tid}/folders').json()[0]['id']
    rule(alice, tid, '{date}_{original_name}', priority=10)
    rule(alice, tid, folder_id=folder, field='text', contains='Rechnung', priority=20)
    doc = upload(alice, tid); process(doc['id'])
    name = alice.get(f'/api/tenants/{tid}/documents/{doc["id"]}').json()['filename']
    password = 'long-backup-test-password'
    archive = alice.post(f'/api/tenants/{tid}/backup', json={'password': password})
    assert archive.status_code == 200
    restored = alice.post('/api/tenants/restore-backup', files={'file': ('archive.dmsbackup', archive.content)}, data={'password': password, 'name': 'Restored'})
    assert restored.status_code == 200, restored.text
    restored_tid = restored.json()['id']; item = alice.get(f'/api/tenants/{restored_tid}/documents').json()['items'][0]
    assert item['filename'] == name
    assert alice.get(f'/api/tenants/{restored_tid}/documents/{item["id"]}/versions').json()['items'][0]['filename'] == 'Scan_001.txt'
    rules = alice.get(f'/api/tenants/{restored_tid}/rules').json()
    assert rules[0]['folder_id'] is None and rules[0]['filename_template'] == '{date}_{original_name}'
    assert rules[1]['folder_id'] and rules[1]['filename_template'] is None


def test_legacy_backup_without_new_fields_restores(alice, tmp_path):
    tid = workspace(alice); folder = alice.get(f'/api/tenants/{tid}/folders').json()[0]['id']
    rule(alice, tid, folder_id=folder, field='text', contains='Rechnung')
    doc = upload(alice, tid); process(doc['id']); password = 'long-backup-test-password'
    exported = alice.post(f'/api/tenants/{tid}/backup', json={'password': password})
    source = tmp_path / 'input'; source.write_bytes(exported.content)
    decrypt_file(source, tmp_path / 'new.zip', password)
    with zipfile.ZipFile(tmp_path / 'new.zip') as new, zipfile.ZipFile(tmp_path / 'old.zip', 'w') as old:
        for info in new.infolist():
            data = new.read(info.filename)
            if info.filename == 'manifest.json':
                manifest = json.loads(data)
                for item in manifest['documents']: item.pop('filename')
                for item in manifest['rules']: item.pop('filename_template')
                data = json.dumps(manifest).encode()
            old.writestr(info.filename, data)
    encrypt_file(tmp_path / 'old.zip', tmp_path / 'old.backup', password)
    restored = alice.post('/api/tenants/restore-backup', files={'file': ('old.backup', (tmp_path / 'old.backup').read_bytes())}, data={'password': password, 'name': 'Legacy restore'})
    assert restored.status_code == 200, restored.text
    assert alice.get(f'/api/tenants/{restored.json()["id"]}/documents').json()['items'][0]['filename'] == 'Scan_001.txt'
