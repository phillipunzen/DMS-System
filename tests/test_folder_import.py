import hashlib
import os
import time
from pathlib import Path
from sqlalchemy import select, func
import pytest
from app import folder_import
from app.db import SessionLocal, Document, FolderImport, Integration, Tenant
from app.integrations import run_integration_once
from app.storage import path_for
from app.worker import tick


@pytest.fixture(autouse=True)
def scanner_mount(tmp_path, monkeypatch):
    monkeypatch.setattr(folder_import, 'ROOT', tmp_path / 'consume')
    monkeypatch.delenv('CONSUME_HOST_PATH', raising=False)


def setup_import(client, config=None):
    r = client.post('/api/tenants', json={'name': 'Scannerarchiv'})
    assert r.status_code == 200, r.text
    tid = r.json()['id']
    r = client.put(f'/api/tenants/{tid}/integrations/folder', json={'enabled': True, 'config': config or {'after_import': 'delete', 'settle_seconds': 5}})
    assert r.status_code == 200, r.text
    return tid, folder_import.directories(tid)


def deposit(paths, name='scan.txt', content=b'Scanner Rechnung\nFaellig am: 01.12.2026\n'):
    path = paths['incoming'] / name
    path.write_bytes(content)
    os.utime(path, (time.time() - 60, time.time() - 60))
    return path


def run_import(client, tid):
    r = client.post(f'/api/tenants/{tid}/integrations/folder/run')
    assert r.status_code == 200, r.text
    return r.json()['status']


def test_scanner_delete_only_after_durable_import_and_ocr(alice):
    tid, paths = setup_import(alice)
    source = deposit(paths)
    content = source.read_bytes()
    assert '1 importiert' in run_import(alice, tid)
    assert not source.exists()
    docs = alice.get(f'/api/tenants/{tid}/documents').json()['items']
    assert len(docs) == 1 and docs[0]['source'] == 'scanner'
    assert path_for(tid, docs[0]['id']).read_bytes() == content
    with SessionLocal() as db:
        receipt = db.scalar(select(FolderImport))
        assert receipt.status == 'done' and receipt.document_id == docs[0]['id']
    tick()
    doc = alice.get(f'/api/tenants/{tid}/documents/{docs[0]["id"]}').json()
    assert doc['status'] == 'ready' and 'Scanner Rechnung' in doc['text']
    assert '0 importiert' in run_import(alice, tid)


def test_scanner_archive_preserves_name_and_never_overwrites(alice):
    tid, paths = setup_import(alice, {'after_import': 'archive', 'settle_seconds': 5})
    source = deposit(paths, 'rechnung.txt')
    first = source.read_bytes()
    assert '1 importiert' in run_import(alice, tid)
    source = deposit(paths, 'rechnung.txt', b'Andere Rechnung mit gleichem Namen')
    assert '1 importiert' in run_import(alice, tid)
    archives = list(paths['processed'].iterdir())
    assert len(archives) == 2 and all(p.name.endswith('-rechnung.txt') for p in archives)
    assert {p.read_bytes() for p in archives} == {first, b'Andere Rechnung mit gleichem Namen'}
    assert not source.exists()


def test_scanner_incomplete_files_duplicates_and_bad_files_are_retained(alice):
    tid, paths = setup_import(alice)
    fresh = deposit(paths, 'fresh.txt', b'Noch im Scanner')
    os.utime(fresh, None)
    partial = deposit(paths, 'scan.part')
    hidden = deposit(paths, '.scan.txt')
    unsupported = deposit(paths, 'bad.zip', b'PK\x03\x04' + b'\x00' * 100)
    source = deposit(paths)
    original = source.read_bytes()
    status = run_import(alice, tid)
    assert '1 importiert' in status and '1 fehlgeschlagen' in status
    assert fresh.exists() and partial.exists() and hidden.exists() and unsupported.exists()
    duplicate = deposit(paths, content=original)
    assert '1 Duplikate' in run_import(alice, tid)
    assert duplicate.exists()
    cfg = next(i for i in alice.get(f'/api/tenants/{tid}/integrations').json() if i['kind'] == 'folder')
    assert any('Duplikat' in e['error'] for e in cfg['errors'])
    assert any(e['filename'] == 'bad.zip' for e in cfg['errors'])
    assert alice.get(f'/api/tenants/{tid}/documents').json()['total'] == 1


def test_scanner_quota_error_can_be_retried_manually(alice):
    tid, paths = setup_import(alice)
    source = deposit(paths)
    with SessionLocal() as db:
        db.get(Tenant, tid).quota_mb = 0
        db.commit()
    assert '1 fehlgeschlagen' in run_import(alice, tid)
    assert source.exists() and alice.get(f'/api/tenants/{tid}/documents').json()['total'] == 0
    with SessionLocal() as db:
        db.get(Tenant, tid).quota_mb = 1
        db.commit()
    assert '1 importiert' in run_import(alice, tid)
    assert not source.exists()


def test_scanner_crash_between_commit_and_deletion_resumes_without_duplicate(alice, monkeypatch):
    tid, paths = setup_import(alice)
    source = deposit(paths)
    real_finalize = folder_import.finalize_source
    def interrupted(*args):
        raise OSError('Crash before source cleanup')
    monkeypatch.setattr(folder_import, 'finalize_source', interrupted)
    assert '1 importiert' in run_import(alice, tid)
    assert source.exists()
    with SessionLocal() as db:
        assert db.scalar(select(FolderImport)).status == 'pending'
        assert db.scalar(select(func.count()).select_from(Document)) == 1
    monkeypatch.setattr(folder_import, 'finalize_source', real_finalize)
    run_import(alice, tid)
    assert not source.exists()
    assert alice.get(f'/api/tenants/{tid}/documents').json()['total'] == 1
    with SessionLocal() as db:
        assert db.scalar(select(FolderImport)).status == 'done'


def test_scanner_changed_source_and_missing_original_are_never_deleted(alice, monkeypatch):
    tid, paths = setup_import(alice)
    source = deposit(paths)
    real_finalize = folder_import.finalize_source
    monkeypatch.setattr(folder_import, 'finalize_source', lambda *args: (_ for _ in ()).throw(OSError('Crash')))
    run_import(alice, tid)
    with SessionLocal() as db:
        doc = db.scalar(select(Document))
        original = path_for(tid, doc.id)
        original.write_bytes(b'Corrupted original')
    monkeypatch.setattr(folder_import, 'finalize_source', real_finalize)
    assert '1 fehlgeschlagen' in run_import(alice, tid)
    assert source.exists()
    # A replacement scanner file must be imported separately, never removed as the old receipt.
    source = deposit(paths, content=b'Neue Datei, gleicher Name')
    assert '1 importiert' in run_import(alice, tid)
    assert alice.get(f'/api/tenants/{tid}/documents').json()['total'] == 2
    with SessionLocal() as db:
        assert 'changed' in db.scalars(select(FolderImport.status)).all()


def test_scanner_tenant_paths_and_permissions_are_enforced(alice, bob, tmp_path):
    tid, paths = setup_import(alice)
    other, other_paths = setup_import(bob)
    alien = deposit(other_paths, content=b'Geheimnis anderer Mandant')
    outside = tmp_path / 'outside.txt'
    outside.write_text('Nicht importieren')
    (paths['incoming'] / 'link.txt').symlink_to(outside)
    (paths['incoming'] / 'subfolder').mkdir()
    assert '0 importiert' in run_import(alice, tid)
    assert outside.exists() and alien.exists()
    assert bob.get(f'/api/tenants/{tid}/integrations').status_code == 403
    assert bob.post(f'/api/tenants/{tid}/integrations/folder/run').status_code == 403
    for config in [{'path': str(other_paths['incoming'])}, {'after_import': 'invalid'}, {'settle_seconds': 0}, {'folder_id': {'path': '/tmp'}}]:
        assert alice.put(f'/api/tenants/{tid}/integrations/folder', json={'enabled': True, 'config': config}).status_code == 422
    foreign_folder = bob.get(f'/api/tenants/{other}/folders').json()[0]['id']
    assert alice.put(f'/api/tenants/{tid}/integrations/folder', json={'enabled': True, 'config': {'folder_id': foreign_folder}}).status_code == 404


def test_scanner_file_change_during_copy_leaves_source_and_no_document(alice, monkeypatch):
    tid, paths = setup_import(alice)
    source = deposit(paths)
    save = folder_import.save_document
    def changing_file(*args, **kwargs):
        doc = save(*args, **kwargs)
        source.write_bytes(b'Continued scanner writing')
        return doc
    monkeypatch.setattr(folder_import, 'save_document', changing_file)
    assert '1 fehlgeschlagen' in run_import(alice, tid)
    assert source.exists()
    assert alice.get(f'/api/tenants/{tid}/documents').json()['total'] == 0
    with SessionLocal() as db:
        assert db.scalar(select(FolderImport)).status == 'error'
    root = path_for(tid, '00000000-0000-0000-0000-000000000000').parent.parent
    assert not root.exists() or not list(root.iterdir())


def test_scanner_background_worker_and_target_folder(alice):
    tid, paths = setup_import(alice)
    folder = alice.post(f'/api/tenants/{tid}/folders', json={'name': 'Scanner'}).json()
    r = alice.put(f'/api/tenants/{tid}/integrations/folder', json={'enabled': True, 'config': {'settle_seconds': 5, 'folder_id': folder['id']}})
    assert r.status_code == 200, r.text
    source = deposit(paths)
    tick()
    assert not source.exists()
    doc = alice.get(f'/api/tenants/{tid}/documents').json()['items'][0]
    assert doc['folder_id'] == folder['id']


def test_scanner_commit_failure_preserves_source_and_cleans_uncommitted_original(alice, monkeypatch):
    from sqlalchemy.orm import Session
    tid, paths = setup_import(alice)
    source = deposit(paths)
    commit = Session.commit
    interrupted = False
    def failed_commit(db):
        nonlocal interrupted
        if not interrupted and any(isinstance(row, FolderImport) and row.status == 'pending' for row in db.new):
            interrupted = True
            raise OSError('Simulated DB commit failure')
        return commit(db)
    monkeypatch.setattr(Session, 'commit', failed_commit)
    assert '1 fehlgeschlagen' in run_import(alice, tid)
    assert interrupted and source.exists()
    assert alice.get(f'/api/tenants/{tid}/documents').json()['total'] == 0
    root = path_for(tid, '00000000-0000-0000-0000-000000000000').parent.parent
    assert not root.exists() or not list(root.iterdir())
    assert '1 importiert' in run_import(alice, tid)
    assert not source.exists()


def test_scanner_manual_and_worker_runs_cannot_overlap(alice):
    import fcntl
    tid, paths = setup_import(alice)
    source = deposit(paths)
    with (paths['tenant'] / '.import.lock').open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert 'bereits geprüft' in run_import(alice, tid)
        assert source.exists()
        assert alice.get(f'/api/tenants/{tid}/documents').json()['total'] == 0
    assert '1 importiert' in run_import(alice, tid)
