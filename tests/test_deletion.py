"""Permanent deletion must survive filesystem/database failures and preserve tenant boundaries."""
from datetime import date, timedelta
import pytest
import threading
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import select, func
from app.db import (SessionLocal, Document, DocumentVersion, DocumentGrant, Review, Contract,
    DocumentNote, Annotation, ShareLink, CalendarSync, FolderImport, Integration, MailImport, Membership, Audit, now, engine)
from app.security import encrypt
from app.storage import version_path, ROOT
from app.permissions import used_bytes
from app import deletion, integrations, worker
from test_workspace_tools import tenant, upload, member


def queue(client, tid, ident):
    assert client.delete(f'/api/tenants/{tid}/documents/{ident}').status_code == 200
    response = client.post(f'/api/tenants/{tid}/documents/{ident}/purge', json={'confirmed': True})
    assert response.status_code == 202, response.text


def finish():
    with SessionLocal() as db:
        return deletion.purge_pending(db)


def retry_now(ident):
    with SessionLocal() as db:
        db.get(Document, ident).heartbeat_at = None;db.commit()


def test_purge_removes_all_archive_versions_and_related_records_but_keeps_import_receipts(alice):
    tid = tenant(alice);ident = upload(alice, tid)
    url = f'/api/tenants/{tid}/documents/{ident}'
    assert alice.post(url + '/versions', files={'file': ('second.txt', b'A different document version')}).status_code == 200
    owner = alice.get('/api/me').json()['id']
    with SessionLocal() as db:
        doc = db.get(Document, ident);doc.status = 'ready'
        folder = Integration(tenant_id=tid, kind='folder', enabled=False, config_encrypted=encrypt({}))
        mail = Integration(tenant_id=tid, kind='imap', enabled=False, config_encrypted=encrypt({}))
        db.add_all([folder, mail]);db.flush()
        receipt = FolderImport(tenant_id=tid, integration_id=folder.id, document_id=ident, source_key='x'*64, filename='scan.txt', status='pending', error='Source cleanup waiting')
        mail_receipt = MailImport(integration_id=mail.id, message_key='processed-mail')
        db.add_all([receipt, mail_receipt,
            DocumentGrant(document_id=ident, user_id=owner, can_edit=True),
            Review(tenant_id=tid, document_id=ident, version=2, requester_id=owner, reviewer_id=owner),
            Contract(document_id=ident, end_date=date(2027, 1, 1)),
            DocumentNote(document_id=ident, author_id=owner, body='Internal note'),
            Annotation(document_id=ident, author_id=owner, version=1, page=1, rect=[0,0,.5,.5]),
            ShareLink(document_id=ident, creator_id=owner, token_hash='x'*64, version=1, filename='doc.txt', expires_at=now()+timedelta(days=1))])
        db.commit();receipt_id, mail_id = receipt.id, mail_receipt.id
        assert used_bytes(db, tid) > doc.size
    original, second = version_path(tid, ident, 1), version_path(tid, ident, 2)
    assert original.is_file() and second.is_file()
    queue(alice, tid, ident)
    with SessionLocal() as db: assert used_bytes(db, tid) > 0
    assert finish()
    assert not original.parent.exists() and not second.exists()
    assert alice.get(url).status_code == 404
    with SessionLocal() as db:
        assert db.get(Document, ident) is None and used_bytes(db, tid) == 0
        for model in [DocumentVersion, DocumentGrant, Review, Contract, DocumentNote, Annotation, ShareLink]:
            assert db.scalar(select(func.count()).select_from(model).where(model.document_id == ident)) == 0
        assert db.get(FolderImport, receipt_id).document_id is None
        assert db.get(FolderImport, receipt_id).status == 'done'
        assert db.get(FolderImport, receipt_id).error is None
        assert db.get(MailImport, mail_id).message_key == 'processed-mail'
        assert {a.action for a in db.scalars(select(Audit).where(Audit.detail == ident))} >= {'document.purge_requested', 'document.purged'}


def test_confirmation_trash_state_and_active_processing_are_required(alice):
    tid = tenant(alice);ident = upload(alice, tid);url = f'/api/tenants/{tid}/documents/{ident}'
    assert alice.post(url+'/purge', json={'confirmed':False}).status_code == 422
    assert alice.post(url+'/purge', json={}).status_code == 422
    assert alice.post(url+'/purge', json={'confirmed':True}).status_code == 409
    with SessionLocal() as db:
        doc=db.get(Document,ident);doc.status='processing';doc.deleted_at=now();db.commit()
    assert alice.post(url+'/purge', json={'confirmed':True}).status_code == 409
    assert version_path(tid,ident,1).is_file()


def test_queued_deletion_is_idempotent_and_blocks_restore_downloads_edits_and_bulk(alice):
    tid=tenant(alice);ident=upload(alice,tid);url=f'/api/tenants/{tid}/documents/{ident}'
    queue(alice,tid,ident)
    assert alice.post(url+'/purge',json={'confirmed':True}).status_code == 202
    for suffix in ['', '/file', '/versions', '/versions/1/file', '/notes']:
        assert alice.get(url+suffix).status_code == 409
    assert alice.post(url+'/restore').status_code == 409
    assert alice.post(url+'/reprocess').status_code == 409
    assert alice.post(f'/api/tenants/{tid}/bulk',json={'action':'restore','document_ids':[ident]}).status_code == 409
    rows=alice.get(f'/api/tenants/{tid}/documents?trash=true').json()['items']
    assert rows[0]['status']=='purging' and rows[0]['can_edit'] is False
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Audit).where(Audit.action=='document.purge_requested',Audit.detail==ident))==1


def test_permanent_delete_requires_manager_edit_rights_and_correct_tenant(alice,bob):
    tid=tenant(alice);member(bob,tid,'editor');ident=upload(alice,tid);url=f'/api/tenants/{tid}/documents/{ident}'
    assert bob.delete(url).status_code==200
    assert bob.post(url+'/purge',json={'confirmed':True}).status_code==403
    assert bob.post(url+'/restore').status_code==200
    assert bob.delete(url).status_code==200
    with SessionLocal() as db:
        db.scalar(select(Membership).where(Membership.tenant_id==tid,Membership.user_id==bob.get('/api/me').json()['id'])).role='manager';db.commit()
    assert alice.put(url+'/access',json={'restricted':True,'grants':[{'user_id':bob.get('/api/me').json()['id'],'can_edit':False}]}).status_code==200
    assert bob.post(url+'/purge',json={'confirmed':True}).status_code==404
    assert bob.get(f'/api/tenants/{tid}/documents?trash=true').json()['items'][0]['can_edit'] is False
    other=tenant(alice)
    assert alice.post(f'/api/tenants/{other}/documents/{ident}/purge',json={'confirmed':True}).status_code==404
    assert version_path(tid,ident,1).is_file()


def test_filesystem_failure_keeps_metadata_and_retries_after_restart(alice,monkeypatch):
    tid=tenant(alice);ident=upload(alice,tid);queue(alice,tid,ident)
    original=deletion.remove_archive
    monkeypatch.setattr(deletion,'remove_archive',lambda doc: (_ for _ in ()).throw(PermissionError('Read-only NAS')))
    assert finish()
    with SessionLocal() as db:
        doc=db.get(Document,ident)
        assert doc.status=='purging' and doc.error and used_bytes(db,tid)>0
    assert version_path(tid,ident,1).is_file()
    assert not finish()  # Retry backoff; no busy loop.
    monkeypatch.setattr(deletion,'remove_archive',original);retry_now(ident)
    assert finish()
    with SessionLocal() as db: assert db.get(Document,ident) is None


def test_database_failure_after_file_removal_is_retryable(alice,monkeypatch):
    tid=tenant(alice);ident=upload(alice,tid);queue(alice,tid,ident)
    with SessionLocal() as db:
        original=db.commit;failed=False
        def commit():
            nonlocal failed
            if not failed: failed=True;raise RuntimeError('Database interruption')
            return original()
        monkeypatch.setattr(db,'commit',commit)
        assert deletion.purge_pending(db)
    assert not version_path(tid,ident,1).parent.exists()
    with SessionLocal() as db: assert db.get(Document,ident).status=='purging'
    retry_now(ident);assert finish()
    with SessionLocal() as db: assert db.get(Document,ident) is None


def test_missing_storage_is_not_treated_as_an_already_deleted_document(alice,monkeypatch,tmp_path):
    tid=tenant(alice);ident=upload(alice,tid);queue(alice,tid,ident)
    monkeypatch.setattr(deletion,'ROOT',tmp_path/'unavailable-nas')
    assert finish()
    with SessionLocal() as db: assert db.get(Document,ident).status=='purging'
    assert version_path(tid,ident,1).is_file()


@pytest.mark.parametrize('link_tenant',[False,True])
def test_archive_directory_symlinks_cannot_delete_other_data(alice,tmp_path,link_tenant):
    tid=tenant(alice);ident=upload(alice,tid);queue(alice,tid,ident)
    target=ROOT/tid if link_tenant else version_path(tid,ident,1).parent
    saved=tmp_path/'preserved';target.rename(saved);target.symlink_to(saved,target_is_directory=True)
    assert finish()
    assert (saved/ident/'original' if link_tenant else saved/'original').is_file()
    with SessionLocal() as db: assert db.get(Document,ident).status=='purging'
    target.unlink();saved.rename(target)


def test_pending_deletion_is_excluded_from_new_tenant_backups(alice):
    tid=tenant(alice);ident=upload(alice,tid);queue(alice,tid,ident)
    response=alice.post(f'/api/tenants/{tid}/backup',json={'password':'long-backup-test-password'})
    assert response.status_code==200,response.text
    restored=alice.post('/api/tenants/restore-backup',files={'file':('deleted.dmsbackup',response.content)},data={'password':'long-backup-test-password','name':'Without deleted document'})
    assert restored.status_code==200,restored.text
    assert alice.get(f"/api/tenants/{restored.json()['id']}/documents?trash=true").json()['total']==0


def test_calendar_cleanup_survives_document_purge_and_provider_failure(alice,monkeypatch):
    tid=tenant(alice);ident=upload(alice,tid)
    with SessionLocal() as db:
        integration=Integration(tenant_id=tid,kind='caldav',enabled=True,config_encrypted=encrypt({'url':'https://calendar.example.org/dms/','username':'test','password':'test'}))
        db.add(integration);db.flush()
        db.add(CalendarSync(integration_id=integration.id,document_id=ident));db.commit();integration_id=integration.id
    queue(alice,tid,ident);assert finish()
    state={'offline':True,'deleted':[]}
    class Client:
        def __init__(self,*args,**kwargs):pass
        def __enter__(self):
            if state['offline']:raise OSError('Offline')
            return self
        def __exit__(self,*args):pass
        def calendar(self,**kwargs):return self
        def event_by_uid(self,uid):
            class Event:
                def delete(self):state['deleted'].append(uid)
            return Event()
    monkeypatch.setattr(integrations.caldav,'DAVClient',Client)
    with SessionLocal() as db:
        assert 'fehlgeschlagen' in integrations.run_integration_once(db,db.get(Integration,integration_id))
        row=db.scalar(select(CalendarSync).where(CalendarSync.integration_id==integration_id))
        assert row.document_id is None and row.event_uid==f'archivraum-{tid}-{ident}'
    state['offline']=False
    with SessionLocal() as db:
        assert integrations.run_integration_once(db,db.get(Integration,integration_id))=='0 Fälligkeiten synchronisiert.'
        assert db.scalar(select(CalendarSync).where(CalendarSync.integration_id==integration_id)) is None
    assert state['deleted']==[f'archivraum-{tid}-{ident}']


def test_worker_completes_deletion_without_a_request_session(alice):
    tid=tenant(alice);ident=upload(alice,tid);queue(alice,tid,ident)
    worker._tick()
    with SessionLocal() as db: assert db.get(Document,ident) is None


@pytest.mark.skipif(engine.dialect.name != 'mysql', reason='Requires MariaDB row locks')
def test_purge_waits_for_inflight_calendar_publication_and_preserves_cleanup(alice, monkeypatch):
    tid=tenant(alice);ident=upload(alice,tid)
    with SessionLocal() as db:
        db.get(Document,ident).due_date=date(2027,1,1)
        integration=Integration(tenant_id=tid,kind='caldav',enabled=True,config_encrypted=encrypt({'url':'https://calendar.example.org/dms/','username':'test','password':'test'}))
        db.add(integration);db.commit();integration_id=integration.id
    publishing,release=threading.Event(),threading.Event()
    class Client:
        def __init__(self,*args,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def calendar(self,**kwargs):return self
        def save_event(self,data):
            publishing.set()
            if not release.wait(10):raise TimeoutError('Calendar publication timeout')
    monkeypatch.setattr(integrations.caldav,'DAVClient',Client)
    def sync():
        with SessionLocal() as db:return integrations.run_integration_once(db,db.get(Integration,integration_id))
    with ThreadPoolExecutor(max_workers=2) as executor:
        sync_job=executor.submit(sync)
        try:
            assert publishing.wait(5)
            queue(alice,tid,ident)
            deletion_job=executor.submit(finish)
            # A publication that read the document before it was trashed still needs its receipt.
            assert version_path(tid,ident,1).is_file()
        finally:release.set()
        assert sync_job.result(timeout=10)=='1 Fälligkeiten synchronisiert.'
        assert deletion_job.result(timeout=10)
    with SessionLocal() as db:
        assert db.get(Document,ident) is None
        row=db.scalar(select(CalendarSync).where(CalendarSync.integration_id==integration_id))
        assert row.document_id is None and row.event_uid==f'archivraum-{tid}-{ident}'
