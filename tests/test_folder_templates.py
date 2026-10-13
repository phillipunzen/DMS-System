"""Dynamic folder paths, tenant separation, inherited ACLs and safe restoration."""
from datetime import datetime
from pathlib import Path
import pytest
from sqlalchemy import select, text
from alembic.config import Config
from alembic import command
from app.db import SessionLocal, Folder, Document, Membership, engine
from app.processing import classify, process_document
from app.storage import current_path
from test_naming import workspace, upload, rule


def folder(client, tid, name, parent=None):
    response = client.post(f'/api/tenants/{tid}/folders', json={'name': name, 'parent_id': parent})
    assert response.status_code == 200, response.text
    return response.json()['id']


def ready(client, tid, sender='Example GmbH', content=b'Rechnung Original archive bytes'):
    doc = upload(client, tid, content)
    with SessionLocal() as db:
        saved = db.get(Document, doc['id'])
        saved.supplier = sender; saved.created_at = datetime(2026, 2, 3, 12)
        process_document(db, saved); db.commit()
    return client.get(f'/api/tenants/{tid}/documents/{doc["id"]}').json()


def test_combined_path_creates_reuses_nested_folders_and_keeps_original(alice):
    tid = workspace(alice); url = f'/api/tenants/{tid}'
    rid = rule(alice, tid, 'Rechnungen/{year}/{sender}/{date} - {doc_type}')
    cfg = alice.get(url + '/rules').json()[0]
    assert cfg['id'] == rid and cfg['folder_template'] == 'Rechnungen/{year}/{sender}'
    assert cfg['filename_template'] == '{date} - {doc_type}'
    doc = ready(alice, tid)
    assert doc['filename'] == '2026-02-03 - Rechnung.txt'
    rows = alice.get(url + '/folders').json(); by_name = {f['name']: f for f in rows}
    root, year, sender = [by_name[n] for n in ['Rechnungen', 'Rechnungen/2026', 'Rechnungen/2026/Example GmbH']]
    assert root['parent_id'] is None and year['parent_id'] == root['id'] and sender['parent_id'] == year['id']
    assert sender['display_name'] == 'Example GmbH' and sender['count'] == 1 and doc['folder_id'] == sender['id']
    assert alice.post(url + '/rules/apply').json()['changed'] == 0
    other = ready(alice, tid, content=b'Rechnung Different original archive bytes')
    assert other['folder_id'] == sender['id'] and len(alice.get(url + '/folders').json()) == len(rows)
    assert alice.delete(url + '/folders/' + root['id']).status_code == 409
    with SessionLocal() as db:
        original = current_path(db.get(Document, doc['id']))
        assert original.read_bytes() == b'Rechnung Original archive bytes'
        assert sender['name'] not in str(original)


def test_missing_sender_waits_without_creating_partial_path(alice):
    tid = workspace(alice); url = f'/api/tenants/{tid}'
    rule(alice, tid, folder_template='Archive/{year}/{sender}')
    before = alice.get(url + '/folders').json()
    doc = ready(alice, tid, sender='')
    assert alice.get(url + '/folders').json() == [f | {'count': 1 if f['id'] == doc['folder_id'] else f['count'], 'total_count': 1 if f['id'] == doc['folder_id'] else f['total_count']} for f in before]
    with SessionLocal() as db:
        saved = db.get(Document, doc['id']); saved.supplier = 'Now known'
        assert classify(db, saved); db.commit()
    assert any(f['name'] == 'Archive/2026/Now known' for f in alice.get(url + '/folders').json())


def test_separate_folder_template_is_relative_to_selected_base(alice):
    tid = workspace(alice); base = folder(alice, tid, 'Business')
    rule(alice, tid, '{date}', folder_id=base, folder_template='{sender}/{year}')
    doc = ready(alice, tid)
    target = next(f for f in alice.get(f'/api/tenants/{tid}/folders').json() if f['id'] == doc['folder_id'])
    assert target['name'] == 'Business/Example GmbH/2026'
    assert doc['filename'] == '2026-02-03.txt'


@pytest.mark.parametrize('template', ['/etc/passwd', '../Archive', 'A/../B', 'A//B', 'A/', '{unknown}', 'A\\B', 'A/\nB', '/'.join(['A']*9)])
def test_invalid_folder_paths_are_rejected(alice, template):
    tid = workspace(alice)
    assert alice.post(f'/api/tenants/{tid}/rules', json={'name':'Unsafe', 'field':'all', 'folder_template':template}).status_code == 422


def test_combined_path_with_separate_template_is_rejected(alice):
    tid = workspace(alice)
    assert alice.post(f'/api/tenants/{tid}/rules', json={'name':'Ambiguous', 'field':'all', 'folder_template':'A', 'filename_template':'B/Name'}).status_code == 422


def test_metadata_cannot_inject_path_and_long_names_do_not_merge(alice):
    tid = workspace(alice)
    rule(alice, tid, folder_template='Archive/{sender}')
    doc = ready(alice, tid, sender='../../A/B\\C')
    names = alice.get(f'/api/tenants/{tid}/folders').json()
    target = next(f for f in names if f['id'] == doc['folder_id'])
    assert target['parent_id'] and target['display_name'] == '-..-A-B-C'
    one = ready(alice, tid, sender='Ä'*100+'A', content=b'Rechnung Long A')
    two = ready(alice, tid, sender='Ä'*100+'B', content=b'Rechnung Long B')
    assert one['folder_id'] != two['folder_id']


def test_restricted_parent_is_inherited_and_changes_apply_immediately(alice, bob):
    tid = workspace(alice); url = f'/api/tenants/{tid}'
    with SessionLocal() as db:
        from app.db import User
        user = db.scalar(select(User).where(User.email == 'bob@example.com'))
        uid = user.id; db.add(Membership(tenant_id=tid,user_id=uid,role='manager')); db.commit()
    root = folder(alice, tid, 'Private')
    rule(alice, tid, folder_id=root, folder_template='{year}/{sender}')
    assert alice.put(url + '/folders/' + root + '/access', json={'restricted':True,'grants':[]}).status_code == 200
    doc = ready(alice, tid)
    assert not any(f['name'].startswith('Private') for f in bob.get(url + '/folders').json())
    assert bob.get(url + '/documents/' + doc['id']).status_code == 404
    assert alice.put(url + '/folders/' + root + '/access', json={'restricted':True,'grants':[{'user_id':uid,'can_edit':False}]}).status_code == 200
    assert bob.get(url + '/documents/' + doc['id']).status_code == 200
    assert bob.delete(url + '/documents/' + doc['id']).status_code == 404
    assert bob.post(url + '/folders', json={'name':'Blocked','parent_id':doc['folder_id']}).status_code == 404
    assert bob.post(url + '/rules/apply').json()['changed'] == 0
    assert alice.put(url + '/folders/' + root + '/access', json={'restricted':True,'grants':[]}).status_code == 200
    assert bob.get(url + '/documents/' + doc['id']).status_code == 404


def test_existing_restricted_destination_cannot_be_used_by_manager(alice, bob):
    tid = workspace(alice); url = f'/api/tenants/{tid}'
    with SessionLocal() as db:
        from app.db import User
        uid = db.scalar(select(User.id).where(User.email=='bob@example.com'))
        db.add(Membership(tenant_id=tid,user_id=uid,role='manager')); db.commit()
    root = folder(alice,tid,'Archive'); child = folder(alice,tid,'2026',root)
    assert alice.put(url+'/folders/'+child+'/access',json={'restricted':True,'grants':[]}).status_code==200
    doc = ready(alice,tid)
    rule(alice,tid,'Changed',folder_id=root,folder_template='{year}')
    assert bob.post(url+'/rules/apply').json()['changed']==0
    unchanged=alice.get(url+'/documents/'+doc['id']).json()
    assert unchanged['folder_id']==doc['folder_id'] and unchanged['filename']==doc['filename']
    assert alice.post(url+'/rules/apply').json()['changed']==1


def test_nested_folders_are_tenant_local_and_depth_is_bounded(alice, bob):
    tid=workspace(alice); other=workspace(bob)
    rule(alice,tid,folder_template='{year}/{sender}');rule(bob,other,folder_template='{year}/{sender}')
    one=ready(alice,tid);two=ready(bob,other)
    assert one['folder_id'] != two['folder_id']
    assert alice.post(f'/api/tenants/{tid}/folders',json={'name':'Foreign','parent_id':two['folder_id']}).status_code==404
    parent=None
    for n in range(8):parent=folder(alice,tid,'Level'+str(n),parent)
    assert alice.post(f'/api/tenants/{tid}/folders',json={'name':'Too deep','parent_id':parent}).status_code==422
    rule(alice,tid,folder_id=parent,folder_template='Overflow',priority=0)
    assert alice.post(f'/api/tenants/{tid}/rules/apply').json()['changed']==0
    assert not any(f['name'].endswith('/Overflow') for f in alice.get(f'/api/tenants/{tid}/folders').json())


def test_backup_restores_hierarchy_and_templates(alice):
    tid=workspace(alice);rule(alice,tid,'{date}',folder_template='Archive/{year}/{sender}')
    doc=ready(alice,tid);password='long-backup-test-password'
    response=alice.post(f'/api/tenants/{tid}/backup',json={'password':password});assert response.status_code==200
    restored=alice.post('/api/tenants/restore-backup',data={'password':password,'name':'Restored'},files={'file':('backup.dms',response.content)})
    assert restored.status_code==200,restored.text
    rid=restored.json()['id'];rows=alice.get(f'/api/tenants/{rid}/folders').json()
    paths={f['name']:f for f in rows}
    assert paths['Archive/2026']['parent_id']==paths['Archive']['id']
    assert paths['Archive/2026/Example GmbH']['parent_id']==paths['Archive/2026']['id']
    cfg=alice.get(f'/api/tenants/{rid}/rules').json()[0]
    assert cfg['folder_template']=='Archive/{year}/{sender}' and cfg['filename_template']=='{date}'
    assert alice.get(f'/api/tenants/{rid}/documents').json()['items'][0]['folder_id']==paths['Archive/2026/Example GmbH']['id']


def test_folder_migration_preserves_existing_rows_and_refuses_loss(alice):
    tid=workspace(alice);root=folder(alice,tid,'Existing')
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    try:
        command.stamp(config,'head');command.downgrade(config,'0009');command.upgrade(config,'head')
        assert alice.get(f'/api/tenants/{tid}/folders').status_code==200
        assert any(f['id']==root and f['parent_id'] is None for f in alice.get(f'/api/tenants/{tid}/folders').json())
        folder(alice,tid,'Child',root)
        with pytest.raises(RuntimeError,match='nested folders'):command.downgrade(config,'0009')
    finally:
        with engine.begin() as conn:conn.execute(text('DROP TABLE IF EXISTS alembic_version'))


def test_worker_checks_dynamic_rule_author_permissions(alice,bob):
    tid=workspace(alice);url=f'/api/tenants/{tid}'
    with SessionLocal() as db:
        from app.db import User
        uid=db.scalar(select(User.id).where(User.email=='bob@example.com'))
        db.add(Membership(tenant_id=tid,user_id=uid,role='manager'));db.commit()
    root=folder(alice,tid,'Private')
    assert alice.put(url+'/folders/'+root+'/access',json={'restricted':True,'grants':[]}).status_code==200
    rid=rule(bob,tid,'Changed',folder_template='Private/{year}')
    doc=ready(alice,tid)
    assert doc['filename']=='Scan_001.txt'
    assert not any(f['name']=='Private/2026' for f in alice.get(url+'/folders').json())
    # The owner can take responsibility for the same saved rule.
    assert alice.put(url+'/rules/'+rid,json={'name':'Trusted','field':'all','folder_template':'Private/{year}','filename_template':'Changed'}).status_code==200
    with SessionLocal() as db:
        saved=db.get(Document,doc['id']);assert classify(db,saved);db.commit()
    assert alice.get(url+'/documents/'+doc['id']).json()['filename']=='Changed.txt'


def test_worker_cannot_move_hidden_source_into_public_folder(alice,bob):
    tid=workspace(alice);url=f'/api/tenants/{tid}'
    with SessionLocal() as db:
        from app.db import User
        uid=db.scalar(select(User.id).where(User.email=='bob@example.com'))
        db.add(Membership(tenant_id=tid,user_id=uid,role='manager'));db.commit()
    doc=ready(alice,tid);inbox=doc['folder_id']
    assert alice.put(url+'/folders/'+inbox+'/access',json={'restricted':True,'grants':[]}).status_code==200
    rule(bob,tid,'Escaped',folder_template='Public/{year}')
    with SessionLocal() as db:
        saved=db.get(Document,doc['id']);assert classify(db,saved) is False;db.commit()
    assert not any(f['name']=='Public' for f in alice.get(url+'/folders').json())
    assert bob.get(url+'/documents/'+doc['id']).status_code==404


def test_legacy_literal_path_root_is_not_reused_as_child(alice):
    tid=workspace(alice)
    with SessionLocal() as db:db.add(Folder(tenant_id=tid,name='Archive/2026'));db.commit()
    rule(alice,tid,folder_template='Archive/{year}')
    doc=ready(alice,tid)
    assert not any(f['name']=='Archive' for f in alice.get(f'/api/tenants/{tid}/folders').json())
    assert next(f for f in alice.get(f'/api/tenants/{tid}/folders').json() if f['name']=='Archive/2026')['parent_id'] is None


def test_case_insensitive_folder_reuse_preserves_canonical_parent_path(alice):
    tid=workspace(alice);root=folder(alice,tid,'Archive')
    rule(alice,tid,folder_template='archive/{year}')
    doc=ready(alice,tid)
    with SessionLocal() as db:
        target=db.get(Folder,doc['folder_id']);parent=db.get(Folder,target.parent_id)
        assert target.name.startswith(parent.name+'/')
    response=alice.post(f'/api/tenants/{tid}/backup',json={'password':'long-backup-test-password'})
    restored=alice.post('/api/tenants/restore-backup',data={'password':'long-backup-test-password','name':'Case restored'},files={'file':('backup.dms',response.content)})
    assert restored.status_code==200,restored.text
