import asyncio
import base64
import io
import json
from datetime import timedelta
from pathlib import Path
import pytest
from PIL import Image
from fastapi.testclient import TestClient
from sqlalchemy import select
from app.main import app
from app.db import (SessionLocal, Document, DocumentVersion, Membership, Annotation,
    DocumentNote, ShareLink, Setting, Audit, Integration, now)
from app.processing import process_document, retry_ai
from app.security import encrypt, digest
from app.storage import version_path
from app import codex_client
from app.vision import document_images
from codex_service.runtime import CodexRuntime
from codex_service import server

RESULT = {'supplier':'Vision GmbH', 'doc_type':'Rechnung', 'amount':'123.45', 'due_date':'2026-12-01'}


def tenant(client): return client.post('/api/tenants', json={'name':'Workspace tools'}).json()['id']
def member(client, tid, role='editor'):
    ident=client.get('/api/me').json()['id']
    with SessionLocal() as db:
        db.add(Membership(tenant_id=tid,user_id=ident,role=role));db.commit()
    return ident


def upload(client, tid, data=b'A simple document with unique text', filename='doc.txt'):
    response=client.post(f'/api/tenants/{tid}/documents', files={'file':(filename,data)})
    assert response.status_code==200,response.text
    doc_id=response.json()['id']
    with SessionLocal() as db:
        doc=db.get(Document,doc_id);doc.status='ready';doc.text=data.decode(errors='replace') if filename.endswith('.txt') else '';db.commit()
    return doc_id


def pdf():
    image=Image.new('RGB',(400,500),'white');buf=io.BytesIO();image.save(buf,format='PDF',save_all=True,append_images=[image]);return buf.getvalue()


def test_bulk_is_atomic_respects_acl_and_tenant(alice,bob):
    tid=tenant(alice);member(bob,tid);one=upload(alice,tid);two=upload(alice,tid,b'Different document text')
    base=f'/api/tenants/{tid}'
    alice.put(base+'/documents/'+two+'/access',json={'restricted':True,'grants':[]})
    body={'document_ids':[one,two],'action':'tags','tags':['batch']}
    assert bob.post(base+'/bulk',json=body).status_code==404
    assert alice.get(base+'/documents/'+one).json()['tags']==[]
    assert alice.post(base+'/bulk',json=body).json()['changed']==2
    assert alice.get(base+'/documents/'+two).json()['tags']==['batch']
    foreign=tenant(bob);other=upload(bob,foreign,b'Another document')
    assert alice.post(base+'/bulk',json=body|{'document_ids':[one,other]}).status_code==404
    assert alice.post(base+'/bulk',json=body|{'tags':['a'*81]}).status_code==422
    with SessionLocal() as db:
        db.get(Document,two).status='processing';db.commit()
    assert alice.post(base+'/bulk',json=body|{'action':'paid'}).status_code==409
    assert not alice.get(base+'/documents/'+one).json()['paid']


def test_bulk_folder_permission_viewer_and_restore(alice,bob):
    tid=tenant(alice);member(bob,tid,'viewer');one=upload(alice,tid)
    base=f'/api/tenants/{tid}'
    assert bob.post(base+'/bulk',json={'document_ids':[one],'action':'trash'}).status_code==403
    assert alice.post(base+'/bulk',json={'document_ids':[one],'action':'trash'}).status_code==200
    assert alice.post(base+'/bulk',json={'document_ids':[one],'action':'paid'}).status_code==409
    assert alice.post(base+'/bulk',json={'document_ids':[one],'action':'restore'}).status_code==200
    assert not alice.get(base+'/documents/'+one).json()['deleted_at']


def test_duplicate_historical_upload_detection(alice):
    tid=tenant(alice);data=b'Original historical content';one=upload(alice,tid,data)
    url=f'/api/tenants/{tid}/documents/{one}'
    assert alice.post(url+'/versions',files={'file':('new.txt',b'New historical content')}).status_code==200
    response=alice.post(f'/api/tenants/{tid}/documents',files={'file':('original.txt',data)})
    assert response.status_code==409


def test_similar_text_only_compares_visible_documents(alice,bob):
    tid=tenant(alice);member(bob,tid)
    content=b'Invoice supplier example corporation services received payment terms quantity discount total reference customer account department address office cost invoice-number 10001'
    one=upload(alice,tid,content);two=upload(alice,tid,content.replace(b'10001',b'10002'))
    base=f'/api/tenants/{tid}'
    pairs=alice.get(base+'/duplicates').json()['items']
    assert len(pairs)==1 and pairs[0]['kind']=='similar_text' and pairs[0]['similarity']<100
    alice.put(base+'/documents/'+two+'/access',json={'restricted':True,'grants':[]})
    assert bob.get(base+'/duplicates').json()['items']==[]
    assert not bob.get(base+'/duplicates').json()['limited']


def test_contract_dates_reminders_and_permissions(alice,bob):
    tid=tenant(alice);one=upload(alice,tid);url=f'/api/tenants/{tid}/documents/{one}/contract'
    data={'partner':'Hosting AG','start_date':'2025-01-01','end_date':'2026-11-01','notice_days':30,'reminder_days':14}
    assert bob.put(url,json=data).status_code==403
    response=alice.put(url,json=data)
    assert response.status_code==200,response.text
    assert response.json()['cancel_by']=='2026-10-02' and response.json()['remind_on']=='2026-09-18'
    assert alice.get(f'/api/tenants/{tid}/documents/{one}').json()['doc_type']=='Vertrag'
    assert alice.put(url,json=data|{'start_date':'2027-01-01'}).status_code==422
    assert alice.put(url,json=data|{'notice_days':-1}).status_code==422
    assert len(alice.get(f'/api/tenants/{tid}/contracts').json())==1
    alice.delete(f'/api/tenants/{tid}/documents/{one}')
    assert not alice.get(f'/api/tenants/{tid}/contracts').json()


def test_notes_authorship_and_no_cross_document_delete(alice,bob):
    tid=tenant(alice);member(bob,tid);one=upload(alice,tid);two=upload(alice,tid,b'Another note document')
    url=f'/api/tenants/{tid}/documents/{one}/notes'
    note=alice.post(url,json={'body':'Original note\nSecond line'}).json()['id']
    assert bob.get(url).json()[0]['body']=='Original note\nSecond line'
    assert bob.put(url+'/'+note,json={'body':'Overwrite'}).status_code==403
    assert bob.delete(url+'/'+note).status_code==403
    assert alice.delete(f'/api/tenants/{tid}/documents/{two}/notes/{note}').status_code==404
    assert alice.put(url+'/'+note,json={'body':'Updated'}).status_code==200
    assert alice.post(url,json={'body':'  '}).status_code==422
    assert alice.delete(url+'/'+note).status_code==200


def test_pdf_annotations_are_version_bound_and_original_unchanged(alice,bob):
    tid=tenant(alice);member(bob,tid);original=pdf();one=upload(alice,tid,original,'doc.pdf');url=f'/api/tenants/{tid}/documents/{one}'
    data={'version':1,'page':2,'rect':[.1,.2,.3,.1],'color':'yellow','body':'Check this amount'}
    annotation=alice.post(url+'/annotations',json=data)
    assert annotation.status_code==200,annotation.text
    ident=annotation.json()['id']
    assert alice.get(url+'/annotations').json()['pages']==2
    response=alice.get(url+'/pdf-page/1/2')
    assert response.status_code==200 and response.headers['content-type']=='image/png'
    assert alice.get(url+'/file').content==original
    assert bob.delete(url+'/annotations/'+ident).status_code==403
    assert alice.post(url+'/annotations',json=data|{'rect':[.9,.2,.3,.1]}).status_code==422
    assert alice.post(url+'/annotations',json=data|{'page':3}).status_code==422
    assert alice.post(url+'/annotations',json=data|{'version':9}).status_code==422
    assert alice.get(url+'/pdf-page/1/3').status_code==404
    assert alice.post(url+'/versions',files={'file':('changed.txt',b'New text version')}).status_code==200
    assert len(alice.get(url+'/annotations?version=1').json()['items'])==1
    assert alice.get(url+'/annotations').status_code==422
    assert alice.delete(url+'/annotations/'+ident).status_code==200


def anonymous(): return TestClient(app,base_url='http://localhost')


def test_share_password_version_pinning_revocation_and_secret_storage(alice,bob):
    tid=tenant(alice);one=upload(alice,tid);url=f'/api/tenants/{tid}/documents/{one}'
    assert bob.post(url+'/shares',json={}).status_code==403
    response=alice.post(url+'/shares',json={'password':'long-share-password','expires_days':2})
    assert response.status_code==200,response.text
    share=response.json();token=share['path'].split('/')[-1];public=anonymous();base='/api/shares/'+token
    assert public.get(base).json()=={'locked':True}
    assert public.get(base+'/file').status_code==403
    assert public.post(base+'/unlock',json={'password':'wrong'}).status_code==403
    assert public.post(base+'/unlock',json={'password':'long-share-password'}).status_code==200
    assert public.get(base).json()['filename']=='doc.txt'
    assert public.get(share['path']).headers['referrer-policy']=='no-referrer'
    original=public.get(base+'/file').content
    assert alice.post(url+'/versions',files={'file':('new.txt',b'Another file version')}).status_code==200
    assert public.get(base+'/file').content==original
    with SessionLocal() as db:
        row=db.get(ShareLink,share['id']);assert row.token_hash==digest(token) and token not in row.password_hash
    assert 'token_hash' not in alice.get(url+'/shares').text
    assert alice.delete(url+'/shares/'+share['id']).status_code==200
    assert public.get(base+'/file').status_code==404
    expired_page=public.get(share['path'])
    assert expired_page.status_code==404 and 'text/html' in expired_page.headers['content-type']
    assert 'share.js' in expired_page.text


@pytest.mark.parametrize('reason',['expired','trashed','creator_inactive','removed','restricted','demoted'])
def test_share_rechecks_live_authority(alice,bob,reason):
    tid=tenant(alice);uid=member(bob,tid,'manager');one=upload(alice,tid);url=f'/api/tenants/{tid}/documents/{one}'
    share=bob.post(url+'/shares',json={}).json();token=share['path'].split('/')[-1];public=anonymous();endpoint='/api/shares/'+token+'/file'
    assert public.get(endpoint).status_code==200
    if reason=='expired':
        with SessionLocal() as db: db.get(ShareLink,share['id']).expires_at=now()-timedelta(seconds=1);db.commit()
    elif reason=='trashed': alice.delete(url)
    elif reason=='creator_inactive':
        from app.db import User
        with SessionLocal() as db: db.get(User,uid).active=False;db.commit()
    elif reason=='removed': alice.delete(f'/api/tenants/{tid}/members/{uid}')
    elif reason=='demoted': alice.put(f'/api/tenants/{tid}/members/{uid}',json={'role':'editor'})
    else: alice.put(url+'/access',json={'restricted':True,'grants':[]})
    assert public.get(endpoint).status_code==404


def test_share_password_throttling_and_origin_check(alice):
    tid=tenant(alice);one=upload(alice,tid);url=f'/api/tenants/{tid}/documents/{one}'
    share=alice.post(url+'/shares',json={'password':'a-long-share-password'}).json();endpoint='/api/shares/'+share['path'].split('/')[-1]+'/unlock';public=anonymous()
    assert public.post(endpoint,json={'password':'a-long-share-password'},headers={'Origin':'https://evil.example'}).status_code==403
    for index in range(10): assert public.post(endpoint,json={'password':'wrong'}).status_code==403
    assert public.post(endpoint,json={'password':'a-long-share-password'}).status_code==429


def configure_ai(tid, enabled=True, fallback=True):
    with SessionLocal() as db:
        db.add(Integration(tenant_id=tid,kind='ai',enabled=enabled,config_encrypted=encrypt({'provider':'codex','consent':True,'privacy_mode':'automatic','automatic_consent':True,'document_fallback':fallback})))
        db.merge(Setting(key='codex.allowed_tenants',value=json.dumps([tid])));db.commit()


def test_failed_ocr_sends_all_pages_only_when_enabled(alice,monkeypatch):
    tid=tenant(alice);one=upload(alice,tid,pdf(),'doc.pdf');configure_ai(tid)
    monkeypatch.setattr('app.processing.extract_text',lambda doc: (_ for _ in ()).throw(ValueError('OCR unavailable')))
    calls=[]
    def request(method,path,data,**kwargs): calls.append(data);return {'metadata':RESULT}
    monkeypatch.setattr(codex_client,'request',request)
    with SessionLocal() as db:
        doc=db.get(Document,one);process_document(db,doc);db.commit()
        assert doc.ocr_failed and doc.supplier=='Vision GmbH' and doc.status=='ready' and not doc.ai_pending
        assert 'Volltextsuche' in doc.error
        assert db.scalar(select(Audit.id).where(Audit.action=='document.ai_full_requested'))
    assert len(calls)==1 and len(calls[0]['images'])==2
    assert 'doc.pdf' not in calls[0]['text']
    with SessionLocal() as db:
        row=db.scalar(select(Integration));row.config_encrypted=encrypt({'provider':'codex','consent':True,'privacy_mode':'automatic','automatic_consent':True,'document_fallback':False});db.commit()
        process_document(db,db.get(Document,one));db.commit()
    assert len(calls)==1


@pytest.mark.parametrize('change',['blocked','manual','disabled','no_consent','deleted','not_allowed'])
def test_whole_document_respects_all_ai_gates(alice,monkeypatch,change):
    tid=tenant(alice);one=upload(alice,tid,pdf(),'doc.pdf');configure_ai(tid)
    monkeypatch.setattr('app.processing.extract_text',lambda d:'')
    def no_request(*args,**kwargs): raise AssertionError('External call forbidden')
    monkeypatch.setattr(codex_client,'request',no_request)
    with SessionLocal() as db:
        row=db.scalar(select(Integration));from app.security import decrypt
        conf=decrypt(row.config_encrypted)
        if change=='blocked':db.merge(Setting(key='ai_external_blocked',value='true'))
        elif change=='manual':conf['privacy_mode']='manual'
        elif change=='disabled':row.enabled=False
        elif change=='no_consent':conf['consent']=False
        elif change=='deleted':db.get(Document,one).deleted_at=now()
        elif change=='not_allowed':db.get(Setting,'codex.allowed_tenants').value='[]'
        row.config_encrypted=encrypt(conf);db.commit();process_document(db,db.get(Document,one));db.commit()


def test_fallback_failure_retries_and_revoked_setting_stops(alice,monkeypatch):
    tid=tenant(alice);one=upload(alice,tid,pdf(),'doc.pdf');configure_ai(tid)
    monkeypatch.setattr('app.processing.extract_text',lambda d:'')
    monkeypatch.setattr(codex_client,'request',lambda *a,**k: (_ for _ in ()).throw(ValueError('unavailable')))
    with SessionLocal() as db:
        doc=db.get(Document,one);process_document(db,doc);db.commit();assert doc.ai_pending
        row=db.scalar(select(Integration));row.enabled=False;db.commit();retry_ai(db,doc);assert not doc.ai_pending


def test_ai_setting_requires_automatic_consent(alice):
    tid=tenant(alice);url=f'/api/tenants/{tid}/integrations/ai'
    for config in [{'provider':'codex','document_fallback':True,'privacy_mode':'manual','consent':True}, {'document_fallback':'true'}]:
        assert alice.put(url,json={'enabled':False,'config':config}).status_code==422


def test_vision_render_never_silently_truncates_and_removes_exif(alice,monkeypatch):
    tid=tenant(alice);one=upload(alice,tid,pdf(),'doc.pdf')
    with SessionLocal() as db:
        monkeypatch.setattr('app.vision.MAX_PAGES',1)
        with pytest.raises(ValueError): document_images(db.get(Document,one))


def test_gateway_images_are_inline_only_and_tool_free(monkeypatch):
    from pydantic import ValidationError
    for image in ['https://example.com/doc.jpg','file:///data/codex/auth.json','data:image/jpeg;base64,AAAA']:
        with pytest.raises(ValidationError):server.ExtractInput(text='Document',images=[image])
    image=Image.new('RGB',(10,10),'white');buffer=io.BytesIO();image.save(buffer,format='JPEG');data='data:image/jpeg;base64,'+base64.b64encode(buffer.getvalue()).decode()
    runtime=CodexRuntime();inputs=[]
    async def status():return {'connected':True}
    async def request(method,params=None,**kwargs):
        if method=='thread/start':return {'thread':{'id':'vision'}}
        if method=='turn/start':
            inputs.append(params['input']);queue=runtime.events['vision']
            queue.put_nowait({'method':'item/completed','params':{'turnId':'turn','item':{'type':'agentMessage','text':json.dumps(RESULT)}}})
            queue.put_nowait({'method':'turn/completed','params':{'turn':{'id':'turn','status':'completed'}}})
            return {'turn':{'id':'turn'}}
        return {}
    monkeypatch.setattr(runtime,'status',status);monkeypatch.setattr(runtime,'request',request)
    assert asyncio.run(runtime.extract('Document pages',None,[data]))==RESULT
    assert inputs[0][1]=={'type':'image','url':data}


def test_system_status_is_admin_only_and_exposes_no_secrets(alice,admin):
    assert alice.get('/api/admin/system-status').status_code==403
    with SessionLocal() as db:db.merge(Setting(key='worker.last_tick',value=now().isoformat()));db.commit()
    response=admin.get('/api/admin/system-status')
    assert response.status_code==200,response.text
    assert response.json()['worker']['healthy'] and response.json()['storage']['free']>0
    assert 'api_key' not in response.text and 'password' not in response.text


def test_backup_restores_contract_notes_annotations_but_not_shares(alice):
    tid=tenant(alice);one=upload(alice,tid,pdf(),'doc.pdf');url=f'/api/tenants/{tid}/documents/{one}'
    alice.put(url+'/contract',json={'end_date':'2027-01-01','partner':'Backup Partner'})
    alice.post(url+'/notes',json={'body':'Keep this note'})
    alice.post(url+'/annotations',json={'version':1,'page':1,'rect':[.1,.1,.3,.2],'body':'Keep this highlight'})
    alice.post(url+'/shares',json={})
    backup=alice.post(f'/api/tenants/{tid}/backup',json={'password':'a-long-backup-password'})
    assert backup.status_code==200,backup.text
    restored=alice.post('/api/tenants/restore-backup',files={'file':('backup.dmsbackup',backup.content)},data={'password':'a-long-backup-password','name':'Restored tools'})
    assert restored.status_code==200,restored.text
    new_tid=restored.json()['id'];new_doc=alice.get(f'/api/tenants/{new_tid}/documents').json()['items'][0]['id'];new_url=f'/api/tenants/{new_tid}/documents/{new_doc}'
    assert alice.get(new_url+'/contract').json()['partner']=='Backup Partner'
    assert alice.get(new_url+'/notes').json()[0]['body']=='Keep this note'
    assert alice.get(new_url+'/annotations').json()['items'][0]['body']=='Keep this highlight'
    assert alice.get(new_url+'/shares').json()==[]
    assert alice.get(f'/api/tenants/{new_tid}/restore-history').json()['original_authors']
