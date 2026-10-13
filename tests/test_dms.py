import io
import json
from datetime import date
from pathlib import Path
import pytest
from sqlalchemy import select
from PIL import Image, ImageDraw, ImageFont
from fastapi.testclient import TestClient
from app.main import app
from app.db import SessionLocal, Document, Integration, Membership, User, Setting, LoginSession
from app.security import encrypt, decrypt
from app.storage import path_for, ROOT
from app.processing import process_document, extract_text, ai_metadata
from app.worker import tick


def tenant(client, name='Archiv'):
    r=client.post('/api/tenants',json={'name':name})
    assert r.status_code==200,r.text
    return r.json()['id']


def upload(client, tid, content=b'Rechnung\nGesamtbetrag: 125,50 EUR\nFaellig am: 01.12.2026\nArchiv Test\n', filename='rechnung.txt'):
    r=client.post(f'/api/tenants/{tid}/documents',files={'file':(filename,content,'text/plain')})
    assert r.status_code==200,r.text
    return r.json()


def metadata(doc, **updates):
    data={k:doc[k] for k in ['title','folder_id','supplier','doc_type','tags','amount','due_date','paid']}
    return data|updates


def test_tenant_isolation_across_all_document_paths(alice,bob,admin):
    a=tenant(alice,'A');b=tenant(bob,'B');doc=upload(alice,a)
    for client in [bob,admin]:
        for suffix in ['/documents','/documents/'+doc['id'],'/documents/'+doc['id']+'/file','/folders','/stats','/rules','/audit','/members','/integrations']:
            assert client.get(f'/api/tenants/{a}'+suffix).status_code==403
        assert client.post(f'/api/tenants/{a}/documents',files={'file':('x.txt',b'secret')}).status_code==403
    assert bob.get(f'/api/tenants/{b}/documents/'+doc['id']).status_code==404
    assert bob.get(f'/api/tenants/{b}/documents/'+doc['id']+'/file').status_code==404
    foreign_folder=alice.get(f'/api/tenants/{a}/folders').json()[0]['id']
    d=upload(bob,b,b'Different document text')
    assert bob.put(f'/api/tenants/{b}/documents/'+d['id'],json=metadata(d,folder_id=foreign_folder)).status_code==404


def test_invitation_and_reader_permissions(alice,bob):
    a=tenant(alice);doc=upload(alice,a)
    invite=alice.post(f'/api/tenants/{a}/invitations',json={'email':'bob@example.com','role':'viewer'}).json()
    assert bob.post('/api/invitations/accept',json={'token':invite['token']}).status_code==200
    bob.headers['X-CSRF-Token']=bob.cookies['dms_csrf']
    assert bob.get(f'/api/tenants/{a}/documents').json()['total']==1
    assert bob.get(f'/api/tenants/{a}/documents/'+doc['id']+'/file').content.startswith(b'Rechnung')
    assert bob.delete(f'/api/tenants/{a}/documents/'+doc['id']).status_code==403
    assert bob.post(f'/api/tenants/{a}/documents',files={'file':('x.txt',b'Test')}).status_code==403
    assert bob.post(f'/api/tenants/{a}/folders',json={'name':'X'}).status_code==403
    assert bob.get(f'/api/tenants/{a}/integrations').status_code==403
    assert bob.post('/api/invitations/accept',json={'token':invite['token']}).status_code==404


def test_new_account_from_invite_and_email_binding(alice,bob):
    a=tenant(alice)
    invitation=alice.post(f'/api/tenants/{a}/invitations',json={'email':'new@example.com','role':'editor'}).json()
    client=TestClient(app,base_url='http://localhost')
    assert client.post('/api/invitations/accept',json={'token':invitation['token'],'name':'New','password':'secure-new-password'}).status_code==200
    assert client.get('/api/me').json()['tenants'][0]['role']=='editor'
    inv2=alice.post(f'/api/tenants/{a}/invitations',json={'email':'alice@example.com','role':'viewer'}).json()
    assert bob.post('/api/invitations/accept',json={'token':inv2['token']}).status_code==403


def test_ocr_rules_search_and_immutable_original(alice):
    tid=tenant(alice)
    folders=alice.get(f'/api/tenants/{tid}/folders').json()
    folder=next(f['id'] for f in folders if f['name']=='Rechnungen')
    assert alice.post(f'/api/tenants/{tid}/rules',json={'name':'Rechnungen','field':'doc_type','contains':'rechnung','folder_id':folder}).status_code==200
    raw='Rechnung\nLieferant Beispiel GmbH\nGesamtbetrag: 125,50 EUR\nFällig am: 01.12.2026\n'.encode()
    doc=upload(alice,tid,raw)
    assert tick() is True
    processed=alice.get(f'/api/tenants/{tid}/documents/'+doc['id']).json()
    assert processed['status']=='ready'
    assert processed['doc_type']=='Rechnung'
    assert processed['due_date']=='2026-12-01'
    assert processed['amount']=='125.50'
    assert processed['folder_id']==folder
    assert alice.get(f'/api/tenants/{tid}/documents?q=beispiel').json()['total']==1
    assert alice.get(f'/api/tenants/{tid}/documents/'+doc['id']+'/file').content==raw
    assert alice.get(f'/api/tenants/{tid}/stats').json()['types']['Rechnung']==1
    assert alice.get(f'/api/tenants/{tid}/audit').json()[0]['action']=='document.processed'


def test_image_ocr_with_tesseract(alice):
    tid=tenant(alice)
    image=Image.new('RGB',(1200,400),'white')
    draw=ImageDraw.Draw(image)
    font=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',42)
    draw.text((60,60),'RECHNUNG\nGesamtbetrag: 150,00 EUR\nArchivraum OCR Test',fill='black',font=font,spacing=20)
    out=io.BytesIO();image.save(out,format='PNG')
    doc=upload(alice,tid,out.getvalue(),'scan.png')
    assert tick() is True
    result=alice.get(f'/api/tenants/{tid}/documents/'+doc['id']).json()
    assert result['status']=='ready'
    assert 'RECHNUNG' in result['text']
    assert result['doc_type']=='Rechnung'


def test_duplicates_trash_restore_and_quota(alice,admin):
    tid=tenant(alice);doc=upload(alice,tid)
    assert alice.post(f'/api/tenants/{tid}/documents',files={'file':('same.txt',b'Rechnung\nGesamtbetrag: 125,50 EUR\nFaellig am: 01.12.2026\nArchiv Test\n')}).status_code==409
    assert alice.delete(f'/api/tenants/{tid}/documents/'+doc['id']).status_code==200
    assert alice.get(f'/api/tenants/{tid}/documents').json()['total']==0
    assert alice.get(f'/api/tenants/{tid}/documents?trash=true').json()['total']==1
    assert alice.post(f'/api/tenants/{tid}/documents/'+doc['id']+'/restore').status_code==200
    assert alice.get(f'/api/tenants/{tid}/documents').json()['total']==1
    assert admin.put(f'/api/admin/tenants/{tid}/quota',json={'quota_mb':1}).status_code==200
    assert alice.post(f'/api/tenants/{tid}/documents',files={'file':('big.txt',b'x'*1100000)}).status_code==413


def test_host_csrf_sessions_and_password_change(alice):
    assert alice.post('/api/tenants',json={'name':'Bad'},headers={'X-CSRF-Token':''}).status_code==403
    assert alice.post('/api/tenants',json={'name':'Bad'},headers={'Origin':'https://evil.example.com'}).status_code==403
    assert alice.get('/api/public',headers={'Host':'evil.example.com'}).status_code==400
    token=alice.cookies['dms_session']
    assert alice.put('/api/me/password',json={'current_password':'a-secure-test-password','password':'replacement-password'}).status_code==200
    stale=TestClient(app,base_url='http://localhost');stale.cookies['dms_session']=token
    assert stale.get('/api/me').status_code==401
    alice.headers['X-CSRF-Token']=alice.cookies['dms_csrf']
    assert alice.post('/api/auth/logout').status_code==200
    assert alice.get('/api/me').status_code==401


def test_last_owner_and_privilege_escalation(alice,bob):
    tid=tenant(alice);aid=alice.get('/api/me').json()['id']
    assert alice.put(f'/api/tenants/{tid}/members/{aid}',json={'role':'viewer'}).status_code==409
    assert alice.delete(f'/api/tenants/{tid}/members/{aid}').status_code==403
    invitation=alice.post(f'/api/tenants/{tid}/invitations',json={'email':'bob@example.com','role':'manager'}).json()
    bob.post('/api/invitations/accept',json={'token':invitation['token']});bob.headers['X-CSRF-Token']=bob.cookies['dms_csrf']
    bid=bob.get('/api/me').json()['id']
    assert bob.put(f'/api/tenants/{tid}/members/{bid}',json={'role':'owner'}).status_code==403
    assert bob.post(f'/api/tenants/{tid}/invitations',json={'email':'third@example.com','role':'manager'}).status_code==403
    assert bob.delete(f'/api/tenants/{tid}/members/{aid}').status_code==403


def test_magic_detection_safe_filename_and_no_script_preview(alice):
    tid=tenant(alice)
    doc=upload(alice,tid,b'Plain safe text document','../../etc/passwd.txt')
    assert doc['filename']=='passwd.txt'
    assert path_for(tid,doc['id']).is_relative_to(ROOT)
    assert alice.post(f'/api/tenants/{tid}/documents',files={'file':('fake.pdf',b'<html><script>alert(1)</script></html>','application/pdf')}).status_code==415
    assert alice.get(f'/api/tenants/{tid}/documents/'+doc['id']+'/file').headers['cache-control']=='no-store'


def test_admin_settings_domains_and_account_suspension(alice,admin):
    assert alice.get('/api/admin').status_code==403
    assert admin.put('/api/admin/settings',json={'app_name':'Mein DMS','registration_enabled':False,'tenant_creation_enabled':False}).status_code==200
    assert admin.get('/api/public').json()['app_name']=='Mein DMS'
    assert alice.post('/api/tenants',json={'name':'No'}).status_code==403
    assert admin.post('/api/admin/domains',json={'host':'archiv.example.com'}).status_code==200
    assert admin.get('/api/public',headers={'Host':'archiv.example.com'}).status_code==200
    aid=alice.get('/api/me').json()['id']
    assert admin.post('/api/admin/users/'+aid+'/toggle').status_code==200
    assert alice.get('/api/me').status_code==401


def test_encrypted_integration_secrets_and_ai_opt_in(alice,monkeypatch):
    tid=tenant(alice)
    assert alice.put(f'/api/tenants/{tid}/integrations/ai',json={'enabled':True,'config':{'api_key':'super-secret','model':'test-model','consent':False}}).status_code==422
    assert alice.put(f'/api/tenants/{tid}/integrations/ai',json={'enabled':True,'config':{'api_key':'super-secret','model':'test-model','consent':True,'privacy_mode':'automatic','automatic_consent':True}}).status_code==200
    result=alice.get(f'/api/tenants/{tid}/integrations').json()[0]
    assert result['config']['api_key']=='••••••••'
    with SessionLocal() as db:
        config=db.scalar(select(Integration).where(Integration.tenant_id==tid))
        assert 'super-secret' not in config.config_encrypted
        assert decrypt(config.config_encrypted)['api_key']=='super-secret'
    doc=upload(alice,tid)
    import httpx
    real_client=httpx.Client
    calls=[]
    def handler(request):
        payload=json.loads(request.content);calls.append(payload)
        assert payload['store'] is False
        assert payload['text']['format']['type']=='json_schema'
        return httpx.Response(200,json={'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':json.dumps({'supplier':'Beispiel GmbH','doc_type':'Rechnung','amount':'125.50','due_date':'2026-12-01'})}]}]})
    monkeypatch.setattr(httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(handler),**kwargs))
    with SessionLocal() as db:
        d=db.get(Document,doc['id']);d.text='Rechnung supplier text';ai_metadata(db,d);db.commit()
        assert d.supplier=='Beispiel GmbH'
    assert len(calls)==1


def test_registration_disabled_and_login_rate_limit():
    client=TestClient(app,base_url='http://localhost')
    assert client.post('/api/auth/register',json={'email':'x@example.com','name':'X','password':'secure-long-password'}).status_code==403
    for _ in range(20):
        assert client.post('/api/auth/login',json={'email':'missing@example.com','password':'wrong'}).status_code==401
    assert client.post('/api/auth/login',json={'email':'missing@example.com','password':'wrong'}).status_code==429


def test_pdf_ocr_and_failed_ai_preserves_text(alice, monkeypatch):
    tid=tenant(alice)
    image=Image.new('RGB',(1200,450),'white')
    draw=ImageDraw.Draw(image)
    font=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',42)
    draw.text((80,80),'RECHNUNG\nGesamtbetrag: 175,00 EUR',fill='black',font=font,spacing=30)
    out=io.BytesIO();image.save(out,format='PDF',resolution=150)
    doc=upload(alice,tid,out.getvalue(),'scan.pdf')
    def fail(*args):raise ValueError('KI-Ausfall')
    monkeypatch.setattr('app.processing.ai_metadata', fail)
    assert tick() is True
    result=alice.get(f'/api/tenants/{tid}/documents/'+doc['id']).json()
    assert result['status']=='ready' and result['ai_pending']
    assert 'RECHNUNG' in result['text']
    assert result['amount']=='175.00'


def test_imap_import_is_repeatable_without_modifying_mail(alice, monkeypatch):
    from email.message import EmailMessage
    from app.integrations import run_integration_once
    tid=tenant(alice)
    message=EmailMessage();message['Subject']='IMAP test';message.set_content('Test body')
    message.add_attachment(b'Eine Rechnung aus der Mail',maintype='text',subtype='plain',filename='rechnung.txt')
    raw=message.as_bytes()
    class FakeIMAP:
        def __init__(self,*a,**kw):pass
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def login(self,username,password):assert username=='user' and password=='secret';self.authenticated=True;return 'OK',[]
        def select(self,folder,readonly):assert self.authenticated and readonly is True;return 'OK',[]
        def response(self,key):return 'UIDVALIDITY',[b'12345']
        def uid(self,command,*args):
            if command=='search':return 'OK',[b'1']
            if args[1]=='(RFC822.SIZE)':return 'OK',[b'1 (RFC822.SIZE '+str(len(raw)).encode()+b')']
            assert args[1]=='(BODY.PEEK[])'
            return 'OK',[(b'RFC822',raw)]
    monkeypatch.setattr('imaplib.IMAP4_SSL',FakeIMAP)
    with SessionLocal() as db:
        i=Integration(tenant_id=tid,kind='imap',enabled=True,config_encrypted=encrypt({'host':'imap.example.com','username':'user','password':'secret'}));db.add(i);db.commit()
        assert run_integration_once(db,i)=='1 Dokumente importiert.'
        assert run_integration_once(db,i)=='0 Dokumente importiert.'
    assert alice.get(f'/api/tenants/{tid}/documents').json()['total']==1
    assert alice.get(f'/api/tenants/{tid}/documents').json()['items'][0]['source']=='email'


def test_caldav_stable_uid_and_removal_when_paid(alice,monkeypatch):
    from app.integrations import run_integration_once
    from icalendar import Calendar
    import caldav
    tid=tenant(alice);doc=upload(alice,tid)
    alice.put(f'/api/tenants/{tid}/documents/'+doc['id'],json=metadata(doc,due_date='2026-12-01',amount='100.00'))
    saved={};deleted=[]
    class FakeCalendar:
        def save_event(self,value):
            event=Calendar.from_ical(value).walk('VEVENT')[0];saved[str(event['UID'])]=event
        def event_by_uid(self,uid):
            class Event:
                def delete(self):deleted.append(uid);saved.pop(uid)
            return Event()
    class FakeClient:
        def __init__(self,*a,**kw):pass
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def calendar(self,**kw):return FakeCalendar()
    monkeypatch.setattr(caldav,'DAVClient',FakeClient)
    with SessionLocal() as db:
        i=Integration(tenant_id=tid,kind='caldav',enabled=True,config_encrypted=encrypt({'url':'https://calendar.example.com/dms/','username':'user','password':'secret'}));db.add(i);db.commit()
        assert run_integration_once(db,i)=='1 Fälligkeiten synchronisiert.'
        assert run_integration_once(db,i)=='1 Fälligkeiten synchronisiert.'
        assert len(saved)==1
        d=db.get(Document,doc['id']);d.paid=True;db.commit()
        assert run_integration_once(db,i)=='0 Fälligkeiten synchronisiert.'
    assert len(deleted)==1
    assert not saved


def test_external_identities_cannot_claim_existing_local_email(alice):
    from app.auth import external_user
    from fastapi import HTTPException
    with SessionLocal() as db:
        with pytest.raises(HTTPException):
            external_user(db,'oidc:issuer','attacker-sub','alice@example.com','X')
        with pytest.raises(HTTPException):
            external_user(db,'ldap:server','attacker-dn','alice@example.com','X')
        assert not db.scalar(select(__import__('app.db',fromlist=['Identity']).Identity))


def test_rule_edit_and_trash_counts_against_quota(alice):
    tid=tenant(alice);doc=upload(alice,tid)
    folder=alice.get(f'/api/tenants/{tid}/folders').json()[0]['id']
    rule={'name':'Match','field':'title','contains':'rechnung','folder_id':folder}
    rid=alice.post(f'/api/tenants/{tid}/rules',json=rule).json()['id']
    assert alice.put(f'/api/tenants/{tid}/rules/'+rid,json=rule|{'enabled':False}).status_code==200
    assert alice.get(f'/api/tenants/{tid}/rules').json()[0]['enabled'] is False
    alice.delete(f'/api/tenants/{tid}/documents/'+doc['id'])
    stats=alice.get(f'/api/tenants/{tid}/stats').json()
    assert stats['documents']==0 and stats['bytes']==doc['size']


def test_configurable_pwa_name(admin):
    admin.put('/api/admin/settings',json={'app_name':'Test-DMS','registration_enabled':False,'tenant_creation_enabled':True})
    assert admin.get('/manifest.webmanifest').json()['name']=='Test-DMS'


def test_oidc_state_pkce_signature_and_login(monkeypatch):
    import time
    import hashlib
    import base64
    import httpx
    from urllib.parse import urlparse, parse_qs
    from authlib.jose import JsonWebKey, jwt
    key=JsonWebKey.generate_key('RSA',2048,is_private=True,options={'kid':'test'})
    state={}
    issuer='https://id.example.com'
    config={'discovery_url':issuer+'/.well-known/openid-configuration','client_id':'dms-client','client_secret':'secret','redirect_uri':'http://localhost/api/auth/oidc/callback'}
    with SessionLocal() as db:
        db.merge(Setting(key='oidc',value=encrypt(config)))
        db.merge(Setting(key='registration_enabled',value='false'));db.commit()
    def handler(request):
        if request.url.path=='/.well-known/openid-configuration':
            return httpx.Response(200,json={'issuer':issuer,'authorization_endpoint':issuer+'/authorize','token_endpoint':issuer+'/token','jwks_uri':issuer+'/jwks','response_types_supported':['code'],'subject_types_supported':['public'],'id_token_signing_alg_values_supported':['RS256']})
        if request.url.path=='/jwks':return httpx.Response(200,json={'keys':[key.as_dict(is_private=False)]})
        if request.url.path=='/token':
            body=parse_qs(request.content.decode())
            verifier=body['code_verifier'][0]
            assert base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')==state['challenge']
            claims={'iss':issuer,'sub':'oidc-user-123','aud':'dms-client','exp':int(time.time())+600,'iat':int(time.time()),'nonce':state['nonce'],'email':'oidc-new@example.com','email_verified':True,'name':'OIDC Test'}
            token=jwt.encode({'alg':'RS256','kid':'test'},claims,key).decode()
            return httpx.Response(200,json={'access_token':'access','token_type':'Bearer','id_token':token})
        raise AssertionError('Unexpected OIDC request')
    original=httpx.AsyncClient.__init__
    def patched(self,*args,**kwargs):kwargs['transport']=httpx.MockTransport(handler);return original(self,*args,**kwargs)
    monkeypatch.setattr(httpx.AsyncClient,'__init__',patched)
    client=TestClient(app,base_url='http://localhost')
    start=client.get('/api/auth/oidc',follow_redirects=False)
    assert start.status_code==302
    params=parse_qs(urlparse(start.headers['location']).query)
    state.update(nonce=params['nonce'][0],challenge=params['code_challenge'][0])
    assert params['code_challenge_method']==['S256']
    bad=client.get('/api/auth/oidc/callback?code=x&state=invalid',follow_redirects=False)
    assert bad.headers['location']=='/?auth_error=1'
    result=client.get('/api/auth/oidc/callback?code=valid&state='+params['state'][0],follow_redirects=False)
    assert result.headers['location']=='/'
    assert client.get('/api/me').json()['email']=='oidc-new@example.com'


def test_ldap_tls_authentication_and_invited_account(alice,monkeypatch):
    from types import SimpleNamespace
    import ssl
    tid=tenant(alice)
    invitation=alice.post(f'/api/tenants/{tid}/invitations',json={'email':'ldap-new@example.com','role':'editor'}).json()
    config={'host':'ldap.example.com','port':636,'transport':'ldaps','base_dn':'DC=example,DC=com','bind_dn':'CN=reader','bind_password':'bind-secret','filter':'(mail={email})'}
    with SessionLocal() as db:db.merge(Setting(key='ldap',value=encrypt(config)));db.commit()
    class FakeConnection:
        def __init__(self,server,user,password,**kwargs):
            assert server.ssl is True and server.tls.validate==ssl.CERT_REQUIRED
            if user=='CN=reader':assert password=='bind-secret'
            else:assert user=='CN=New User,DC=example,DC=com' and password=='ldap-password'
            self.entries=[]
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def search(self,base,filter,**kwargs):
            assert base=='DC=example,DC=com' and filter=='(mail=ldap-new@example.com)'
            self.entries=[SimpleNamespace(entry_dn='CN=New User,DC=example,DC=com',mail=SimpleNamespace(value='ldap-new@example.com'),displayName=SimpleNamespace(value='LDAP New'))]
    monkeypatch.setattr('app.auth.Connection',FakeConnection)
    client=TestClient(app,base_url='http://localhost')
    result=client.post('/api/auth/login',json={'email':'ldap-new@example.com','password':'ldap-password','method':'ldap'})
    assert result.status_code==200,result.text
    assert client.post('/api/invitations/accept',json={'token':invitation['token']}).status_code==200
    assert client.get('/api/me').json()['tenants'][0]['role']=='editor'


def test_request_limits_before_parsing_and_chunked_json():
    client=TestClient(app,base_url='http://localhost')
    large='x'*(2*1024*1024)
    assert client.post('/api/auth/login',content=large,headers={'Content-Type':'application/json'}).status_code==413
    assert client.post('/api/auth/login',content=iter([large.encode()]),headers={'Content-Type':'application/json'}).status_code==413


def test_loopback_health_with_only_production_domains(monkeypatch):
    monkeypatch.setenv('ALLOWED_HOSTS','dms.example.org')
    client=TestClient(app,base_url='http://127.0.0.1',client=('127.0.0.1',45000))
    assert client.get('/api/health').status_code==200
    assert client.get('/api/public').status_code==400
