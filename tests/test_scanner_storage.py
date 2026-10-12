import ftplib
import io
import os
import threading
import time
from pathlib import Path
import paramiko
import pytest
from sqlalchemy import select
from app.db import SessionLocal, Integration
from app.security import decrypt
from app import folder_import, scanner_service as service, storage_control


@pytest.fixture
def scanner(alice, tmp_path, monkeypatch):
    consume = tmp_path/'consume'; consume.mkdir()
    monkeypatch.setattr(folder_import, 'ROOT', consume)
    monkeypatch.setattr(service, 'STATE', tmp_path/'scanner')
    monkeypatch.setattr(service, 'ATTEMPTS', {})
    tenant = alice.post('/api/tenants', json={'name':'Scanner workspace'}).json()['id']
    return tenant, consume


def enable(alice, tenant, protocol='sftp'):
    result = alice.put(f'/api/tenants/{tenant}/scanner', json={'enabled':True,'protocol':protocol,'ftp_confirmed':protocol=='ftp'})
    assert result.status_code == 200, result.text
    return result.json()


@pytest.fixture
def sftp_server():
    listener = service.start_sftp(paramiko.RSAKey.generate(2048), port=0, host='127.0.0.1')
    yield listener.getsockname()[1]
    listener.close()


def sftp(port, credentials):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('127.0.0.1', port=port, username=credentials['username'], password=credentials['password'], look_for_keys=False, allow_agent=False, timeout=5)
    return client, client.open_sftp()


@pytest.fixture
def ftp_server():
    class Handler(service.FTPInbox):
        passive_ports = None
        masquerade_address = '127.0.0.1'
        auth_failed_timeout = 0
    server = service.ThreadedFTPServer(('127.0.0.1',0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'timeout':0.1, 'handle_exit':False}, daemon=True)
    thread.start()
    yield server.socket.getsockname()[1]
    server.close_all(); thread.join(timeout=3)


def ftp(port, credentials):
    client = ftplib.FTP(); client.connect('127.0.0.1', port, timeout=5)
    client.login(credentials['username'],credentials['password'])
    client.cwd('/eingang')
    return client


def test_provisioning_owner_and_encrypted_credentials(alice, bob, scanner):
    tenant, _ = scanner
    assert bob.get(f'/api/tenants/{tenant}/scanner').status_code == 403
    data = enable(alice,tenant)
    assert data['protocol']=='sftp' and len(data['password'])>=24
    assert data['password'] not in data['url']
    with SessionLocal() as db:
        row=db.scalar(select(Integration).where(Integration.tenant_id==tenant,Integration.kind=='scanner'))
        assert data['password'] not in row.config_encrypted
        assert decrypt(row.config_encrypted)['password_hash'].startswith('$argon2')
    assert not any(i['kind']=='scanner' for i in alice.get(f'/api/tenants/{tenant}/integrations').json())
    assert bob.post(f'/api/tenants/{tenant}/scanner/rotate').status_code==403


def test_ftp_requires_explicit_confirmation_and_admin_can_disable(alice,admin,scanner):
    tenant,_=scanner
    assert alice.put(f'/api/tenants/{tenant}/scanner',json={'enabled':True,'protocol':'ftp'}).status_code==422
    assert admin.put('/api/admin/scanner',json={'host':'scanner.example.com','ftp_allowed':False}).status_code==200
    assert alice.put(f'/api/tenants/{tenant}/scanner',json={'enabled':True,'protocol':'ftp','ftp_confirmed':True}).status_code==403
    data=enable(alice,tenant)
    assert data['host']=='scanner.example.com'
    assert alice.put('/api/admin/scanner',json={'host':'evil.example.com'}).status_code==403


def test_sftp_complete_file_imports_then_source_removed(alice,scanner,sftp_server):
    tenant,consume=scanner;credentials=enable(alice,tenant)
    client,channel=sftp(sftp_server,credentials)
    content=b'Synthetic invoice supplier Scanner Test GmbH amount 123.45'
    try:
        channel.putfo(io.BytesIO(content),'/eingang/invoice.txt')
        source=consume/tenant/'eingang'/'invoice.txt'
        assert source.read_bytes()==content
        os.utime(source,(time.time()-10,time.time()-10))
        result=alice.post(f'/api/tenants/{tenant}/integrations/folder/run')
        assert result.status_code==200,result.text
        assert not source.exists()
        items=alice.get(f'/api/tenants/{tenant}/documents').json()['items']
        assert len(items)==1 and items[0]['source']=='scanner'
    finally: channel.close();client.close()


def test_sftp_aborted_upload_and_shell_are_denied(alice,scanner,sftp_server):
    tenant,consume=scanner;credentials=enable(alice,tenant)
    client,channel=sftp(sftp_server,credentials)
    upload=channel.open('/eingang/partial.txt','w');upload.write(b'not complete')
    assert not (consume/tenant/'eingang'/'partial.txt').exists()
    channel.close();client.close()
    deadline=time.time()+3
    while time.time()<deadline and list((service.STATE/'staging'/tenant).glob('*.part')): time.sleep(.05)
    assert not list((consume/tenant/'eingang').iterdir())
    assert not list((service.STATE/'staging'/tenant).glob('*.part'))
    client,channel=sftp(sftp_server,credentials)
    try:
        with pytest.raises(paramiko.SSHException): client.exec_command('cat /etc/passwd')
        with pytest.raises(OSError): channel.open('/../outside.txt','w')
        with pytest.raises(OSError): channel.open('/eingang/document.txt','r')
    finally: channel.close();client.close()


def test_sftp_rotation_revokes_open_transfer_and_old_login(alice,scanner,sftp_server):
    tenant,consume=scanner;credentials=enable(alice,tenant)
    client,channel=sftp(sftp_server,credentials)
    upload=channel.open('/eingang/rotated.txt','w');upload.write(b'before rotation')
    new=alice.post(f'/api/tenants/{tenant}/scanner/rotate').json()
    assert new['password']!=credentials['password']
    with pytest.raises(OSError): upload.write(b'after rotation')
    # Paramiko deliberately suppresses CLOSE errors; inspect the protocol reply.
    from paramiko.sftp import CMD_CLOSE
    with pytest.raises(OSError): channel._request(CMD_CLOSE, upload.handle)
    upload.close()
    channel.close();client.close()
    assert not (consume/tenant/'eingang'/'rotated.txt').exists()
    with pytest.raises(paramiko.AuthenticationException): sftp(sftp_server,credentials)


def test_ftp_genuine_passive_upload_no_download_and_collision_retained(alice,scanner,ftp_server):
    tenant,consume=scanner;credentials=enable(alice,tenant,'ftp')
    client=ftp(ftp_server,credentials)
    try:
        assert client.storbinary('STOR scan.txt',io.BytesIO(b'FTP synthetic invoice')).startswith('226')
        assert (consume/tenant/'eingang'/'scan.txt').read_bytes()==b'FTP synthetic invoice'
        with pytest.raises(ftplib.error_perm): client.retrbinary('RETR scan.txt',lambda _:None)
        with pytest.raises(ftplib.error_perm): client.storbinary('STOR scan.txt',io.BytesIO(b'Different content'))
        assert (consume/tenant/'eingang'/'scan.txt').read_bytes()==b'FTP synthetic invoice'
        with pytest.raises(ftplib.error_perm): client.storbinary('STOR forbidden.exe',io.BytesIO(b'executable'))
    finally: client.close()


def test_ftp_disabled_during_session(alice,scanner,ftp_server):
    tenant,consume=scanner;credentials=enable(alice,tenant,'ftp');client=ftp(ftp_server,credentials)
    alice.put(f'/api/tenants/{tenant}/scanner',json={'enabled':False,'protocol':'ftp'})
    try:
        with pytest.raises(ftplib.error_perm): client.storbinary('STOR disabled.txt',io.BytesIO(b'disabled'))
        assert not (consume/tenant/'eingang'/'disabled.txt').exists()
    finally: client.close()


def test_scanner_wrong_protocol_and_tenant_isolation(alice,bob,scanner,sftp_server):
    tenant,consume=scanner;credentials=enable(alice,tenant)
    other=bob.post('/api/tenants',json={'name':'Other'}).json()['id']
    enable(bob,other,'ftp')
    client,channel=sftp(sftp_server,credentials)
    try:
        with pytest.raises(OSError): channel.open('/'+other+'/attack.txt','w')
        channel.putfo(io.BytesIO(b'Correct tenant'),'/eingang/own.txt')
        assert (consume/tenant/'eingang'/'own.txt').is_file()
        assert not (consume/other/'eingang'/'own.txt').exists()
    finally:channel.close();client.close()
    with pytest.raises(PermissionError): service.account(credentials['username'],'ftp')


def test_upload_limit_and_invalid_content_preserve_inbox(alice,scanner,monkeypatch):
    tenant,consume=scanner;credentials=enable(alice,tenant)
    identity=service.account(credentials['username'],'sftp')
    monkeypatch.setattr(service,'MAX_UPLOAD',4)
    upload=service.ScanUpload(identity,'sftp','large.txt')
    try:
        with pytest.raises(OSError): upload.write(b'12345')
        with pytest.raises(OSError): upload.publish()
    finally:upload.close()
    upload=service.ScanUpload(identity,'sftp','empty.pdf')
    try:
        with pytest.raises(OSError):upload.publish()
    finally:upload.close()
    assert not list((consume/tenant/'eingang').iterdir())


def test_missing_nas_never_falls_back_to_local(tmp_path,monkeypatch):
    monkeypatch.setattr(storage_control,'MANAGED',True)
    monkeypatch.setattr(storage_control,'STATE_ROOT',tmp_path)
    import json
    (tmp_path/'active.json').write_text(json.dumps({'mode':'nas','mount':'/data/nas/nonexistent','source':'//nas/documents','fstype':'cifs','subdirectory':'archivraum'}))
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as failure:storage_control.root('documents')
    assert failure.value.status_code==503


def test_verified_migration_keeps_originals_and_rejects_conflicts(tmp_path,monkeypatch):
    monkeypatch.setenv('STORAGE_SERVICE_TOKEN','test-storage-token-'*4)
    from storage_service.server import verified_copy
    old=tmp_path/'old';old.mkdir();(old/'original').write_bytes(b'original document')
    new=tmp_path/'new'
    assert verified_copy(old,new)==1
    assert (old/'original').read_bytes()==(new/'original').read_bytes()
    assert verified_copy(old,new)==0
    (new/'original').write_bytes(b'conflicting document')
    with pytest.raises(ValueError):verified_copy(old,new)
    assert (old/'original').read_bytes()==b'original document'


def test_migration_and_nas_config_reject_symlinks_and_mount_injection(tmp_path,monkeypatch):
    monkeypatch.setenv('STORAGE_SERVICE_TOKEN','test-storage-token-'*4)
    from storage_service.server import verified_copy, validate
    from fastapi import HTTPException
    source=tmp_path/'source';source.mkdir();(source/'link').symlink_to('/etc/passwd')
    with pytest.raises(ValueError):verified_copy(source,tmp_path/'target')
    with pytest.raises(HTTPException):validate({'protocol':'smb','host':'nas','share':'documents,username=evil','subdirectory':'archivraum','username':'ok'})
    with pytest.raises(HTTPException):validate({'protocol':'nfs','host':'nas','share':'/../etc','subdirectory':'archivraum'})
    with pytest.raises(HTTPException):validate({'protocol':'smb','host':'nas','share':'docs','subdirectory':'archivraum','username':'admin\npassword=evil'})


def test_migration_refuses_nested_target_before_copying(tmp_path,monkeypatch):
    monkeypatch.setenv('STORAGE_SERVICE_TOKEN','test-storage-token-'*4)
    from storage_service.server import verified_copy
    source=tmp_path/'source';source.mkdir();(source/'original').write_text('safe original')
    with pytest.raises(ValueError):verified_copy(source,source/'nested')
    assert (source/'original').read_text()=='safe original'


def test_storage_migration_gate_protects_active_file_access(tmp_path,monkeypatch):
    monkeypatch.setattr(storage_control,'MANAGED',True)
    monkeypatch.setattr(storage_control,'STATE_ROOT',tmp_path)
    from fastapi import HTTPException
    with storage_control.storage_gate():
        with pytest.raises(HTTPException) as failure:
            with storage_control.storage_gate(exclusive=True):pass
        assert failure.value.status_code==503
    with storage_control.storage_gate(exclusive=True):
        with pytest.raises(HTTPException):
            with storage_control.storage_gate():pass


def test_nas_control_auth_encryption_and_same_share_recovery(tmp_path,monkeypatch):
    monkeypatch.setenv('STORAGE_SERVICE_TOKEN','test-storage-token-'*4)
    from storage_service import server
    from fastapi.testclient import TestClient
    from types import SimpleNamespace
    from fastapi import HTTPException
    state=tmp_path/'state';state.mkdir()
    mounts=tmp_path/'mounts';mounts.mkdir()
    olddocs=tmp_path/'originals';olddocs.mkdir();(olddocs/'document').write_bytes(b'NAS migration evidence')
    oldconsume=tmp_path/'consume';oldconsume.mkdir()
    monkeypatch.setattr(server,'STATE_ROOT',state)
    monkeypatch.setattr(server,'NAS_ROOT',mounts)
    monkeypatch.setattr(server,'root',lambda kind:olddocs if kind=='documents' else oldconsume)
    monkeypatch.setattr(server,'mount_share',lambda config,path:path.mkdir(exist_ok=True))
    monkeypatch.setattr(server,'write_probe',lambda path,sub:None)
    monkeypatch.setattr(server,'mount_record',lambda path:{'mount':str(path),'source':'//nas/documents','fstype':'cifs'})
    monkeypatch.setattr(server,'mounted',lambda *args:True)
    monkeypatch.setattr(server.subprocess,'run',lambda *args,**kwargs:SimpleNamespace(returncode=0))
    def migrate(a,b,c,d):
        return {'files':server.verified_copy(a,c)+server.verified_copy(b,d)}
    monkeypatch.setattr(server,'migrate',migrate)
    with TestClient(server.app) as client:
        assert client.get('/status').status_code==401
        client.headers['Authorization']='Bearer '+server.TOKEN
        config={'protocol':'smb','host':'nas','share':'documents','subdirectory':'archivraum','username':'dms','password':'private-nas-password'}
        assert client.post('/apply',json=config).status_code==200
        saved=__import__('json').loads((state/'active.json').read_text())
        assert 'private-nas-password' not in (state/'active.json').read_text()
        assert server.credentials()['password']=='private-nas-password'
        assert client.get('/status').json()['config']['password']=='••••••••'
        assert (Path(saved['mount'])/'archivraum'/'documents'/'document').read_bytes()==b'NAS migration evidence'
        # Recovery on the same share must work even when the old mount is gone.
        def unavailable(kind):raise HTTPException(503,'old mount unavailable')
        monkeypatch.setattr(server,'root',unavailable)
        assert client.post('/test',json=config).status_code==200
        config['password']='new-private-nas-password'
        result=client.post('/apply',json=config)
        assert result.status_code==200,result.text
        assert server.credentials()['password']=='new-private-nas-password'
        assert result.json()['files']==0


def test_login_limit_counts_failures_not_successful_scans(alice,scanner):
    tenant,_=scanner;credentials=enable(alice,tenant)
    for _ in range(14):
        assert service.authenticate(credentials['username'],credentials['password'],'sftp','192.0.2.45')['tenant_id']==tenant
    for _ in range(12):
        with pytest.raises(PermissionError):service.authenticate(credentials['username'],'incorrect','sftp','192.0.2.45')
    with pytest.raises(PermissionError):service.authenticate(credentials['username'],credentials['password'],'sftp','192.0.2.45')


def test_scanner_listener_configuration(monkeypatch):
    for name, value in {'SFTP_LISTEN_PORT':'14222', 'FTP_LISTEN_PORT':'14221',
                        'FTP_PASSIVE_MIN':'14300', 'FTP_PASSIVE_MAX':'14309'}.items():
        monkeypatch.setenv(name, value)
    assert service.scanner_ports() == {'SFTP_LISTEN_PORT':14222, 'FTP_LISTEN_PORT':14221,
                                    'FTP_PASSIVE_MIN':14300, 'FTP_PASSIVE_MAX':14309}
    monkeypatch.setenv('FTP_LISTEN_PORT', '14222')
    with pytest.raises(ValueError): service.scanner_ports()
    monkeypatch.setenv('FTP_LISTEN_PORT', '14300')
    with pytest.raises(ValueError): service.scanner_ports()
    monkeypatch.setenv('FTP_LISTEN_PORT', '14221')
    monkeypatch.setenv('FTP_PASSIVE_MAX', '14299')
    with pytest.raises(ValueError): service.scanner_ports()
    monkeypatch.setenv('FTP_PASSIVE_MAX', '65536')
    with pytest.raises(ValueError): service.scanner_ports()


@pytest.mark.parametrize('version', ['3', '4', '4.1', '4.2'])
def test_nfs_protocol_locking_and_mount_safety(tmp_path,monkeypatch,version):
    monkeypatch.setenv('STORAGE_SERVICE_TOKEN','test-storage-token-'*4)
    from storage_service import server
    from types import SimpleNamespace
    commands=[]
    def successful_mount(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stderr=b'')
    monkeypatch.setattr(server.subprocess,'run',successful_mount)
    server.mount_share({'protocol':'nfs','host':'nas.example.com','share':'/var/nfs/shared/DMS','nfs_version':version},tmp_path/'mount')
    options=set(commands[0][-1].split(','))
    assert {'vers='+version,'hard','nosuid','nodev','noexec','proto=tcp','resvport'} <= options
    assert ('nolock' in options) == (version=='3')
    assert ('mountproto=tcp' in options) == (version=='3')
    assert 'soft' not in options and 'nosoft' not in options


@pytest.mark.parametrize(('stderr','expected'), [
    (b'mount.nfs: rpc.statd is not running but is required for remote locking.', 'Sperrdienst'),
    (b'mount.nfs: access denied by server while mounting nas:/private-export', 'Exportpfad'),
    (b'mount.nfs: requested NFS version or transport protocol is not supported', 'NFS-Version'),
    (b'mount.nfs: Connection refused', 'RPC-Dienst'),
    (b'mount.nfs: Operation not permitted', 'Host-Umgebung'),
    (b'mount.nfs: unknown error for nas:/private-export', 'NAS konnte nicht'),
])
def test_nfs_mount_error_preserves_active_storage(tmp_path,monkeypatch,stderr,expected):
    monkeypatch.setenv('STORAGE_SERVICE_TOKEN','test-storage-token-'*4)
    from storage_service import server
    from types import SimpleNamespace
    from fastapi.testclient import TestClient
    state=tmp_path/'state';state.mkdir()
    mounts=tmp_path/'mounts';mounts.mkdir()
    monkeypatch.setattr(server,'STATE_ROOT',state)
    monkeypatch.setattr(server,'NAS_ROOT',mounts)
    monkeypatch.setattr(server.subprocess,'run',lambda *args,**kwargs:SimpleNamespace(returncode=32,stderr=stderr))
    def no_write(*args):raise AssertionError('Write probe must not run after a failed mount')
    monkeypatch.setattr(server,'write_probe',no_write)
    with TestClient(server.app) as client:
        before=(state/'active.json').read_bytes()
        response=client.post('/apply',headers={'Authorization':'Bearer '+server.TOKEN},json={
            'protocol':'nfs','host':'nas','share':'/var/nfs/shared/DMS','subdirectory':'archivraum','nfs_version':'3'})
        assert response.status_code==422,response.text
        assert expected in response.json()['detail']
        assert '/private-export' not in response.text
        assert (state/'active.json').read_bytes()==before
        assert not list(mounts.iterdir())
