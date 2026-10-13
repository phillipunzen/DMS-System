"""Combined import configuration and genuine dynamically enabled scanner listeners."""
import ftplib
import io
import json
import socket
import time
import paramiko
import pytest
from sqlalchemy import select
from app import scanner_service as service, folder_import
from app.db import SessionLocal, Integration, User, Setting
from app.security import encrypt, decrypt


@pytest.fixture
def workspace(alice, tmp_path, monkeypatch):
    consume = tmp_path/'consume'; consume.mkdir()
    state = tmp_path/'scanner'; state.mkdir()
    monkeypatch.setattr(folder_import, 'ROOT', consume)
    monkeypatch.setattr(service, 'STATE', state)
    monkeypatch.setattr(service, 'ATTEMPTS', {})
    monkeypatch.setenv('SCANNER_STATE_ROOT', str(state))
    tid = alice.post('/api/tenants', json={'name': 'Combined scanner'}).json()['id']
    return tid, consume, state


def payload(selected=('sftp', 'ftp'), **changes):
    return {'enabled': True, 'protocols': list(selected), 'ftp_confirmed': True,
        'folder_import': {'enabled': True, 'config': {'after_import': 'delete', 'settle_seconds': 5, 'folder_id': None}}, **changes}


def save(alice, tid, data=None):
    result = alice.put(f'/api/tenants/{tid}/scanner', json=data or payload())
    assert result.status_code == 200, result.text
    return result.json()


def test_both_protocols_share_credentials_and_one_folder_configuration(alice, workspace):
    tid, _, _ = workspace
    config = payload();config['folder_import']['config']['after_import'] = 'archive'
    data = save(alice, tid, config)
    assert data['protocols'] == ['sftp', 'ftp']
    assert [c['protocol'] for c in data['connections']] == ['sftp', 'ftp']
    assert all(c['directory'] == '/eingang' and data['password'] not in c['url'] for c in data['connections'])
    assert service.account(data['username'], 'sftp')['tenant_id'] == tid
    assert service.account(data['username'], 'ftp')['tenant_id'] == tid
    folder = next(i for i in alice.get(f'/api/tenants/{tid}/integrations').json() if i['kind'] == 'folder')
    assert folder['enabled'] and folder['config']['after_import'] == 'archive'
    assert folder['config']['settle_seconds'] == 5
    rotated = alice.post(f'/api/tenants/{tid}/scanner/rotate').json()
    for protocol in ('sftp', 'ftp'):
        with pytest.raises(Exception):
            service.authenticate(data['username'], data['password'], protocol, '192.0.2.8')
        assert service.authenticate(rotated['username'], rotated['password'], protocol, '192.0.2.8')


@pytest.mark.parametrize('failure', ['confirmation', 'disabled_import', 'invalid_folder', 'invalid_delay', 'path_injection'])
def test_combined_save_is_atomic_on_invalid_configuration(alice, workspace, failure):
    tid, _, _ = workspace
    old = save(alice, tid, payload(('sftp',)))
    with SessionLocal() as db:
        before = {r.kind: r.config_encrypted for r in db.scalars(select(Integration).where(Integration.tenant_id == tid))}
    data = payload()
    if failure == 'confirmation': data['ftp_confirmed'] = False
    if failure == 'disabled_import': data['folder_import']['enabled'] = False
    if failure == 'invalid_folder': data['folder_import']['config']['folder_id'] = 'another-tenant-folder'
    if failure == 'invalid_delay': data['folder_import']['config']['settle_seconds'] = 1
    if failure == 'path_injection': data['folder_import']['config']['path'] = '/etc'
    assert alice.put(f'/api/tenants/{tid}/scanner', json=data).status_code in (422, 404)
    with SessionLocal() as db:
        assert {r.kind: r.config_encrypted for r in db.scalars(select(Integration).where(Integration.tenant_id == tid))} == before
    assert alice.get(f'/api/tenants/{tid}/scanner').json()['password'] == old['password']


def test_server_ftp_policy_applies_to_both_protocols(alice, admin, workspace):
    tid, _, _ = workspace
    admin.put('/api/admin/scanner', json={'host': 'scanner.example.com', 'ftp_allowed': False})
    assert alice.put(f'/api/tenants/{tid}/scanner', json=payload()).status_code == 403
    save(alice, tid, payload(('sftp',)))
    assert service.desired_protocols() == {'sftp'}


def test_direct_directory_disables_network_account_and_keeps_import_enabled(alice, workspace):
    tid, _, _ = workspace
    data = save(alice, tid)
    save(alice, tid, payload(enabled=False))
    assert service.desired_protocols() == set()
    with pytest.raises(PermissionError): service.account(data['username'], 'sftp')
    folder = next(i for i in alice.get(f'/api/tenants/{tid}/integrations').json() if i['kind'] == 'folder')
    assert folder['enabled']


def test_listener_selection_respects_active_owners_and_global_ftp_policy(alice, admin, workspace):
    tid, _, _ = workspace
    save(alice, tid)
    assert service.desired_protocols() == {'sftp', 'ftp'}
    admin.put('/api/admin/scanner', json={'host': 'scanner.example.com', 'ftp_allowed': False})
    assert service.desired_protocols() == {'sftp'}
    with SessionLocal() as db:
        db.scalar(select(User).where(User.email == 'alice@example.com')).active = False
        db.commit()
    assert service.desired_protocols() == set()


def test_existing_single_protocol_accounts_continue_to_work(alice, workspace):
    tid, _, _ = workspace
    data = save(alice, tid, payload(('sftp',)))
    with SessionLocal() as db:
        row = db.scalar(select(Integration).where(Integration.tenant_id == tid, Integration.kind == 'scanner'))
        cfg = decrypt(row.config_encrypted);cfg.pop('protocols')
        row.config_encrypted = encrypt(cfg);db.commit()
    assert service.authenticate(data['username'], data['password'], 'sftp', '192.0.2.5')
    assert service.desired_protocols() == {'sftp'}
    with pytest.raises(PermissionError): service.account(data['username'], 'ftp')


def test_owner_status_reports_real_listeners_and_hides_stale_status(alice, workspace, monkeypatch):
    tid, _, state = workspace
    save(alice, tid)
    status = {'heartbeat': time.time(), 'host_key': 'SHA256:test',
              'listeners': {'sftp': {'state': 'listening', 'port': 2222}, 'ftp': {'state': 'error', 'port': 2121, 'message': 'Port belegt'}},
              'passive_ports': {'min': 31000, 'max': 31009}}
    (state/'status.json').write_text(json.dumps(status))
    data = alice.get(f'/api/tenants/{tid}/scanner').json()
    assert data['healthy'] and data['connections'][0]['state'] == 'listening'
    assert data['connections'][1]['state'] == 'error'
    assert data['passive_ports'] == {'min': 31000, 'max': 31009}
    monkeypatch.setenv('SCANNER_NETWORK_MODE', 'host')
    status['listeners']['sftp']['port'] = 14222
    (state/'status.json').write_text(json.dumps(status))
    data = alice.get(f'/api/tenants/{tid}/scanner').json()
    assert data['connections'][0]['state'] == 'error'
    assert 'Port passt nicht' in data['connections'][0]['message']
    status['heartbeat'] -= 60
    (state/'status.json').write_text(json.dumps(status))
    data = alice.get(f'/api/tenants/{tid}/scanner').json()
    assert not data['healthy'] and data['connections'][0]['state'] == 'unknown'


def test_dynamic_listeners_upload_both_protocols_and_import_into_same_tenant(alice, workspace):
    tid, consume, _ = workspace
    credentials = save(alice, tid)
    ports = {'SFTP_LISTEN_PORT': 0, 'FTP_LISTEN_PORT': 0, 'FTP_PASSIVE_MIN': 30000, 'FTP_PASSIVE_MAX': 30009}
    manager = service.ScannerListeners(paramiko.RSAKey.generate(2048), ports, '127.0.0.1')
    try:
        manager.reconcile(set())
        assert manager.sftp is None and manager.ftp is None
        result = manager.reconcile(service.desired_protocols())
        assert all(r['state'] == 'listening' for r in result.values())
        ssh = paramiko.SSHClient();ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('127.0.0.1', port=manager.sftp.getsockname()[1], username=credentials['username'],
            password=credentials['password'], look_for_keys=False, allow_agent=False, timeout=5)
        with ssh.open_sftp() as channel:
            channel.putfo(io.BytesIO(b'SFTP combined invoice'), '/eingang/sftp.txt')
        ssh.close()
        client = ftplib.FTP();client.connect('127.0.0.1', manager.ftp.socket.getsockname()[1], timeout=5)
        client.login(credentials['username'], credentials['password']);client.cwd('/eingang')
        client.storbinary('STOR ftp.txt', io.BytesIO(b'FTP combined invoice'));client.quit()
        incoming = consume/tid/'eingang'
        assert {p.name for p in incoming.iterdir()} == {'sftp.txt', 'ftp.txt'}
        for p in incoming.iterdir():
            __import__('os').utime(p, (time.time()-10, time.time()-10))
        assert alice.post(f'/api/tenants/{tid}/integrations/folder/run').status_code == 200
        assert len(alice.get(f'/api/tenants/{tid}/documents').json()['items']) == 2
        assert not list(incoming.iterdir())
        sftp_port = manager.sftp.getsockname()[1]
        save(alice, tid, payload(('ftp',)))
        manager.reconcile(service.desired_protocols())
        assert manager.sftp is None and manager.ftp is not None
        with pytest.raises(OSError): socket.create_connection(('127.0.0.1', sftp_port), timeout=1)
        manager.reconcile(set())
        assert manager.ftp is None
    finally:
        manager.close()


def test_port_conflict_does_not_crash_service_and_is_retried():
    blocker = socket.socket();blocker.bind(('127.0.0.1', 0));blocker.listen()
    ports = {'SFTP_LISTEN_PORT': blocker.getsockname()[1], 'FTP_LISTEN_PORT': 0, 'FTP_PASSIVE_MIN': 30000, 'FTP_PASSIVE_MAX': 30009}
    manager = service.ScannerListeners(paramiko.RSAKey.generate(2048), ports, '127.0.0.1')
    try:
        assert manager.reconcile({'sftp'})['sftp']['state'] == 'error'
        assert manager.sftp is None
        blocker.close()
        assert manager.reconcile({'sftp'})['sftp']['state'] == 'listening'
    finally:
        manager.close();blocker.close()
