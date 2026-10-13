"""Automatic reconnect must repair stale mounts with the saved configuration."""
import json
import threading
from pathlib import Path
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app import storage_control


@pytest.fixture
def nas(tmp_path, monkeypatch):
    monkeypatch.setenv('STORAGE_SERVICE_TOKEN', 'test-storage-token-'*4)
    from storage_service import server
    state = tmp_path/'state'; state.mkdir()
    mounts = tmp_path/'mounts'; mounts.mkdir()
    old = mounts/'old'; old.mkdir()
    evidence = old/'original'; evidence.write_bytes(b'Original NAS evidence')
    cfg = {'protocol': 'nfs', 'host': 'nas.example.com', 'share': '/var/nfs/shared/DMS', 'subdirectory': 'archivraum', 'nfs_version': '3'}
    data = {'mode': 'nas', 'mount': str(old), 'source': 'nas.example.com:/var/nfs/shared/DMS', 'fstype': 'nfs', 'subdirectory': 'archivraum', 'encrypted_config': server.CIPHER.encrypt(json.dumps(cfg).encode()).decode()}
    monkeypatch.setattr(server, 'STATE_ROOT', state)
    monkeypatch.setattr(server, 'NAS_ROOT', mounts)
    monkeypatch.setattr(server, 'LOCK', threading.Lock())
    monkeypatch.setattr(server, 'RECOVERY', {'key': None, 'connected': False, 'retrying': False, 'message': 'pending', 'checked_at': None, 'last_success': None})
    monkeypatch.setattr(storage_control, 'MANAGED', True)
    monkeypatch.setattr(storage_control, 'STATE_ROOT', state)
    server.atomic_json(state/'active.json', data)
    records = {str(old): data}
    calls = {'mount': [], 'probe': [], 'unmount': []}
    def mounted(path, source, fstype):
        record = records.get(str(path))
        return bool(record and record['source'] == source and record['fstype'] == fstype)
    def mount(config, path):
        calls['mount'].append((config.copy(), path))
        path.mkdir(exist_ok=True)
        records[str(path)] = {'mount': str(path), 'source': config['host']+':'+config['share'] if config['protocol']=='nfs' else '//'+config['host']+'/'+config['share'], 'fstype': 'nfs' if config['protocol']=='nfs' else 'cifs'}
    def probe(path, subdirectory):
        calls['probe'].append((path, subdirectory))
    def mount_record(path):
        if str(path) not in records:
            raise HTTPException(503, 'No mount')
        return {k: records[str(path)][k] for k in ('mount', 'source', 'fstype')}
    def run(command, **kwargs):
        assert command[0] == 'umount'
        calls['unmount'].append(command[1])
        records.pop(command[1], None)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(server, 'mounted', mounted)
    monkeypatch.setattr(server, 'mount_share', mount)
    monkeypatch.setattr(server, 'write_probe', probe)
    monkeypatch.setattr(server, 'mount_record', mount_record)
    monkeypatch.setattr(server.subprocess, 'run', run)
    migrate = __import__('unittest.mock', fromlist=['Mock']).Mock(side_effect=AssertionError('Must not migrate originals'))
    monkeypatch.setattr(server, 'migrate', migrate)
    return SimpleNamespace(server=server, data=data, config=cfg, old=old, evidence=evidence, records=records, calls=calls, migrate=migrate)


def test_mount_presence_is_not_reported_as_verified_connection(nas):
    assert not nas.server.status()['connected']
    assert nas.server.reconnect_once()
    assert nas.server.status()['connected']
    assert not nas.calls['mount']
    assert nas.calls['probe'] == [(nas.old, 'archivraum')]
    assert nas.server.active() == nas.data


def test_missing_mount_is_restored_and_saved_atomically(nas):
    nas.records.clear()
    assert nas.server.reconnect_once()
    current = nas.server.active()
    assert current['mount'] != nas.data['mount']
    assert current['encrypted_config'] == nas.data['encrypted_config']
    assert current['subdirectory'] == 'archivraum'
    assert nas.calls['mount'][0][0] == nas.config
    assert nas.server.status()['connected']
    assert nas.evidence.read_bytes() == b'Original NAS evidence'
    nas.migrate.assert_not_called()


@pytest.mark.parametrize('error', [HTTPException(504, 'probe timeout'), OSError(101, 'Network is unreachable')])
def test_stale_mount_is_replaced_without_stacking_or_copying(nas, monkeypatch, error):
    def probe(path, subdirectory):
        nas.calls['probe'].append((path, subdirectory))
        if path == nas.old:
            raise error
    monkeypatch.setattr(nas.server, 'write_probe', probe)
    assert nas.server.reconnect_once()
    current = nas.server.active()
    assert current['mount'] != str(nas.old)
    assert len(nas.calls['mount']) == 1
    assert nas.calls['unmount'] == [str(nas.old)]
    assert nas.evidence.read_bytes() == b'Original NAS evidence'
    nas.migrate.assert_not_called()


def test_failed_mount_retains_original_configuration_and_retries(nas, monkeypatch):
    nas.records.clear()
    original = nas.server.mount_share
    def failure(config, path):
        path.mkdir()
        raise HTTPException(422, 'private credentials must not be shown')
    monkeypatch.setattr(nas.server, 'mount_share', failure)
    assert not nas.server.reconnect_once()
    assert nas.server.active() == nas.data
    assert not nas.server.status()['connected']
    assert 'private credentials' not in str(nas.server.status())
    monkeypatch.setattr(nas.server, 'mount_share', original)
    assert nas.server.reconnect_once()
    assert nas.server.status()['connected']


def test_new_mount_is_not_activated_when_write_probe_fails(nas, monkeypatch):
    nas.records.clear()
    monkeypatch.setattr(nas.server, 'write_probe', lambda *args: (_ for _ in ()).throw(HTTPException(422, 'UID cannot write')))
    assert not nas.server.reconnect_once()
    assert nas.server.active() == nas.data
    assert nas.calls['unmount'] == [str(nas.calls['mount'][0][1])]
    assert nas.evidence.read_bytes() == b'Original NAS evidence'


def test_atomic_state_failure_preserves_old_mount_and_cleans_candidate(nas, monkeypatch):
    nas.records.clear()
    def failure(*args):
        raise OSError('state storage failure')
    monkeypatch.setattr(nas.server, 'atomic_json', failure)
    assert not nas.server.reconnect_once()
    assert nas.server.active() == nas.data
    assert len(nas.calls['unmount']) == 1
    assert str(nas.old) not in nas.calls['unmount']


def test_active_file_transfer_postpones_reconnect_until_lock_released(nas):
    nas.records.clear()
    with storage_control.storage_gate():
        assert not nas.server.reconnect_once()
    assert len(nas.calls['mount']) == 1
    assert nas.server.active() == nas.data
    assert len(nas.calls['unmount']) == 1
    assert nas.server.reconnect_once()
    assert len(nas.calls['mount']) == 2


def test_concurrent_manual_save_is_not_interrupted(nas):
    nas.records.clear()
    with nas.server.LOCK:
        assert not nas.server.reconnect_once()
    assert not nas.calls['mount']
    assert nas.server.reconnect_once()


def test_wrong_filesystem_is_not_unmounted(nas):
    nas.records[str(nas.old)] = {'mount': str(nas.old), 'source': 'another-nas:/other', 'fstype': 'nfs'}
    assert nas.server.reconnect_once()
    assert not nas.calls['unmount']
    assert nas.evidence.exists()


def test_local_storage_does_not_trigger_nas_mount(nas):
    nas.server.atomic_json(nas.server.STATE_ROOT/'active.json', {'mode': 'local'})
    assert nas.server.reconnect_once()
    assert nas.server.status()['mode'] == 'local'
    assert nas.server.status()['connected']
    assert not nas.calls['mount'] and not nas.calls['probe']


def test_reconnect_loop_checks_immediately_then_retries(nas, monkeypatch):
    events = []
    class Stop:
        def is_set(self): return False
        def wait(self, seconds):
            events.append(('wait', seconds))
            return len(events) == 4
    monkeypatch.setattr(nas.server, 'reconnect_once', lambda: events.append(('connect', None)))
    nas.server.reconnect_loop(Stop())
    assert events == [('connect', None), ('wait', 20), ('connect', None), ('wait', 20)]


def test_helper_restart_reconnects_saved_nas_without_admin_action(nas):
    nas.records.clear()
    with TestClient(nas.server.app) as client:
        assert client.get('/health').status_code == 200
        client.headers['Authorization'] = 'Bearer ' + nas.server.TOKEN
        for _ in range(100):
            if nas.server.status()['connected']:
                break
            __import__('time').sleep(0.01)
        assert client.get('/status').json()['connected']
        assert len(nas.calls['mount']) == 1
    # A second helper startup checks the healthy mount without replacing it.
    with TestClient(nas.server.app) as client:
        for _ in range(100):
            if len(nas.calls['probe']) >= 2:
                break
            __import__('time').sleep(0.01)
        assert len(nas.calls['mount']) == 1
    assert nas.server.credentials() == nas.config
    assert nas.evidence.read_bytes() == b'Original NAS evidence'


def test_smb_credentials_survive_reconnect_and_are_masked(nas):
    cfg = {**nas.config, 'protocol': 'smb', 'share': 'documents', 'username': 'dms', 'password': 'nas-private-password', 'domain': 'OFFICE'}
    data = {**nas.data, 'fstype': 'cifs', 'source': '//nas.example.com/documents', 'encrypted_config': nas.server.CIPHER.encrypt(json.dumps(cfg).encode()).decode()}
    nas.server.atomic_json(nas.server.STATE_ROOT/'active.json', data)
    nas.records.clear()
    assert nas.server.reconnect_once()
    assert nas.calls['mount'][0][0] == cfg
    assert nas.server.credentials()['password'] == 'nas-private-password'
    status = nas.server.status()
    assert status['config']['password'] == '••••••••'
    assert 'nas-private-password' not in str(status)


def test_state_published_before_fsync_error_keeps_active_mount(nas, monkeypatch):
    nas.records.clear()
    original = nas.server.atomic_json
    def committed_but_failed(path, data):
        original(path, data)
        raise OSError('directory fsync failed after replace')
    monkeypatch.setattr(nas.server, 'atomic_json', committed_but_failed)
    assert not nas.server.reconnect_once()
    current = nas.server.active()
    assert current['mount'] != str(nas.old)
    assert not nas.calls['unmount']
    assert current['mount'] in nas.records
    monkeypatch.setattr(nas.server, 'atomic_json', original)
    assert nas.server.reconnect_once()
    assert nas.server.status()['connected']


def test_reconnect_refreshes_kernel_source_record(nas, monkeypatch):
    nas.records.clear()
    original = nas.server.mount_share
    def changed_source(config, path):
        original(config, path)
        nas.records[str(path)]['source'] = '192.0.2.10:/var/nfs/shared/DMS'
    monkeypatch.setattr(nas.server, 'mount_share', changed_source)
    assert nas.server.reconnect_once()
    assert nas.server.active()['source'] == '192.0.2.10:/var/nfs/shared/DMS'
    assert nas.server.reconnect_once()
    assert len(nas.calls['mount']) == 1
    assert nas.server.status()['connected']


def test_slow_nas_mount_does_not_block_api_access_gate(nas, monkeypatch):
    nas.records.clear()
    started, release = threading.Event(), threading.Event()
    original = nas.server.mount_share
    def delayed(config, path):
        started.set()
        assert release.wait(5)
        original(config, path)
    monkeypatch.setattr(nas.server, 'mount_share', delayed)
    thread = threading.Thread(target=nas.server.reconnect_once)
    thread.start()
    try:
        assert started.wait(5)
        with storage_control.storage_gate():
            assert nas.server.active() == nas.data
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert nas.server.status()['connected']
