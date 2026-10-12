"""Owner-only scanner provisioning and administrator-only NAS control."""
import os
import re
import secrets
from urllib.parse import quote
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select
from .db import Integration, Setting, get_db
from .security import admin_user, current_user, membership, encrypt, decrypt, passwords, audit, setting
from .folder_import import directories

router = APIRouter()


class ScannerInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    enabled: bool
    protocol: str = Field(default='sftp', pattern=r'^(sftp|ftp)$')
    ftp_confirmed: bool = False


class ScannerServerInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    host: str = Field(min_length=1, max_length=253, pattern=r'^[a-zA-Z0-9.-]+$')
    sftp_port: int = Field(default=2222, ge=1, le=65535)
    ftp_port: int = Field(default=2121, ge=1, le=65535)
    ftp_allowed: bool = True


def scanner_settings(db, request):
    raw = setting(db, 'scanner.server')
    return __import__('json').loads(raw) if raw else {'host': os.getenv('SCANNER_PUBLIC_HOST') or request.url.hostname,
        'sftp_port': int(os.getenv('SFTP_PORT', '2222')), 'ftp_port': int(os.getenv('FTP_PORT', '2121')), 'ftp_allowed': True}


def scanner_row(db, tenant_id):
    return db.scalar(select(Integration).where(Integration.tenant_id == tenant_id, Integration.kind == 'scanner').with_for_update())


def scanner_data(db, tenant_id, request):
    row = scanner_row(db, tenant_id)
    config = decrypt(row.config_encrypted) if row else {}
    server = scanner_settings(db, request)
    protocol = config.get('protocol', 'sftp')
    port = server[protocol + '_port']
    from pathlib import Path
    import json, time
    try:
        live = json.loads((Path(os.getenv('SCANNER_STATE_ROOT', '/data/scanner')) / 'status.json').read_text())
        healthy = time.time() - live['heartbeat'] < 45
    except (OSError, ValueError, KeyError):
        live, healthy = {}, False
    return {'enabled': bool(row and row.enabled), 'protocol': protocol, 'host': server['host'], 'port': port,
        'username': config.get('username', ''), 'password': config.get('password', ''), 'directory': '/eingang',
        'url': f"{protocol}://{quote(config.get('username', ''), safe='')}@{server['host']}:{port}/eingang" if config else '',
        'ftp_allowed': server['ftp_allowed'], 'healthy': healthy, 'host_key': live.get('host_key', ''),
        'last_status': row.last_status if row else None}


@router.get('/api/tenants/{tenant_id}/scanner')
def get_scanner(tenant_id: str, request: Request, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    return scanner_data(db, tenant_id, request)


@router.put('/api/tenants/{tenant_id}/scanner')
def save_scanner(tenant_id: str, data: ScannerInput, request: Request, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    if data.enabled and data.protocol == 'ftp':
        if not scanner_settings(db, request)['ftp_allowed']:
            raise HTTPException(403, 'FTP wurde vom Serveradmin deaktiviert. Bitte SFTP verwenden.')
        if not data.ftp_confirmed:
            raise HTTPException(422, 'Die unverschlüsselte FTP-Übertragung muss ausdrücklich bestätigt werden.')
    row = scanner_row(db, tenant_id)
    config = decrypt(row.config_encrypted) if row else {}
    if not config:
        password = secrets.token_urlsafe(24)
        config = {'username': 'scan_' + tenant_id.replace('-', ''), 'password': password, 'password_hash': passwords.hash(password), 'generation': secrets.token_hex(16)}
    config['protocol'] = data.protocol
    config['generation'] = secrets.token_hex(16)
    if data.enabled:
        directories(tenant_id)
        folder = db.scalar(select(Integration).where(Integration.tenant_id == tenant_id, Integration.kind == 'folder').with_for_update())
        if not folder:
            folder = Integration(tenant_id=tenant_id, kind='folder', config_encrypted=encrypt({'after_import': 'delete', 'settle_seconds': 5}))
            db.add(folder)
        folder.enabled = True
    if not row:
        row = Integration(tenant_id=tenant_id, kind='scanner')
        db.add(row)
    row.enabled = data.enabled
    row.config_encrypted = encrypt(config)
    audit(db, user, tenant_id, 'scanner.configured', data.protocol + (' enabled' if data.enabled else ' disabled'))
    db.commit()
    return scanner_data(db, tenant_id, request)


@router.post('/api/tenants/{tenant_id}/scanner/rotate')
def rotate_scanner(tenant_id: str, request: Request, user=Depends(current_user), db=Depends(get_db)):
    membership(db, user, tenant_id, 'owner')
    row = scanner_row(db, tenant_id)
    if not row:
        raise HTTPException(404, 'Archiv-Import zuerst konfigurieren.')
    config = decrypt(row.config_encrypted)
    password = secrets.token_urlsafe(24)
    config.update(password=password, password_hash=passwords.hash(password), generation=secrets.token_hex(16))
    row.config_encrypted = encrypt(config)
    audit(db, user, tenant_id, 'scanner.password_rotated')
    db.commit()
    return scanner_data(db, tenant_id, request)


@router.get('/api/admin/scanner')
def get_scanner_server(request: Request, user=Depends(admin_user), db=Depends(get_db)):
    return scanner_settings(db, request)


@router.put('/api/admin/scanner')
def save_scanner_server(data: ScannerServerInput, user=Depends(admin_user), db=Depends(get_db)):
    import json
    db.merge(Setting(key='scanner.server', value=json.dumps(data.model_dump())))
    audit(db, user, None, 'scanner.server_configured')
    db.commit()
    return {'ok': True}


class NASInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    protocol: str = Field(pattern=r'^(smb|nfs|local)$')
    host: str = Field(default='', max_length=253, pattern=r'^[a-zA-Z0-9.-]*$')
    share: str = Field(default='', max_length=500)
    username: str = Field(default='', max_length=200)
    password: str = Field(default='', max_length=500)
    domain: str = Field(default='', max_length=200)
    subdirectory: str = Field(default='archivraum', min_length=1, max_length=150, pattern=r'^[a-zA-Z0-9_-]+$')
    nfs_version: str = Field(default='4', pattern=r'^(3|4|4.1|4.2)$')


def storage_service(method, path, data=None):
    url, token = os.getenv('STORAGE_SERVICE_URL'), os.getenv('STORAGE_SERVICE_TOKEN', '')
    if not url or len(token) < 32:
        raise HTTPException(503, 'Speicherdienst ist nicht konfiguriert. Docker-Konfiguration prüfen.')
    try:
        with httpx.Client(timeout=600 if path == '/apply' else 45, trust_env=False) as client:
            result = client.request(method, url + path, json=data, headers={'Authorization': 'Bearer ' + token})
        if result.status_code >= 400:
            detail = result.json().get('detail', 'NAS-Verbindung fehlgeschlagen.')
            raise HTTPException(result.status_code, detail)
        return result.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(503, 'Speicherdienst nicht erreichbar. Docker-Konfiguration prüfen.')


@router.get('/api/admin/storage')
def get_storage(user=Depends(admin_user), db=Depends(get_db)):
    result = storage_service('GET', '/status')
    raw = setting(db, 'storage.nas')
    config = result.get('config') or (decrypt(raw) if raw else {'protocol': 'local', 'subdirectory': 'archivraum', 'nfs_version': '4'})
    config['password'] = '••••••••' if config.get('password') else ''
    return result | {'config': config}


@router.post('/api/admin/storage/{action}')
def configure_storage(action: str, data: NASInput, user=Depends(admin_user), db=Depends(get_db)):
    if action not in {'test', 'apply'}:
        raise HTTPException(404, 'Unbekannte Speicheraktion.')
    config = data.model_dump()
    if config['password'] == '••••••••':
        raw = setting(db, 'storage.nas')
        config['password'] = decrypt(raw).get('password') or '••••••••' if raw else '••••••••'
    result = storage_service('POST', '/' + action, config)
    if action == 'apply':
        db.merge(Setting(key='storage.nas', value=encrypt(config)))
        audit(db, user, None, 'storage.changed', config['protocol'])
        db.commit()
    return result
