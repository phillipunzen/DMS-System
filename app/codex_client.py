"""No OpenAI auth tokens enter the DMS database or browser."""
import json
import os
import httpx
from fastapi import HTTPException
from .db import Setting


def allowed_tenants(db):
    row = db.get(Setting, 'codex.allowed_tenants')
    return json.loads(row.value) if row else []


def enabled_for(db, tenant_id):
    return tenant_id in allowed_tenants(db)


def request(method, path, data=None, timeout=20):
    key = os.getenv('CODEX_SERVICE_TOKEN', '')
    if len(key) < 32:
        raise HTTPException(503, 'Codex-Dienst ist noch nicht eingerichtet.')
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.request(method, os.getenv('CODEX_SERVICE_URL', 'http://codex:8001').rstrip('/') + '/v1/' + path,
                headers={'X-Codex-Token': key}, json=data)
        if not response.is_success:
            message = 'Codex-Anfrage fehlgeschlagen. Anmeldung, Modell und Nutzungslimit prüfen.'
            if response.status_code == 503:
                try:
                    detail = response.json().get('detail')
                    if isinstance(detail, str) and len(detail) <= 255:
                        message = detail
                except ValueError:
                    pass
            raise HTTPException(503, message)
        return response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(503, 'Codex-Dienst ist nicht erreichbar. Containerstatus prüfen.')


def status():
    try:
        return request('GET', 'status', timeout=5)
    except HTTPException as exc:
        return {'available': False, 'connected': False, 'message': exc.detail, 'login': None}
