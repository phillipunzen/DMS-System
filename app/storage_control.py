"""Shared storage state and a cross-process migration gate. No local fallback on NAS."""
import fcntl
import errno
import json
import os
from contextlib import contextmanager
from pathlib import Path
from fastapi import HTTPException

STATE_ROOT = Path(os.getenv('STORAGE_STATE_ROOT', '/data/storage-state'))
MANAGED = bool(os.getenv('STORAGE_SERVICE_URL'))
LOCAL_DOCUMENTS = Path(os.getenv('STORAGE_ROOT', '/data/documents')).resolve()
LOCAL_CONSUME = Path(os.getenv('CONSUME_ROOT', '/data/consume')).resolve()


def state():
    if not MANAGED:
        return {'mode': 'local'}
    try:
        data = json.loads((STATE_ROOT / 'active.json').read_text())
    except (OSError, ValueError):
        raise HTTPException(503, 'Speicherdienst nicht bereit. Serveradministration prüfen.')
    if data.get('mode') not in {'local', 'nas'}:
        raise HTTPException(503, 'Ungültiger Speicherzustand.')
    return data


def mounted(mount, source, fstype):
    # Check this container's namespace, not a helper's stale "connected" flag.
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        fields = right.split()
        if left.split()[4] == mount and fields[0] == fstype and fields[1] == source:
            return True
    return False


def root(kind):
    data = state()
    if data['mode'] == 'local':
        return LOCAL_DOCUMENTS if kind == 'documents' else LOCAL_CONSUME
    mount = data.get('mount', '')
    if not mount.startswith('/data/nas/') or not mounted(mount, data.get('source'), data.get('fstype')):
        raise HTTPException(503, 'NAS nicht eingebunden. Zugriff angehalten; kein lokaler Ersatzspeicher.')
    return Path(mount) / data['subdirectory'] / kind


STORAGE_NETWORK_ERRORS = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT,
                          errno.ESTALE, errno.ENOTCONN, errno.ECONNREFUSED, errno.EIO}
UNAVAILABLE = 'NAS nicht erreichbar. Zugriff angehalten; Verbindung unter Speicher & Scanner prüfen. Kein lokaler Ersatzspeicher.'


def require_worker_storage():
    location = root('documents')
    if state()['mode'] == 'nas':
        try:
            # A mountinfo entry alone does not establish reachability. Check
            # before selecting jobs, so outages do not turn into OCR failures.
            if not location.is_dir():
                raise HTTPException(503, UNAVAILABLE)
        except OSError:
            raise HTTPException(503, UNAVAILABLE) from None


class StoragePath(os.PathLike):
    """Resolve on each operation; imported references survive storage switches."""
    def __init__(self, kind):
        self.kind = kind
    def __fspath__(self):
        return str(root(self.kind))
    def __str__(self):
        return os.fspath(self)
    def __truediv__(self, other):
        return root(self.kind) / other
    def __getattr__(self, name):
        return getattr(root(self.kind), name)


@contextmanager
def storage_gate(exclusive=False):
    if not MANAGED:
        yield
        return
    fd = os.open(STATE_ROOT / 'migration.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HTTPException(503, 'Speicher wird gerade verwendet oder umgestellt. Bitte erneut versuchen.')
        yield
    finally:
        os.close(fd)


class StorageGateMiddleware:
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        path = scope.get('path', '')
        if scope['type'] != 'http' or not path.startswith('/api/') or path.startswith('/api/admin/storage') or path in {'/api/health', '/api/public'}:
            return await self.app(scope, receive, send)
        from starlette.responses import JSONResponse
        started = False
        async def tracked_send(message):
            nonlocal started
            if message['type'] == 'http.response.start':
                started = True
            await send(message)
        try:
            with storage_gate():
                await self.app(scope, receive, tracked_send)
        except HTTPException as exc:
            if started:
                raise
            await JSONResponse({'detail': exc.detail}, status_code=exc.status_code)(scope, receive, send)
        except OSError as exc:
            if started or exc.errno not in STORAGE_NETWORK_ERRORS or state()['mode'] != 'nas':
                raise
            await JSONResponse({'detail': UNAVAILABLE}, status_code=503,
                               headers={'Cache-Control': 'no-store'})(scope, receive, send)


def storage_summary():
    try:
        location = root('documents')
        return {'storage': str(location), 'storage_writable': os.access(location, os.W_OK)}
    except (HTTPException, OSError):
        return {'storage': 'NAS nicht verfügbar', 'storage_writable': False}
