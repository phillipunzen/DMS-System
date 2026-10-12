"""Isolated mount manager. No Docker socket, application DB or app encryption key."""
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from cryptography.fernet import Fernet
from fastapi import FastAPI, Depends, HTTPException, Request
from app.storage_control import STATE_ROOT, LOCAL_DOCUMENTS, LOCAL_CONSUME, mounted, root, storage_gate

TOKEN = os.getenv('STORAGE_SERVICE_TOKEN', '')
if len(TOKEN) < 32:
    raise RuntimeError('STORAGE_SERVICE_TOKEN must contain at least 32 characters')
CIPHER = Fernet(base64.urlsafe_b64encode(hashlib.sha256(TOKEN.encode()).digest()))
NAS_ROOT = Path('/data/nas')
LOCK = threading.Lock()


def atomic_json(path, data):
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(8))
    with temporary.open('x') as stream:
        json.dump(data, stream)
        stream.flush(); os.fsync(stream.fileno())
    temporary.chmod(0o600)
    os.chown(temporary, 10001, 10001)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def active():
    return json.loads((STATE_ROOT / 'active.json').read_text())


def credentials():
    return json.loads(CIPHER.decrypt(active()['encrypted_config'].encode()))


def validate(config):
    if config.get('protocol') not in {'local', 'smb', 'nfs'}:
        raise HTTPException(422, 'Unbekanntes Speicherprotokoll.')
    if config['protocol'] == 'local':
        return
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', config.get('host', '')) or config['host'].startswith('-'):
        raise HTTPException(422, 'Ungültiger NAS-Server.')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,150}', config.get('subdirectory', '')):
        raise HTTPException(422, 'Unterverzeichnis: nur Buchstaben, Ziffern, _ und - verwenden.')
    share = config.get('share', '')
    if config['protocol'] == 'smb':
        if not re.fullmatch(r'[A-Za-z0-9 _.$-]{1,200}', share) or share in {'.', '..'}:
            raise HTTPException(422, 'SMB-Freigabename ohne Server oder Unterordner angeben.')
        for key in ['username', 'password', 'domain']:
            if any(c in config.get(key, '') for c in ['\n', '\r', '\x00']):
                raise HTTPException(422, 'Ungültige NAS-Zugangsdaten.')
        if not config.get('username'):
            raise HTTPException(422, 'SMB-Benutzername fehlt.')
    else:
        if not re.fullmatch(r'/[A-Za-z0-9_/ .-]{0,499}', share) or '..' in share.split('/'):
            raise HTTPException(422, 'NFS-Export muss ein absoluter Pfad sein.')
        if config.get('nfs_version', '4') not in {'3', '4', '4.1', '4.2'}:
            raise HTTPException(422, 'Ungültige NFS-Version.')


def mount_share(config, mount):
    mount.mkdir(mode=0o755, exist_ok=True)
    # A reconnect must never stack mounts or overwrite another active filesystem.
    if os.path.ismount(mount):
        return
    credentials_path = None
    try:
        if config['protocol'] == 'smb':
            with tempfile.NamedTemporaryFile(mode='w', dir='/tmp', delete=False) as stream:
                credentials_path = Path(stream.name)
                for key in ['username', 'password', 'domain']:
                    stream.write(key + '=' + config.get(key, '') + '\n')
            credentials_path.chmod(0o600)
            source = '//' + config['host'] + '/' + config['share']
            command = ['mount', '-t', 'cifs', source, str(mount), '-o', f'credentials={credentials_path},vers=3.0,uid=10001,gid=10001,forceuid,forcegid,file_mode=0600,dir_mode=0700,nosuid,nodev,noexec']
        else:
            source = config['host'] + ':' + config['share']
            command = ['mount', '-t', 'nfs', source, str(mount), '-o', 'vers=' + config.get('nfs_version', '4') + ',hard,retry=0,timeo=50,retrans=2,nosuid,nodev,noexec']
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        if result.returncode and b'Operation not permitted' in result.stderr:
            raise HTTPException(422, 'Die Host-Umgebung verbietet SMB/NFS-Mounts. In einem unprivilegierten LXC sind native NAS-Mounts nicht möglich. Docker in einer VM verwenden oder NAS auf dem übergeordneten Host einbinden. Siehe README.')
        if result.returncode:
            raise HTTPException(422, 'NAS konnte nicht eingebunden werden. Adresse, Zugangsdaten, NAS-Berechtigungen und Mount-Rechte des Speichercontainers prüfen.')
    except subprocess.TimeoutExpired:
        raise HTTPException(504, 'NAS antwortet nicht rechtzeitig.')
    finally:
        if credentials_path:
            credentials_path.unlink(missing_ok=True)


def mount_record(mount):
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        if left.split()[4] == str(mount):
            fields = right.split()
            return {'mount': str(mount), 'fstype': fields[0], 'source': fields[1]}
    raise HTTPException(503, 'NAS-Mount nicht verfügbar.')


def as_dms():
    os.setgroups([])
    os.setgid(10001)
    os.setuid(10001)


def write_probe(mount, subdirectory):
    # Check permissions as the real DMS UID, including NFS root_squash behavior.
    script = '''import os,sys,secrets
from pathlib import Path
p=Path(sys.argv[1])
if p.is_symlink(): raise ValueError()
p.mkdir(mode=0o700,exist_ok=True)
for k in ['documents','consume']:
 if (p/k).is_symlink(): raise ValueError()
 (p/k).mkdir(mode=0o700,exist_ok=True)
f=p/('.connection-test-'+secrets.token_hex(12))
try:
 with f.open('xb') as out: out.write(b'archivraum');out.flush();os.fsync(out.fileno())
 if f.read_bytes()!=b'archivraum': raise ValueError()
finally: f.unlink(missing_ok=True)
'''
    try:
        result = subprocess.run(['python', '-c', script, str(mount / subdirectory)], user=10001, group=10001, extra_groups=[],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if result.returncode:
            raise HTTPException(422, 'NAS verbunden, aber UID/GID 10001 kann dort nicht sicher schreiben und lesen. NAS-Freigaberechte prüfen.')
    except subprocess.TimeoutExpired:
        raise HTTPException(504, 'NAS-Schreibprüfung hat das Zeitlimit überschritten.')


def verified_copy(source, target):
    """Immutable originals and scanner files: never overwrite conflicting destinations."""
    source, target = Path(source), Path(target)
    if target.is_symlink(): raise ValueError('Symlink im Zielspeicher.')
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    if source.exists() and os.path.samefile(source, target): return 0
    for ancestor in target.parents:
        if ancestor.exists() and source.exists() and os.path.samefile(source, ancestor):
            raise ValueError('Zielspeicher liegt innerhalb der Quelle.')
    for ancestor in source.parents:
        if ancestor.exists() and os.path.samefile(target, ancestor):
            raise ValueError('Quellspeicher liegt innerhalb des Ziels.')
    copied = 0
    for current, dirs, files in os.walk(source, followlinks=False):
        current = Path(current)
        for name in dirs + files:
            if (current / name).is_symlink():
                raise ValueError('Symlink im Speicher; Umstellung abgebrochen.')
        destination = target / current.relative_to(source)
        if destination.is_symlink(): raise ValueError('Symlink im Zielspeicher.')
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in files:
            original = current / name
            if not original.is_file():
                raise ValueError('Nichtreguläre Datei im Speicher.')
            final = destination / name
            with original.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if final.is_symlink(): raise ValueError('Symlink im Zielspeicher.')
            if final.exists():
                with final.open('rb') as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                        raise ValueError('Zielspeicher enthält eine abweichende Datei. Ein neues NAS-Unterverzeichnis verwenden.')
                continue
            temporary = destination / ('.migration-' + secrets.token_hex(16))
            try:
                with original.open('rb') as stream, temporary.open('xb') as output:
                    shutil.copyfileobj(stream, output)
                    output.flush(); os.fsync(output.fileno())
                with temporary.open('rb') as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                        raise ValueError('Prüfsumme stimmt nicht überein.')
                temporary.chmod(0o600)
                os.replace(temporary, final)
                copied += 1
            finally:
                temporary.unlink(missing_ok=True)
        fd = os.open(destination, os.O_DIRECTORY)
        try:
            try: os.fsync(fd)
            except OSError as exc:
                import errno
                if exc.errno not in {errno.EINVAL, errno.ENOTSUP}: raise
        finally: os.close(fd)
    return copied


def migrate(old_documents, old_consume, documents, consume):
    # Run unprivileged. Kernel mount capability is never available to copied content.
    script = '''import json,sys
from storage_service.server import verified_copy
print(json.dumps({'files':verified_copy(sys.argv[1],sys.argv[3])+verified_copy(sys.argv[2],sys.argv[4])}))
'''
    try:
        result = subprocess.run(['python', '-c', script, str(old_documents), str(old_consume), str(documents), str(consume)],
            user=10001, group=10001, extra_groups=[], capture_output=True, text=True, timeout=540)
        if result.returncode:
            raise HTTPException(422, 'Dateiübernahme fehlgeschlagen. Schreibrechte, Symlinks und abweichende Dateien im Ziel prüfen. Der bisherige Speicher bleibt aktiv.')
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        raise HTTPException(504, 'Dateiübernahme überschreitet das Zeitlimit. Der bisherige Speicher bleibt aktiv.')


def authorized(request: Request):
    if not secrets.compare_digest(request.headers.get('authorization', ''), 'Bearer ' + TOKEN):
        raise HTTPException(401, 'Nicht autorisiert.')


def reconnect_loop(stop):
    while not stop.wait(20):
        if not LOCK.acquire(blocking=False): continue
        try:
            data = active()
            if data['mode'] == 'nas' and not mounted(data['mount'], data['source'], data['fstype']):
                mount_share(credentials(), Path(data['mount']))
        except Exception:
            pass  # Credentials and paths never enter logs.
        finally: LOCK.release()


@asynccontextmanager
async def lifespan(app):
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(STATE_ROOT, 10001, 10001)
    lock = STATE_ROOT / 'migration.lock'
    lock.touch(mode=0o600, exist_ok=True); os.chown(lock, 10001, 10001)
    if not (STATE_ROOT / 'active.json').exists():
        atomic_json(STATE_ROOT / 'active.json', {'mode': 'local'})
    stopped = threading.Event()
    thread = threading.Thread(target=reconnect_loop, args=(stopped,), daemon=True)
    thread.start()
    yield
    stopped.set(); thread.join(timeout=1)


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


@app.get('/health')
def health(): return {'ok': True}


@app.get('/status', dependencies=[Depends(authorized)])
def status():
    data = active()
    connected = data['mode'] == 'local' or mounted(data['mount'], data['source'], data['fstype'])
    config = {'protocol': 'local', 'subdirectory': 'archivraum', 'nfs_version': '4'}
    if data['mode'] == 'nas' and data.get('encrypted_config'):
        config = credentials()
        config['password'] = '••••••••' if config.get('password') else ''
    return {'config': config, 'mode': data['mode'], 'connected': connected, 'documents': str(LOCAL_DOCUMENTS) if data['mode']=='local' else data['mount']+'/'+data['subdirectory']+'/documents',
        'consume': str(LOCAL_CONSUME) if data['mode']=='local' else data['mount']+'/'+data['subdirectory']+'/consume'}


@app.post('/{action}', dependencies=[Depends(authorized)])
def configure(action: str, config: dict):
    if action not in {'test', 'apply'}: raise HTTPException(404, 'Unbekannte Aktion.')
    if config.get('password') == '••••••••':
        try: config['password'] = credentials().get('password', '')
        except Exception: raise HTTPException(422, 'NAS-Passwort erneut eingeben.')
    validate(config)
    if not LOCK.acquire(blocking=False): raise HTTPException(409, 'Speicheraktion läuft bereits.')
    candidate = None
    committed = False
    try:
        with storage_gate(exclusive=True):
            previous = active()
            if config['protocol'] == 'local':
                data = {'mode': 'local'}
                documents, consume = LOCAL_DOCUMENTS, LOCAL_CONSUME
            else:
                candidate = NAS_ROOT / str(uuid.uuid4())
                mount_share(config, candidate)
                write_probe(candidate, config['subdirectory'])
                data = {'mode': 'nas', 'subdirectory': config['subdirectory']} | mount_record(candidate)
                documents, consume = candidate/config['subdirectory']/'documents', candidate/config['subdirectory']/'consume'
            if action == 'test': return {'ok': True, 'message': 'Verbindung sowie Lesen und Schreiben erfolgreich geprüft.'}
            same_nas = False
            if previous['mode'] == 'nas' and previous.get('encrypted_config'):
                old_config = credentials()
                same_nas = all(old_config.get(k) == config.get(k) for k in ['protocol', 'host', 'share', 'subdirectory'])
            if same_nas:
                result = {'files': 0}  # Reconnect/change credentials on the same NAS tree.
            else:
                old_documents, old_consume = root('documents'), root('consume')
                result = {'files': 0} if old_documents == documents else migrate(old_documents, old_consume, documents, consume)
            if config['protocol'] != 'local':
                data['encrypted_config'] = CIPHER.encrypt(json.dumps(config).encode()).decode()
            atomic_json(STATE_ROOT / 'active.json', data)
            committed = True
            if previous['mode'] == 'nas' and previous['mount'] != data.get('mount'):
                try:
                    unmounted = subprocess.run(['umount', previous['mount']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                    if not unmounted.returncode: Path(previous['mount']).rmdir()
                except (OSError, subprocess.TimeoutExpired): pass
            return {'ok': True, 'message': 'NAS-Verbindung erneuert. Dokumente und Scannereingänge bleiben auf derselben Freigabe.' if same_nas else 'Speicher aktiviert. Vorhandene Dateien wurden mit Prüfsummen übernommen; die bisherige Kopie bleibt erhalten.', **result}
    finally:
        try:
            if candidate and not committed:
                result = subprocess.run(['umount', str(candidate)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                if not result.returncode or not candidate.is_mount():
                    try: candidate.rmdir()
                    except OSError: pass
        finally:
            LOCK.release()
