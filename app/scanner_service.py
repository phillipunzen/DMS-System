"""Upload-only virtual SFTP/optional FTP accounts. Complete scans publish atomically."""
import base64
import errno
import hashlib
import json
import logging
import os
import re
import secrets
import socket
import stat
import threading
import time
import uuid
from pathlib import Path, PurePosixPath
import magic
import paramiko
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.handlers import FTPHandler, DTPHandler
from pyftpdlib.servers import ThreadedFTPServer
from sqlalchemy import select
from .db import SessionLocal, Integration, Membership, User, Setting, Tenant
from .security import decrypt, passwords
from .storage import MAX_UPLOAD, ALLOWED
from .storage_control import storage_gate, root
from .folder_import import directories, sync_directory
from .scanner_config import protocols

STATE = Path(os.getenv('SCANNER_STATE_ROOT', '/data/scanner'))
CONNECTIONS = threading.BoundedSemaphore(40)
ATTEMPTS = {}
ATTEMPT_LOCK = threading.Lock()


def allowed_attempt(ip):
    with ATTEMPT_LOCK:
        current = time.monotonic()
        for key in list(ATTEMPTS):
            if current - ATTEMPTS[key][0] > 60: del ATTEMPTS[key]
        return ATTEMPTS.get(ip, (current, 0))[1] < 12


def record_failure(ip):
    with ATTEMPT_LOCK:
        start, count = ATTEMPTS.get(ip, (time.monotonic(), 0))
        ATTEMPTS[ip] = (start, count + 1)


def account(username, protocol, generation=None):
    if not re.fullmatch(r'scan_[0-9a-f]{32}', username):
        raise PermissionError(errno.EACCES, 'Ungültiger Scannerzugang')
    tenant_id = str(uuid.UUID(username[5:]))
    with SessionLocal() as db:
        row = db.scalar(select(Integration).where(Integration.tenant_id == tenant_id, Integration.kind == 'scanner', Integration.enabled.is_(True)))
        if not row or not db.scalar(select(Membership.id).join(User, Membership.user_id == User.id).where(Membership.tenant_id == tenant_id, Membership.role == 'owner', User.active.is_(True))):
            raise PermissionError(errno.EACCES, 'Scannerzugang deaktiviert')
        config = decrypt(row.config_encrypted)
        server = db.get(Setting, 'scanner.server')
        if protocol == 'ftp' and server and not json.loads(server.value).get('ftp_allowed', True):
            raise PermissionError(errno.EACCES, 'FTP deaktiviert')
        if protocol not in protocols(config) or config.get('username') != username or (generation and config.get('generation') != generation):
            raise PermissionError(errno.EACCES, 'Scannerzugang geändert')
        return config | {'tenant_id': tenant_id, 'quota': db.get(Tenant, tenant_id).quota_mb * 1024 * 1024}


def authenticate(username, password, protocol, ip):
    if not allowed_attempt(ip): raise PermissionError(errno.EACCES, 'Zu viele Anmeldeversuche')
    try:
        config = account(username, protocol)
        if not passwords.verify(password, config['password_hash']): raise PermissionError(errno.EACCES, 'Anmeldung fehlgeschlagen')
        return config
    except Exception:
        record_failure(ip)
        raise


def scan_name(path):
    parts = PurePosixPath(path).parts
    if '..' in parts or '\\' in path or '\x00' in path:
        raise PermissionError(errno.EACCES, 'Ungültiger Dateipfad')
    parts = tuple(p for p in parts if p not in {'/', '.'})
    if len(parts) == 2 and parts[0] == 'eingang': parts = parts[1:]
    if len(parts) != 1 or parts[0].startswith('.') or len(parts[0].encode()) > 200:
        raise PermissionError(errno.EACCES, 'Nur Dateien im Scanner-Eingang erlaubt')
    name = parts[0]
    if Path(name).suffix.lower() not in {'.pdf', '.png', '.jpg', '.jpeg', '.tif', '.tiff', '.txt'}:
        raise PermissionError(errno.EACCES, 'Nicht unterstützter Dateityp')
    if any(ord(c) < 32 for c in name): raise PermissionError(errno.EACCES, 'Ungültiger Dateiname')
    return name


class ScanUpload:
    def __init__(self, identity, protocol, filename):
        self.identity, self.protocol, self.filename = identity, protocol, scan_name(filename)
        self.failed = self.committed = False
        self.closed = False
        self.gate = storage_gate()
        self.gate.__enter__()
        self.stream = None
        try:
            # Verify NAS mount before accepting bytes. No accidental local inbox.
            incoming = directories(identity['tenant_id'])['incoming']
            config = account(identity['username'], protocol, identity['generation'])
            pending = list(incoming.iterdir())
            if len(pending) >= 1000 or sum(p.stat().st_size for p in pending if p.is_file() and not p.is_symlink()) >= config['quota']:
                raise OSError(errno.ENOSPC, 'Scanner-Eingang ist voll')
            stage = STATE / 'staging' / identity['tenant_id']
            stage.mkdir(parents=True, exist_ok=True, mode=0o700)
            if len(list(stage.iterdir())) >= 40:
                raise OSError(errno.ENOSPC, 'Zu viele laufende Übertragungen')
            self.path = stage / (secrets.token_hex(24) + '.part')
            self.stream = self.path.open('xb+')
            self.path.chmod(0o600)
            self.name = str(self.path)
        except Exception:
            self.gate.__exit__(None, None, None)
            raise

    def write(self, data):
        try:
            account(self.identity['username'], self.protocol, self.identity['generation'])
            if self.stream.tell() + len(data) > min(MAX_UPLOAD, self.identity['quota']):
                raise OSError(errno.EFBIG, 'Scan überschreitet das Upload-Limit')
            return self.stream.write(data)
        except Exception:
            self.failed = True
            raise
    def seek(self, offset, whence=0): return self.stream.seek(offset, whence)
    def tell(self): return self.stream.tell()
    def fileno(self): return self.stream.fileno()
    def flush(self): return self.stream.flush()

    def publish(self):
        if self.failed or self.closed: raise OSError(errno.EIO, 'Übertragung unvollständig')
        account(self.identity['username'], self.protocol, self.identity['generation'])
        self.stream.flush(); os.fsync(self.stream.fileno())
        if self.path.stat().st_size == 0 or magic.from_file(str(self.path), mime=True) not in ALLOWED:
            raise OSError(errno.EINVAL, 'Leere oder nicht unterstützte Datei')
        incoming = directories(self.identity['tenant_id'])['incoming']
        destination = incoming / self.filename
        # Stage and NAS may be different filesystems. Publish a hidden durable
        # copy by hard link only after checksum verification; never overwrite.
        temporary = incoming / ('.scanner-' + secrets.token_hex(24) + '.part')
        try:
            import shutil
            self.stream.seek(0)
            source_hash = hashlib.file_digest(self.stream, 'sha256').hexdigest()
            self.stream.seek(0)
            with temporary.open('xb') as output:
                shutil.copyfileobj(self.stream, output)
                output.flush(); os.fsync(output.fileno())
            temporary.chmod(0o600)
            with temporary.open('rb') as verify:
                if hashlib.file_digest(verify, 'sha256').hexdigest() != source_hash: raise OSError(errno.EIO, 'Prüfsumme stimmt nicht überein')
            os.link(temporary, destination, follow_symlinks=False)
            sync_directory(incoming)
            self.committed = True
        finally:
            temporary.unlink(missing_ok=True)

    def close(self):
        if self.closed: return
        self.closed = True
        try:
            if self.stream: self.stream.close()
            self.path.unlink(missing_ok=True)
        finally:
            self.gate.__exit__(None, None, None)


class SSHAccount(paramiko.ServerInterface):
    def __init__(self, ip):
        self.ip, self.identity = ip, None
        self.channel_open = False
    def get_allowed_auths(self, username): return 'password'
    def check_auth_password(self, username, password):
        try:
            self.identity = authenticate(username, password, 'sftp', self.ip)
            return paramiko.AUTH_SUCCESSFUL
        except Exception: return paramiko.AUTH_FAILED
    def check_channel_request(self, kind, chanid):
        if kind == 'session' and self.identity and not self.channel_open:
            self.channel_open = True
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    # Shell, exec, forwarding and public key authentication stay denied.


class ScanHandle(paramiko.SFTPHandle):
    def __init__(self, interface, upload):
        super().__init__(os.O_WRONLY)
        self.interface, self.upload = interface, upload
    def write(self, offset, data):
        try:
            if self.interface.ended or offset != self.upload.tell():
                self.upload.failed = True
                return paramiko.SFTP_FAILURE
            self.upload.write(data)
            return paramiko.SFTP_OK
        except Exception:
            self.upload.failed = True
            return paramiko.SFTP_FAILURE
    def stat(self):
        return paramiko.SFTPAttributes.from_stat(os.fstat(self.upload.fileno()))
    def close(self):
        try:
            if self.interface.ended: return paramiko.SFTP_FAILURE
            self.upload.publish()
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        except Exception: return paramiko.SFTP_FAILURE
        finally: self.upload.close()


class SFTPInbox(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.identity, self.ended = server.identity, False
    def session_ended(self): self.ended = True
    def canonicalize(self, path): return '/eingang' if path in {'.', '/', '/eingang'} else path
    def list_folder(self, path):
        return [] if path in {'.', '/', '/eingang', 'eingang'} else paramiko.SFTP_PERMISSION_DENIED
    def stat(self, path):
        if path in {'.', '/', '/eingang', 'eingang'}:
            a = paramiko.SFTPAttributes(); a.st_mode = stat.S_IFDIR | 0o700; a.st_size = 0
            return a
        try:
            with storage_gate():
                account(self.identity['username'], 'sftp', self.identity['generation'])
                filename = scan_name(path)
                incoming = directories(self.identity['tenant_id'])['incoming']
                target = incoming/filename
                if target.is_symlink(): return paramiko.SFTP_PERMISSION_DENIED
                return paramiko.SFTPAttributes.from_stat(target.stat())
        except OSError as exc: return paramiko.SFTPServer.convert_errno(exc.errno)
        except Exception: return paramiko.SFTP_PERMISSION_DENIED
    lstat = stat
    def open(self, path, flags, attr):
        if not flags & os.O_WRONLY or flags & (os.O_RDWR | os.O_APPEND): return paramiko.SFTP_PERMISSION_DENIED
        try: return ScanHandle(self, ScanUpload(self.identity, 'sftp', path))
        except OSError as exc: return paramiko.SFTPServer.convert_errno(exc.errno)
        except Exception: return paramiko.SFTP_PERMISSION_DENIED


class DurableSFTPServer(paramiko.SFTPServer):
    def _read_packet(self):
        import struct
        size = struct.unpack('>I', self._read_all(4))[0]
        if size < 1 or size > 1024 * 1024:
            raise EOFError('Invalid SFTP packet size')
        data = self._read_all(size)
        return data[0], data[1:]
    def _process(self, packet_type, request_number, message):
        from paramiko.sftp import CMD_CLOSE
        if packet_type != CMD_CLOSE:
            return super()._process(packet_type, request_number, message)
        handle = message.get_binary()
        if handle in self.file_table:
            file = self.file_table.pop(handle)
            # Paramiko's stock handler discards close() errors. Scanner uploads
            # must acknowledge successful durable publication, not just receipt.
            self._send_status(request_number, file.close())
        elif handle in self.folder_table:
            del self.folder_table[handle]
            self._send_status(request_number, paramiko.SFTP_OK)
        else:
            self._send_status(request_number, paramiko.SFTP_BAD_MESSAGE)
    def finish_subsystem(self):
        self.server.session_ended()
        try:
            for file in list(self.file_table.values()): file.close()
            self.file_table.clear(); self.folder_table.clear()
        finally:
            paramiko.SubsystemHandler.finish_subsystem(self)


def ftp_home(username):
    identity = account(username, 'ftp')
    path = STATE / 'homes' / identity['tenant_id']
    (path/'eingang').mkdir(parents=True, exist_ok=True, mode=0o700)
    return str(path)


class FTPAccounts(DummyAuthorizer):
    def validate_authentication(self, username, password, handler):
        try: handler.scanner_identity = authenticate(username, password, 'ftp', handler.remote_ip)
        except Exception: raise AuthenticationFailed('Scanner authentication failed.')
    def get_home_dir(self, username): return ftp_home(username)
    def has_perm(self, username, perm, path=None):
        try: account(username, 'ftp')
        except Exception: return False
        return perm in 'elw'
    def get_perms(self, username): return 'elw'
    def get_msg_login(self, username): return 'Scanner inbox ready.'
    def get_msg_quit(self, username): return 'Goodbye.'
    def impersonate_user(self, username, password): pass
    def terminate_impersonation(self, username): pass


class FTPInboxFS(AbstractedFS):
    def open(self, filename, mode):
        if mode != 'wb': raise OSError(errno.EACCES, 'Upload only; no resume or append')
        relative = Path(filename).relative_to(self.root).as_posix()
        return ScanUpload(self.cmd_channel.scanner_identity, 'ftp', relative)


class SafeDTP(DTPHandler):
    def close(self):
        upload = self.file_obj
        if not self._closed and upload and isinstance(upload, ScanUpload) and self.receive and self.transfer_finished:
            try: upload.publish()
            except Exception:
                self.transfer_finished = False
                self._resp = ('550 Scan not stored. Retry transfer or check the DMS inbox.', logging.warning)
        super().close()


def scanner_ports():
    values = {name: int(os.getenv(name, default)) for name, default in {
        'SFTP_LISTEN_PORT': '2222', 'FTP_LISTEN_PORT': '2121',
        'FTP_PASSIVE_MIN': '30000', 'FTP_PASSIVE_MAX': '30009'}.items()}
    if any(not 1 <= value <= 65535 for value in values.values()):
        raise ValueError('Scanner ports must be between 1 and 65535')
    low, high = values['FTP_PASSIVE_MIN'], values['FTP_PASSIVE_MAX']
    if low > high or values['SFTP_LISTEN_PORT'] == values['FTP_LISTEN_PORT']:
        raise ValueError('Scanner ports must be distinct and the passive range must be ordered')
    if any(low <= values[name] <= high for name in ('SFTP_LISTEN_PORT', 'FTP_LISTEN_PORT')):
        raise ValueError('Passive FTP ports must not overlap scanner control ports')
    return values


class FTPInbox(FTPHandler):
    authorizer = FTPAccounts()
    abstracted_fs = FTPInboxFS
    dtp_handler = SafeDTP
    banner = 'DMS scanner inbox'
    timeout = 120
    auth_failed_timeout = 2
    max_login_attempts = 3
    permit_foreign_addresses = False
    permit_privileged_ports = False
    passive_ports = range(scanner_ports()['FTP_PASSIVE_MIN'], scanner_ports()['FTP_PASSIVE_MAX'] + 1)
    masquerade_address = os.getenv('FTP_PASV_ADDRESS') or None
    def ftp_PASV(self, line):
        if not os.getenv('FTP_PASV_ADDRESS'):
            try:
                with SessionLocal() as db:
                    saved = db.get(Setting, 'scanner.server')
                    host = json.loads(saved.value)['host'] if saved else os.getenv('SCANNER_PUBLIC_HOST', '')
                if host: self.masquerade_address = socket.gethostbyname(host)
            except Exception: pass
        return super().ftp_PASV(line)
    def log_transfer(self, *args, **kwargs): pass
    def log(self, *args, **kwargs): pass
    def logline(self, *args, **kwargs): pass
    def on_file_received(self, filename): pass
    def on_incomplete_file_received(self, filename): pass


def serve_connection(client, address, key):
    transport = None
    if not CONNECTIONS.acquire(blocking=False): client.close(); return
    try:
        client.settimeout(120)
        transport = paramiko.Transport(client)
        transport.set_subsystem_handler('sftp', DurableSFTPServer, SFTPInbox)
        transport.add_server_key(key)
        transport.set_keepalive(30)
        transport.start_server(server=SSHAccount(address[0]))
        deadline = time.monotonic() + 600
        while transport.is_active() and time.monotonic() < deadline: time.sleep(0.25)
    except Exception: pass
    finally:
        if transport: transport.close()
        client.close(); CONNECTIONS.release()


def start_sftp(key, port=2222, host='0.0.0.0'):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port)); listener.listen(40)
    def run():
        while True:
            try: client, address = listener.accept()
            except OSError: return
            threading.Thread(target=serve_connection, args=(client, address, key), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()
    return listener


def desired_protocols():
    """Listen only for protocols requested by an active tenant owner."""
    with SessionLocal() as db:
        owners = set(db.scalars(select(Membership.tenant_id).join(User, Membership.user_id == User.id)
            .where(Membership.role == 'owner', User.active.is_(True))))
        wanted = set()
        for row in db.scalars(select(Integration).where(Integration.kind == 'scanner', Integration.enabled.is_(True))):
            if row.tenant_id in owners:
                wanted.update(protocols(decrypt(row.config_encrypted)))
        server = db.get(Setting, 'scanner.server')
        if server and not json.loads(server.value).get('ftp_allowed', True):
            wanted.discard('ftp')
        return wanted


class ScannerListeners:
    def __init__(self, key, ports, host):
        self.key, self.ports, self.host = key, ports, host
        self.sftp = self.ftp = self.ftp_thread = None
        self.status = {}

    def stop(self, protocol):
        if protocol == 'sftp' and self.sftp:
            try: self.sftp.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            self.sftp.close()
            self.sftp = None
        elif protocol == 'ftp' and self.ftp:
            self.ftp.close_all()
            if self.ftp_thread: self.ftp_thread.join(timeout=2)
            self.ftp = self.ftp_thread = None

    def close(self):
        for protocol in ('sftp', 'ftp'): self.stop(protocol)

    def reconcile(self, wanted):
        for protocol in ('sftp', 'ftp'):
            port = self.ports[protocol.upper() + '_LISTEN_PORT']
            if protocol not in wanted:
                self.stop(protocol)
                self.status[protocol] = {'state': 'disabled', 'port': port, 'message': 'Kein aktiver Scannerzugang für dieses Protokoll.'}
                continue
            try:
                if protocol == 'sftp' and self.sftp is None:
                    self.sftp = start_sftp(self.key, port=port, host=self.host)
                if protocol == 'ftp' and (self.ftp is None or not self.ftp_thread.is_alive()):
                    self.stop('ftp')
                    class Handler(FTPInbox):
                        passive_ports = range(self.ports['FTP_PASSIVE_MIN'], self.ports['FTP_PASSIVE_MAX'] + 1)
                    self.ftp = ThreadedFTPServer((self.host, port), Handler)
                    self.ftp.max_cons, self.ftp.max_cons_per_ip = 40, 5
                    self.ftp_thread = threading.Thread(target=self.ftp.serve_forever,
                        kwargs={'timeout': 0.5, 'handle_exit': False}, daemon=True)
                    self.ftp_thread.start()
                self.status[protocol] = {'state': 'listening', 'port': port, 'message': 'Scannerport ist geöffnet. Netzwerk und Host-Firewall müssen den Zugriff zulassen.'}
            except OSError:
                self.stop(protocol)
                self.status[protocol] = {'state': 'error', 'port': port, 'message': 'Scannerport konnte nicht geöffnet werden. Portbelegung und Bind-Adresse prüfen. Erneuter Versuch in fünf Sekunden.'}
        return self.status


def main():
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    logging.getLogger('pyftpdlib').setLevel(logging.CRITICAL)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    # A restarted service has no live upload handles; discard only its own
    # incomplete staging files. Completed scans are in tenant inboxes.
    stage_root = STATE/'staging'
    if stage_root.exists():
        for tenant_stage in stage_root.iterdir():
            if tenant_stage.is_dir() and not tenant_stage.is_symlink():
                for partial in tenant_stage.glob('*.part'):
                    if partial.is_file() and not partial.is_symlink(): partial.unlink()
    key_path = STATE/'ssh_host_rsa_key'
    if key_path.exists(): key = paramiko.RSAKey.from_private_key_file(str(key_path))
    else:
        key = paramiko.RSAKey.generate(3072)
        key.write_private_key_file(str(key_path)); key_path.chmod(0o600)
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
    ports = scanner_ports()
    bind = os.getenv('SCANNER_LISTEN_HOST', '0.0.0.0')
    listeners = ScannerListeners(key, ports, bind)
    try:
        while True:
            try:
                status = listeners.reconcile(desired_protocols())
            except Exception:
                # Authentication still fails closed during a database outage.
                status = {p: {'state': 'error', 'port': ports[p.upper() + '_LISTEN_PORT'],
                    'message': 'Scannerkonfiguration nicht erreichbar. Erneuter Versuch in fünf Sekunden.'} for p in ('sftp', 'ftp')}
            temporary = STATE/'.status.tmp'
            temporary.write_text(json.dumps({'heartbeat': time.time(), 'host_key': fingerprint,
                'listeners': status, 'passive_ports': {'min': ports['FTP_PASSIVE_MIN'], 'max': ports['FTP_PASSIVE_MAX']}}))
            temporary.chmod(0o600); os.replace(temporary, STATE/'status.json')
            time.sleep(5)
    finally:
        listeners.close()


if __name__ == '__main__': main()
