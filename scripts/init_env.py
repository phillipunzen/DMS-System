from pathlib import Path
import secrets

root = Path(__file__).resolve().parent.parent
path = root / '.env'
if path.exists():
    raise SystemExit('.env already exists; refusing to overwrite it.')
password = secrets.token_urlsafe(24)
db_password = secrets.token_hex(24)
values = {'SECRET_KEY': secrets.token_hex(48), 'BOOTSTRAP_ADMIN_EMAIL': 'admin@example.com', 'BOOTSTRAP_ADMIN_PASSWORD': password, 'DATABASE_URL': f'mysql+pymysql://dms:{db_password}@db:3306/dms?charset=utf8mb4', 'DB_PASSWORD': db_password, 'DB_ROOT_PASSWORD': secrets.token_hex(32), 'APP_PORT': '8120', 'APP_BIND': '0.0.0.0', 'COOKIE_SECURE': 'false', 'ALLOWED_HOSTS': '*', 'MAX_UPLOAD_MB': '50', 'DOCUMENTS_PATH': 'documents', 'CONSUME_PATH': str(root / 'consume'), 'CODEX_SERVICE_TOKEN': secrets.token_hex(32), 'STORAGE_SERVICE_TOKEN': secrets.token_hex(32), 'NAS_MOUNT_PATH': '/srv/dms-system/nas', 'SCANNER_PUBLIC_HOST': '', 'SCANNER_BIND': '0.0.0.0', 'SFTP_PORT': '2222', 'FTP_PORT': '2121'}
path.write_text('\n'.join(f'{k}={v}' for k, v in values.items()) + '\n')
path.chmod(0o600)
access = root / 'INITIAL_ACCESS.txt'
access.write_text(f'Evaluation instance: http://SERVER-IP:8120\nEmail: admin@example.com\nPassword: {password}\n\nAfter signing in, change the password under Konto. Then delete this file.\n')
access.chmod(0o600)
print('.env and INITIAL_ACCESS.txt created with mode 0600.')
