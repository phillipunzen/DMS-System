#!/usr/bin/env python3
"""Consistent backup of the development Compose stack; no plaintext password output."""
import argparse
import hashlib
import json
import os
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ['docker', 'compose', '-f', str(ROOT / 'compose.yaml'), '-f', str(ROOT / 'compose.dev.yaml')]


def command(args, **kwargs):
    return subprocess.run(args, check=True, cwd=ROOT, **kwargs)


parser = argparse.ArgumentParser(description='Backup der lokalen Testinstanz. Stoppt die App für eine konsistente Sicherung.')
parser.add_argument('destination', type=Path, help='Neues Backup-Verzeichnis außerhalb des Projekts')
args = parser.parse_args()
dest = args.destination.resolve()
if dest.is_relative_to(ROOT):
    parser.error('Backup außerhalb des Projekts speichern.')
dest.mkdir(parents=True, exist_ok=False, mode=0o700)
started = False
scanner_present = bool(subprocess.check_output(COMPOSE + ['ps', '-aq', 'scanner'], cwd=ROOT, text=True).strip())
restart_ids = [subprocess.check_output(COMPOSE + ['ps', '-aq', name], cwd=ROOT, text=True).strip() for name in ['codex', 'app'] + (['scanner'] if scanner_present else [])]
restart_ids = [container_id for container_id in restart_ids if container_id]
try:
    command(COMPOSE + ['stop', 'app', 'codex'] + (['scanner'] if scanner_present else []), stdout=subprocess.DEVNULL)
    started = True
    with (dest / 'database.sql').open('wb') as output:
        command(COMPOSE + ['exec', '-T', 'db', 'sh', '-c', 'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb-dump -uroot --single-transaction --routines --triggers dms'], stdout=output)
    with (dest / 'documents.tar').open('wb') as output:
        command(COMPOSE + ['run', '--rm', '--no-deps', '--entrypoint', 'python', 'app', '-c', "from app.storage_control import root;import subprocess;subprocess.run(['tar','-C',str(root('documents')),'-cf','-','.'],check=True)"], stdout=output)
    with (dest / 'consume.tar').open('wb') as output:
        command(COMPOSE + ['run', '--rm', '--no-deps', '--entrypoint', 'python', 'app', '-c', "from app.storage_control import root;import subprocess;subprocess.run(['tar','-C',str(root('consume')),'-cf','-','.'],check=True)"], stdout=output)
    with (dest / 'codex_auth.tar').open('wb') as output:
        command(COMPOSE + ['run', '--rm', '--no-deps', '--entrypoint', 'tar', 'codex', '-C', '/data/codex', '-cf', '-', '.'], stdout=output)
    for name, mount in [('storage_state', '/data/storage-state'), ('scanner_state', '/data/scanner')]:
        with (dest / (name + '.tar')).open('wb') as output:
            command(COMPOSE + ['run', '--rm', '--no-deps', '--entrypoint', 'tar', 'app', '-C', mount, '-cf', '-', '.'], stdout=output)
    # SECRET_KEY is necessary to decrypt saved integration credentials on restore.
    with tarfile.open(dest / 'configuration.tar', 'w') as archive:
        for name in ['.env', 'compose.yaml', 'compose.dev.yaml', 'requirements.lock']:
            archive.add(ROOT / name, arcname=name)
    hashes = {}
    for path in dest.iterdir():
        if path.is_file():
            with path.open('rb') as stream:
                hashes[path.name] = hashlib.file_digest(stream, 'sha256').hexdigest()
    (dest / 'manifest.json').write_text(json.dumps({'created_at': datetime.now(timezone.utc).isoformat(), 'sha256': hashes}, indent=2))
    for path in dest.iterdir():
        path.chmod(0o600)
    print(f'Backup erstellt: {dest}')
finally:
    if started:
        command(['docker', 'start'] + restart_ids, stdout=subprocess.DEVNULL)
