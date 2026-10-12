#!/usr/bin/env python3
"""One-time shared bind parent for mounts created by the isolated NAS helper."""
import argparse
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description='Prepare a Linux shared mount parent for Web UI managed NAS storage.')
parser.add_argument('path', nargs='?', default='/srv/dms-system/nas', type=Path)
args = parser.parse_args()
path = args.path.resolve()
if path == Path('/') or len(path.parts) < 3:
    parser.error('Use a dedicated directory, such as /srv/dms-system/nas.')
path.mkdir(parents=True, exist_ok=True, mode=0o755)
if not path.is_mount():
    subprocess.run(['mount', '--bind', str(path), str(path)], check=True)
subprocess.run(['mount', '--make-rshared', str(path)], check=True)
print(f'Shared NAS mount parent ready: {path}')
print('Set NAS_MOUNT_PATH to this absolute path in .env. Reapply this preparation after a host reboot, or use the documented systemd unit.')
