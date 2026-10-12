"""Keep API and durable background worker in the same application container."""
import os
import signal
import subprocess
import sys
import time

listen_host = os.getenv('APP_LISTEN_HOST', '0.0.0.0')
listen_port = int(os.getenv('APP_LISTEN_PORT', '8000'))
if not 1 <= listen_port <= 65535:
    raise ValueError('APP_LISTEN_PORT must be between 1 and 65535')

children = []


def stop(*_):
    for child in children:
        child.terminate()
    for child in children:
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
    sys.exit(0)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
children.append(subprocess.Popen([sys.executable, '-m', 'app.worker']))
children.append(subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', listen_host, '--port', str(listen_port), '--no-proxy-headers', '--no-access-log', '--limit-concurrency', '100']))
while True:
    if any(child.poll() is not None for child in children):
        for child in children:
            child.terminate()
        sys.exit(1)
    time.sleep(1)
