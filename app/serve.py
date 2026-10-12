"""Keep API and durable background worker in the same application container."""
import os
import signal
import subprocess
import sys
import time

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
children.append(subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', '8000', '--no-proxy-headers', '--no-access-log', '--limit-concurrency', '100']))
while True:
    if any(child.poll() is not None for child in children):
        for child in children:
            child.terminate()
        sys.exit(1)
    time.sleep(1)
