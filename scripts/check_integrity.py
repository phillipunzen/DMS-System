"""Run in the application container: python scripts/check_integrity.py."""
import hashlib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sqlalchemy import select
from app.db import SessionLocal, DocumentVersion
from app.storage import version_path

failed = 0
checked = 0
with SessionLocal() as db:
    for doc in db.scalars(select(DocumentVersion).execution_options(yield_per=100)):
        checked += 1
        path = version_path(doc.tenant_id, doc.document_id, doc.number)
        try:
            with path.open('rb') as stream:
                checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
            if checksum != doc.sha256:
                failed += 1
                print(f'Prüfsumme abweichend: {doc.id}')
        except OSError:
            failed += 1
            print(f'Datei nicht lesbar: {doc.id}')
print(f'{checked} Dokumentversionen geprüft, {failed} Fehler.')
sys.exit(1 if failed else 0)
