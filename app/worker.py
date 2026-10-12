import logging
import time
import threading
from datetime import timedelta
from sqlalchemy import select, update, delete
from .db import SessionLocal, Document, Integration, LoginSession, AuthAttempt, Audit, MFAChallenge, now
from .processing import process_document, retry_ai
from .integrations import run_integration_once

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')


def heartbeat(document_id, stop):
    while not stop.wait(30):
        try:
            with SessionLocal() as db:
                db.execute(update(Document).where(Document.id == document_id, Document.status == 'processing').values(heartbeat_at=now()))
                from .db import Setting
                db.merge(Setting(key='worker.last_tick', value=now().isoformat()))
                db.commit()
        except Exception:
            logging.warning('Worker-Heartbeat nicht gespeichert')


def tick():
    busy = False
    with SessionLocal() as db:
        db.execute(update(Document).where(Document.status == 'processing', Document.heartbeat_at < now() - timedelta(minutes=5)).values(status='queued'))
        db.execute(delete(MFAChallenge).where(MFAChallenge.expires_at < now()))
        db.execute(delete(LoginSession).where(LoginSession.expires_at < now()))
        db.execute(delete(AuthAttempt).where(AuthAttempt.reset_at < now() - timedelta(hours=1)))
        from .db import Setting
        db.merge(Setting(key='worker.last_tick', value=now().isoformat()))
        db.commit()
        doc = db.scalar(select(Document).where(Document.status == 'queued', Document.deleted_at.is_(None)).order_by(Document.created_at).limit(1).with_for_update(skip_locked=True))
        if doc:
            busy = True
            doc.status = 'processing'
            doc.heartbeat_at = now()
            db.commit()
            stopped = threading.Event()
            thread = threading.Thread(target=heartbeat, args=(doc.id, stopped), daemon=True)
            thread.start()
            try:
                process_document(db, doc)
                db.add(Audit(tenant_id=doc.tenant_id, action='document.processed', detail=doc.id))
                db.commit()
                logging.info('Dokument verarbeitet: %s', doc.id)
            except Exception as exc:
                db.rollback()
                doc = db.get(Document, doc.id)
                doc.status = 'error'
                doc.error = 'OCR oder KI-Verarbeitung fehlgeschlagen. Dateiformat, Seitenlimit und KI-Einstellungen prüfen.'
                db.commit()
                logging.warning('Verarbeitung fehlgeschlagen: %s (%s)', doc.id, type(exc).__name__)
            finally:
                stopped.set()
                thread.join(timeout=2)
        pending = db.scalar(select(Document).where(Document.ai_pending.is_(True), Document.ai_retry_at <= now(), Document.status == 'ready', Document.deleted_at.is_(None)).order_by(Document.ai_retry_at).limit(1).with_for_update(skip_locked=True))
        if pending:
            pending.status, pending.heartbeat_at = 'processing', now()
            pending.ai_retry_at = now() + timedelta(minutes=10)
            db.commit()
            stopped = threading.Event()
            thread = threading.Thread(target=heartbeat, args=(pending.id, stopped), daemon=True)
            thread.start()
            try:
                retry_ai(db, pending)
            finally:
                stopped.set(); thread.join(timeout=2)
            busy = True
        # Integrations also run during a continuous stream of document uploads.
        for integration in db.scalars(select(Integration).where(Integration.enabled.is_(True), Integration.kind.in_(['imap', 'caldav', 'folder']))).all():
            interval = {'imap': 300, 'caldav': 900, 'folder': 30}[integration.kind]
            if not integration.last_run or (now() - integration.last_run).total_seconds() >= interval:
                run_integration_once(db, integration)
        return busy


if __name__ == '__main__':
    logging.info('DMS-Worker gestartet')
    while True:
        try:
            busy = tick()
            time.sleep(1 if busy else 10)
        except Exception as exc:
            logging.error('Worker-Fehler: %s', type(exc).__name__)
            time.sleep(10)
