"""Upgrade existing calendar receipts without losing event/document references."""
from pathlib import Path
import pytest
from sqlalchemy import text
from alembic.config import Config
from alembic import command
from app.db import SessionLocal, CalendarSync, Integration, engine
from app.security import encrypt
from test_workspace_tools import tenant, upload


def test_calendar_upgrade_preserves_existing_receipts_and_protects_pending_cleanup(alice):
    tid=tenant(alice);ident=upload(alice,tid)
    with SessionLocal() as db:
        integration=Integration(tenant_id=tid,kind='caldav',config_encrypted=encrypt({}))
        db.add(integration);db.flush()
        receipt=CalendarSync(integration_id=integration.id,document_id=ident)
        db.add(receipt);db.commit();receipt_id=receipt.id
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    try:
        command.stamp(config,'head')
        command.downgrade(config,'0008')
        command.upgrade(config,'head')
        with SessionLocal() as db:
            row=db.get(CalendarSync,receipt_id)
            assert row.document_id==ident and row.event_uid is None
            row.document_id=None;row.event_uid=f'archivraum-{tid}-{ident}';db.commit()
        with pytest.raises(RuntimeError,match='pending calendar deletions'):
            command.downgrade(config,'0008')
        with SessionLocal() as db:assert db.get(CalendarSync,receipt_id).event_uid==f'archivraum-{tid}-{ident}'
    finally:
        with engine.begin() as connection:connection.execute(text('DROP TABLE IF EXISTS alembic_version'))
