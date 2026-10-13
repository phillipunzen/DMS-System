"""Run the real Alembic upgrade with an existing IMAP receipt (SQLite and MariaDB)."""
from datetime import datetime
from pathlib import Path
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import IntegrityError
from app import db as database
from app.db import Base, Integration, MailImport, SessionLocal
from app.security import encrypt, decrypt


def test_upgrade_preserves_connections_receipts_and_singleton_constraints():
    engine = database.engine
    Base.metadata.drop_all(engine)
    config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
    command.upgrade(config, '0007')
    try:
        legacy = sa.MetaData();legacy.reflect(engine)
        encrypted = encrypt({'host': 'imap.example.com', 'username': 'existing', 'password': 'preserved-secret'})
        at = datetime(2026, 10, 1, 12, 0)
        with engine.begin() as connection:
            connection.execute(legacy.tables['tenants'].insert().values(id='tenant', name='Archive', created_at=at, quota_mb=100, workflow_enabled=False))
            connection.execute(legacy.tables['integrations'].insert().values(id='existing-imap', tenant_id='tenant', kind='imap',
                config_encrypted=encrypted, enabled=True, last_run=at, last_status='Previous result'))
            connection.execute(legacy.tables['mail_imports'].insert().values(id='receipt', integration_id='existing-imap', message_key='already-processed'))
            connection.execute(legacy.tables['integrations'].insert().values(id='existing-ai', tenant_id='tenant', kind='ai', config_encrypted=encrypt({}), enabled=False))
        command.upgrade(config, 'head')
        with SessionLocal() as session:
            old = session.get(Integration, 'existing-imap')
            assert old.account_key == '' and old.enabled
            assert old.config_encrypted == encrypted and decrypt(old.config_encrypted)['password'] == 'preserved-secret'
            assert old.last_run == at and old.last_status == 'Previous result'
            assert session.get(MailImport, 'receipt').integration_id == old.id
            assert session.get(MailImport, 'receipt').message_key == 'already-processed'
            session.add(Integration(id='second-imap', tenant_id='tenant', kind='imap', account_key='second-imap', config_encrypted=encrypt({})))
            session.commit()
            for kind, key in [('imap', 'second-imap'), ('ai', ''), ('ai', 'bypass-singleton')]:
                session.add(Integration(tenant_id='tenant', kind=kind, account_key=key, config_encrypted=encrypt({})))
                # MariaDB reports CHECK violations as OperationalError (4025).
                errors = (IntegrityError, sa.exc.OperationalError) if key == 'bypass-singleton' else (IntegrityError,)
                with pytest.raises(errors): session.commit()
                session.rollback()
            assert session.get(MailImport, 'receipt') is not None
        # A rollback must refuse to lose connections when the old schema cannot represent them.
        with pytest.raises(RuntimeError, match='additional mail connections'):
            command.downgrade(config, '0007')
    finally:
        Base.metadata.drop_all(engine)
        with engine.begin() as connection:
            connection.execute(sa.text('DROP TABLE IF EXISTS alembic_version'))
