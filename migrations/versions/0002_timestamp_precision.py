"""Microsecond timestamps for deterministic activity ordering on MariaDB."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql
revision = '0002'
down_revision = '0001'

COLUMNS = {
    'users': ['created_at'], 'tenants': ['created_at'], 'sessions': ['expires_at'],
    'documents': ['created_at', 'deleted_at', 'processed_at', 'heartbeat_at'],
    'invitations': ['expires_at', 'used_at'], 'integrations': ['last_run'],
    'audit': ['created_at'], 'auth_attempts': ['reset_at'],
}


def upgrade():
    if op.get_bind().dialect.name == 'mysql':
        for table, columns in COLUMNS.items():
            for name in columns:
                op.alter_column(table, name, existing_type=sa.DateTime(), type_=mysql.DATETIME(fsp=6), existing_nullable=not ((table in {'sessions', 'invitations'} and name == 'expires_at') or table == 'auth_attempts'))


def downgrade():
    if op.get_bind().dialect.name == 'mysql':
        for table, columns in COLUMNS.items():
            for name in columns:
                op.alter_column(table, name, existing_type=mysql.DATETIME(fsp=6), type_=sa.DateTime(), existing_nullable=not ((table in {'sessions', 'invitations'} and name == 'expires_at') or table == 'auth_attempts'))
