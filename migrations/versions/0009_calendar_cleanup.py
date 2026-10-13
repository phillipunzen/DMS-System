"""Retain remote event identifiers after permanent document deletion."""
from alembic import op
import sqlalchemy as sa

revision = '0009'
down_revision = '0008'


def upgrade():
    op.add_column('calendar_sync', sa.Column('event_uid', sa.String(120), nullable=True))


def downgrade():
    if op.get_bind().execute(sa.text('SELECT id FROM calendar_sync WHERE document_id IS NULL AND event_uid IS NOT NULL')).first():
        raise RuntimeError('Synchronize pending calendar deletions before downgrading.')
    op.drop_column('calendar_sync', 'event_uid')
