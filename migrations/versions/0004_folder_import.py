"""Durable receipts for tenant scanner folders."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql
revision = '0004'
down_revision = '0003'


def upgrade():
    op.create_table('folder_imports',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('integration_id', sa.String(36), sa.ForeignKey('integrations.id'), nullable=False),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('source_key', sa.String(64), nullable=False),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=True),
        sa.Column('action', sa.String(20), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('error', sa.String(255), nullable=True),
        sa.Column('updated_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), 'mysql'), nullable=False),
        sa.UniqueConstraint('integration_id', 'source_key', name='uq_folder_import_source'))
    op.create_index('ix_folder_imports_integration_id', 'folder_imports', ['integration_id'])


def downgrade():
    op.drop_table('folder_imports')
