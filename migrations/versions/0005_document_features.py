"""Versions, access lists, optional reviews and two-factor authentication."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql
revision = '0005'
down_revision = '0004'
T = sa.DateTime().with_variant(mysql.DATETIME(fsp=6), 'mysql')


def upgrade():
    op.add_column('tenants', sa.Column('workflow_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('folders', sa.Column('restricted', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('documents', sa.Column('current_version', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('documents', sa.Column('restricted', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('documents', sa.Column('review_status', sa.String(20), nullable=False, server_default='none'))
    op.add_column('documents', sa.Column('ai_pending', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('documents', sa.Column('ai_retry_at', T))
    op.add_column('documents', sa.Column('ai_attempts', sa.Integer(), nullable=False, server_default='0'))
    op.create_table('document_versions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=False),
        sa.Column('number', sa.Integer(), nullable=False), sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('mime', sa.String(100), nullable=False), sa.Column('size', sa.BigInteger(), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False), sa.Column('uploader_id', sa.String(36), sa.ForeignKey('users.id')),
        sa.Column('note', sa.String(255), nullable=False), sa.Column('created_at', T, nullable=False),
        sa.UniqueConstraint('document_id', 'number', name='uq_document_version'))
    for column in ['tenant_id', 'document_id']:
        op.create_index('ix_document_versions_' + column, 'document_versions', [column])
    # IDs are globally unique, so the initial version may reuse the document ID.
    op.execute("INSERT INTO document_versions (id, tenant_id, document_id, number, filename, mime, size, sha256, uploader_id, note, created_at) SELECT id, tenant_id, id, 1, filename, mime, size, sha256, uploader_id, '', created_at FROM documents")
    for table, parent, key in [('folder_grants', 'folders', 'folder_id'), ('document_grants', 'documents', 'document_id')]:
        op.create_table(table, sa.Column('id', sa.String(36), primary_key=True),
            sa.Column(key, sa.String(36), sa.ForeignKey(parent + '.id'), nullable=False),
            sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('can_edit', sa.Boolean(), nullable=False), sa.UniqueConstraint(key, 'user_id'))
    op.create_table('reviews', sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('requester_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('reviewer_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('status', sa.String(20), nullable=False), sa.Column('note', sa.String(1000), nullable=False),
        sa.Column('created_at', T, nullable=False), sa.Column('decided_at', T))
    for column in ['tenant_id', 'document_id']:
        op.create_index('ix_reviews_' + column, 'reviews', [column])
    op.create_table('user_mfa', sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), primary_key=True),
        sa.Column('enabled', sa.Boolean(), nullable=False), sa.Column('secret_encrypted', sa.Text(), nullable=False),
        sa.Column('pending_until', T), sa.Column('last_counter', sa.BigInteger(), nullable=False),
        sa.Column('recovery_hashes', sa.JSON(), nullable=False))
    op.create_table('mfa_challenges', sa.Column('token_hash', sa.String(64), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('expires_at', T, nullable=False), sa.Column('attempts', sa.Integer(), nullable=False))


def downgrade():
    for table in ['mfa_challenges', 'user_mfa', 'reviews', 'document_grants', 'folder_grants', 'document_versions']:
        op.drop_table(table)
    for column in ['ai_attempts', 'ai_retry_at', 'ai_pending', 'review_status', 'restricted', 'current_version']:
        op.drop_column('documents', column)
    op.drop_column('folders', 'restricted')
    op.drop_column('tenants', 'workflow_enabled')
