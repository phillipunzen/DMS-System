"""Contracts, external shares, notes, version-bound PDF annotations and OCR fallback."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import DATETIME
revision = '0007'
down_revision = '0006'
TS = sa.DateTime().with_variant(DATETIME(fsp=6), 'mysql')


def upgrade():
    op.add_column('documents', sa.Column('ocr_failed', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table('contracts',
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), primary_key=True),
        sa.Column('partner', sa.String(150), nullable=False), sa.Column('start_date', sa.Date()),
        sa.Column('end_date', sa.Date(), nullable=False), sa.Column('notice_days', sa.Integer(), nullable=False),
        sa.Column('reminder_days', sa.Integer(), nullable=False), sa.Column('status', sa.String(20), nullable=False),
        sa.Column('note', sa.String(2000), nullable=False))
    op.create_index('ix_contracts_end_date', 'contracts', ['end_date'])
    for name, columns in [
        ('document_notes', [sa.Column('body', sa.String(4000), nullable=False), sa.Column('updated_at', TS, nullable=False)]),
        ('annotations', [sa.Column('version', sa.Integer(), nullable=False), sa.Column('page', sa.Integer(), nullable=False),
            sa.Column('rect', sa.JSON(), nullable=False), sa.Column('color', sa.String(20), nullable=False), sa.Column('body', sa.String(1000), nullable=False)])]:
        op.create_table(name, sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=False),
            sa.Column('author_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('created_at', TS, nullable=False), *columns)
        op.create_index('ix_' + name + '_document_id', name, ['document_id'])
    op.create_table('share_links', sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=False),
        sa.Column('creator_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True), sa.Column('password_hash', sa.Text()),
        sa.Column('version', sa.Integer(), nullable=False), sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('expires_at', TS, nullable=False), sa.Column('revoked_at', TS),
        sa.Column('created_at', TS, nullable=False), sa.Column('downloads', sa.Integer(), nullable=False))
    op.create_index('ix_share_links_document_id', 'share_links', ['document_id'])


def downgrade():
    for name in ['share_links', 'annotations', 'document_notes', 'contracts']:
        op.drop_table(name)
    op.drop_column('documents', 'ocr_failed')
