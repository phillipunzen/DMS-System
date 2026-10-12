"""Initial immutable tenant-scoped schema."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql
revision = "0001"
down_revision = None

def upgrade():
    op.create_table('audit',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('actor_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('action', sa.String(length=100), nullable=False, primary_key=False),
        sa.Column('detail', sa.String(length=255), nullable=True, primary_key=False),
        sa.Column('created_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=True, primary_key=False),
    )
    op.create_index('ix_audit_tenant_id', 'audit', ['tenant_id'], unique=False)
    op.create_index('ix_audit_created_at', 'audit', ['created_at'], unique=False)
    op.create_table('auth_attempts',
        sa.Column('key', sa.String(length=64), nullable=False, primary_key=True),
        sa.Column('count', sa.Integer(), nullable=True, primary_key=False),
        sa.Column('reset_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=False, primary_key=False),
    )
    op.create_table('settings',
        sa.Column('key', sa.String(length=100), nullable=False, primary_key=True),
        sa.Column('value', sa.Text(), nullable=False, primary_key=False),
    )
    op.create_table('tenants',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('name', sa.String(length=150), nullable=False, primary_key=False),
        sa.Column('created_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=True, primary_key=False),
        sa.Column('quota_mb', sa.Integer(), nullable=True, primary_key=False),
    )
    op.create_table('users',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('email', sa.String(length=254), nullable=False, primary_key=False),
        sa.Column('name', sa.String(length=150), nullable=False, primary_key=False),
        sa.Column('password_hash', sa.Text(), nullable=True, primary_key=False),
        sa.Column('admin', sa.Boolean(), nullable=True, primary_key=False),
        sa.Column('active', sa.Boolean(), nullable=True, primary_key=False),
        sa.Column('created_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=True, primary_key=False),
        sa.UniqueConstraint('email'),
    )
    op.create_table('domains',
        sa.Column('host', sa.String(length=253), nullable=False, primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
    )
    op.create_table('folders',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('name', sa.String(length=150), nullable=False, primary_key=False),
        sa.Column('color', sa.String(length=20), nullable=True, primary_key=False),
        sa.UniqueConstraint('tenant_id', 'name'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
    )
    op.create_index('ix_folders_tenant_id', 'folders', ['tenant_id'], unique=False)
    op.create_table('identities',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('user_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('provider', sa.String(length=255), nullable=False, primary_key=False),
        sa.Column('subject', sa.String(length=255), nullable=False, primary_key=False),
        sa.UniqueConstraint('provider', 'subject'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )
    op.create_table('integrations',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('kind', sa.String(length=30), nullable=False, primary_key=False),
        sa.Column('config_encrypted', sa.Text(), nullable=False, primary_key=False),
        sa.Column('enabled', sa.Boolean(), nullable=True, primary_key=False),
        sa.Column('last_run', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=True, primary_key=False),
        sa.Column('last_status', sa.String(length=255), nullable=True, primary_key=False),
        sa.UniqueConstraint('tenant_id', 'kind'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
    )
    op.create_index('ix_integrations_tenant_id', 'integrations', ['tenant_id'], unique=False)
    op.create_table('invitations',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('email', sa.String(length=254), nullable=False, primary_key=False),
        sa.Column('role', sa.String(length=20), nullable=False, primary_key=False),
        sa.Column('token_hash', sa.String(length=64), nullable=True, primary_key=False),
        sa.Column('expires_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=False, primary_key=False),
        sa.Column('used_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=True, primary_key=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.UniqueConstraint('token_hash'),
    )
    op.create_index('ix_invitations_tenant_id', 'invitations', ['tenant_id'], unique=False)
    op.create_table('memberships',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('user_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('role', sa.String(length=20), nullable=False, primary_key=False),
        sa.UniqueConstraint('tenant_id', 'user_id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )
    op.create_index('ix_memberships_user_id', 'memberships', ['user_id'], unique=False)
    op.create_index('ix_memberships_tenant_id', 'memberships', ['tenant_id'], unique=False)
    op.create_table('sessions',
        sa.Column('token_hash', sa.String(length=64), nullable=False, primary_key=True),
        sa.Column('user_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('expires_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=False, primary_key=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )
    op.create_index('ix_sessions_user_id', 'sessions', ['user_id'], unique=False)
    op.create_table('documents',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('uploader_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('folder_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('title', sa.String(length=255), nullable=False, primary_key=False),
        sa.Column('filename', sa.String(length=255), nullable=False, primary_key=False),
        sa.Column('mime', sa.String(length=100), nullable=False, primary_key=False),
        sa.Column('size', sa.BigInteger(), nullable=False, primary_key=False),
        sa.Column('sha256', sa.String(length=64), nullable=True, primary_key=False),
        sa.Column('status', sa.String(length=20), nullable=True, primary_key=False),
        sa.Column('error', sa.String(length=255), nullable=True, primary_key=False),
        sa.Column('text', sa.Text().with_variant(mysql.LONGTEXT(), "mysql"), nullable=True, primary_key=False),
        sa.Column('supplier', sa.String(length=150), nullable=True, primary_key=False),
        sa.Column('doc_type', sa.String(length=100), nullable=True, primary_key=False),
        sa.Column('tags', sa.JSON(), nullable=True, primary_key=False),
        sa.Column('amount', sa.String(length=30), nullable=True, primary_key=False),
        sa.Column('due_date', sa.Date(), nullable=True, primary_key=False),
        sa.Column('paid', sa.Boolean(), nullable=True, primary_key=False),
        sa.Column('source', sa.String(length=30), nullable=True, primary_key=False),
        sa.Column('created_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=True, primary_key=False),
        sa.Column('deleted_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=True, primary_key=False),
        sa.Column('processed_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=True, primary_key=False),
        sa.Column('heartbeat_at', sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=True, primary_key=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['uploader_id'], ['users.id']),
        sa.ForeignKeyConstraint(['folder_id'], ['folders.id']),
    )
    op.create_index('ix_documents_created_at', 'documents', ['created_at'], unique=False)
    op.create_index('ix_documents_status', 'documents', ['status'], unique=False)
    op.create_index('ix_documents_sha256', 'documents', ['sha256'], unique=False)
    op.create_index('ix_documents_tenant_id', 'documents', ['tenant_id'], unique=False)
    op.create_index('ix_documents_due_date', 'documents', ['due_date'], unique=False)
    op.create_table('mail_imports',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('integration_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('message_key', sa.String(length=255), nullable=False, primary_key=False),
        sa.UniqueConstraint('integration_id', 'message_key'),
        sa.ForeignKeyConstraint(['integration_id'], ['integrations.id']),
    )
    op.create_table('rules',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('name', sa.String(length=150), nullable=False, primary_key=False),
        sa.Column('field', sa.String(length=20), nullable=False, primary_key=False),
        sa.Column('contains', sa.String(length=150), nullable=False, primary_key=False),
        sa.Column('folder_id', sa.String(length=36), nullable=False, primary_key=False),
        sa.Column('priority', sa.Integer(), nullable=True, primary_key=False),
        sa.Column('enabled', sa.Boolean(), nullable=True, primary_key=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['folder_id'], ['folders.id']),
    )
    op.create_index('ix_rules_tenant_id', 'rules', ['tenant_id'], unique=False)
    op.create_table('calendar_sync',
        sa.Column('id', sa.String(length=36), nullable=False, primary_key=True),
        sa.Column('integration_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.Column('document_id', sa.String(length=36), nullable=True, primary_key=False),
        sa.ForeignKeyConstraint(['integration_id'], ['integrations.id']),
        sa.UniqueConstraint('integration_id', 'document_id'),
        sa.ForeignKeyConstraint(['document_id'], ['documents.id']),
    )

def downgrade():
    op.drop_table('calendar_sync')
    op.drop_table('rules')
    op.drop_table('mail_imports')
    op.drop_table('documents')
    op.drop_table('sessions')
    op.drop_table('memberships')
    op.drop_table('invitations')
    op.drop_table('integrations')
    op.drop_table('identities')
    op.drop_table('folders')
    op.drop_table('domains')
    op.drop_table('users')
    op.drop_table('tenants')
    op.drop_table('settings')
    op.drop_table('auth_attempts')
    op.drop_table('audit')
