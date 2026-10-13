"""Multiple IMAP connections; preserve existing IDs and message receipts."""
from alembic import op
import sqlalchemy as sa

revision = '0008'
down_revision = '0007'


def upgrade():
    constraints = sa.inspect(op.get_bind()).get_unique_constraints('integrations')
    previous = next(c for c in constraints if c['column_names'] == ['tenant_id', 'kind'])
    # SQLite's initial constraint is unnamed. Batch reflection assigns it this name.
    naming = {'uq': 'uq_%(table_name)s_%(column_0_name)s_%(column_1_name)s'}
    with op.batch_alter_table('integrations', naming_convention=naming) as batch:
        batch.add_column(sa.Column('account_key', sa.String(36), nullable=False, server_default=''))
        batch.drop_constraint(previous['name'] or 'uq_integrations_tenant_id_kind', type_='unique')
        batch.create_unique_constraint('uq_integrations_account', ['tenant_id', 'kind', 'account_key'])
        batch.create_check_constraint('ck_integrations_singleton', "kind = 'imap' OR account_key = ''")


def downgrade():
    # Never silently discard additional mailboxes or their import history on rollback.
    rows = op.get_bind().execute(sa.text("SELECT tenant_id, kind FROM integrations GROUP BY tenant_id, kind HAVING COUNT(*) > 1")).first()
    if rows:
        raise RuntimeError('Remove additional mail connections before downgrading to 0007.')
    with op.batch_alter_table('integrations') as batch:
        batch.drop_constraint('ck_integrations_singleton', type_='check')
        batch.drop_constraint('uq_integrations_account', type_='unique')
        batch.drop_column('account_key')
        batch.create_unique_constraint('uq_integrations_tenant_id_kind', ['tenant_id', 'kind'])
