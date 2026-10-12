"""Ensure expiry and throttle windows cannot be NULL after precision migration."""
from alembic import op
from sqlalchemy.dialects import mysql
revision = '0003'
down_revision = '0002'


def upgrade():
    if op.get_bind().dialect.name == 'mysql':
        for table, column in [('sessions', 'expires_at'), ('invitations', 'expires_at'), ('auth_attempts', 'reset_at')]:
            op.alter_column(table, column, existing_type=mysql.DATETIME(fsp=6), nullable=False)


def downgrade():
    pass  # These columns were always required by the original model.
