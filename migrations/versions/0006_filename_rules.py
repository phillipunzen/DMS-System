"""Optional automatic document naming alongside folder rules."""
from alembic import op
import sqlalchemy as sa
revision = '0006'
down_revision = '0005'


def upgrade():
    with op.batch_alter_table('rules') as batch:
        batch.alter_column('folder_id', existing_type=sa.String(36), nullable=True)
        batch.add_column(sa.Column('filename_template', sa.String(255), nullable=True))


def downgrade():
    # Rename-only rules have no representation in the previous schema.
    op.execute('DELETE FROM rules WHERE folder_id IS NULL')
    with op.batch_alter_table('rules') as batch:
        batch.drop_column('filename_template')
        batch.alter_column('folder_id', existing_type=sa.String(36), nullable=False)
