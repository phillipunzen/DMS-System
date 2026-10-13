"""Nested logical folders and metadata-driven folder templates."""
from alembic import op
import sqlalchemy as sa

revision = '0010'
down_revision = '0009'


def upgrade():
    with op.batch_alter_table('folders') as batch:
        batch.alter_column('name', existing_type=sa.String(150), type_=sa.String(700), existing_nullable=False)
        batch.add_column(sa.Column('parent_id', sa.String(36), nullable=True))
        batch.create_foreign_key('fk_folders_parent', 'folders', ['parent_id'], ['id'])
        batch.create_index('ix_folders_parent_id', ['parent_id'])
    with op.batch_alter_table('rules') as batch:
        batch.add_column(sa.Column('folder_template', sa.String(700), nullable=True))
        batch.add_column(sa.Column('author_id', sa.String(36), nullable=True))
        batch.create_foreign_key('fk_rules_author', 'users', ['author_id'], ['id'])


def downgrade():
    connection = op.get_bind()
    if connection.execute(sa.text('SELECT id FROM folders WHERE parent_id IS NOT NULL OR LENGTH(name) > 150')).first() or connection.execute(sa.text('SELECT id FROM rules WHERE folder_template IS NOT NULL')).first():
        raise RuntimeError('Remove nested folders and folder templates before downgrading; no data is discarded.')
    with op.batch_alter_table('rules') as batch:
        batch.drop_constraint('fk_rules_author', type_='foreignkey')
        batch.drop_column('author_id')
        batch.drop_column('folder_template')
    with op.batch_alter_table('folders') as batch:
        batch.drop_constraint('fk_folders_parent', type_='foreignkey')
        batch.drop_index('ix_folders_parent_id')
        batch.drop_column('parent_id')
        batch.alter_column('name', existing_type=sa.String(700), type_=sa.String(150), existing_nullable=False)
