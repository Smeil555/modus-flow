import sqlalchemy as sa
from alembic import op

revision = 'ab2026111101'
down_revision = '9c2afd4b951d'


def upgrade():
    op.add_column('users', sa.Column('must_change_password', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        'user_permissions',
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('permission', sa.String(64), primary_key=True),
    )


def downgrade():
    op.drop_table('user_permissions')
    op.drop_column('users', 'must_change_password')
