"""l2 branding and partner links

Revision ID: l2brand0001
Revises: l1lic0001
Create Date: 2026-09-02 16:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'l2brand0001'
down_revision: Union[str, None] = 'l1lic0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('branding', sa.JSON(), nullable=False, server_default='{}'))
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('partner_user_id', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f('ix_users_partner_user_id'), ['partner_user_id'], unique=False)
        batch_op.create_foreign_key('fk_users_partner_user_id', 'users', ['partner_user_id'], ['id'])
    op.create_table(
        'org_links',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('partner_org_id', sa.Integer(), nullable=False),
        sa.Column('client_org_id', sa.Integer(), nullable=False),
        sa.Column('created_by', sa.String(length=320), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['client_org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['partner_org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('org_links', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_org_links_client_org_id'), ['client_org_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_org_links_partner_org_id'), ['partner_org_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('org_links', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_org_links_partner_org_id'))
        batch_op.drop_index(batch_op.f('ix_org_links_client_org_id'))
    op.drop_table('org_links')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_constraint('fk_users_partner_user_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_users_partner_user_id'))
        batch_op.drop_column('partner_user_id')
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('branding')
