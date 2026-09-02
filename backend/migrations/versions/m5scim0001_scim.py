"""m5 scim provisioning

Revision ID: m5scim0001
Revises: m1cert0001
Create Date: 2026-09-02 14:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'm5scim0001'
down_revision: Union[str, None] = 'm1cert0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scim_token_hash', sa.String(length=64), nullable=True))
        batch_op.create_index(batch_op.f('ix_organizations_scim_token_hash'), ['scim_token_hash'], unique=False)
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scim_external_id', sa.String(length=200), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('scim_external_id')
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_organizations_scim_token_hash'))
        batch_op.drop_column('scim_token_hash')
