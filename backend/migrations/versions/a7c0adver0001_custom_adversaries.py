"""a7 custom adversaries

Revision ID: a7c0adver0001
Revises: 77babc1cfc57
Create Date: 2026-09-01 20:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a7c0adver0001'
down_revision: Union[str, None] = '77babc1cfc57'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'custom_adversaries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=False),
        sa.Column('key', sa.String(length=60), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('label', sa.String(length=240), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('motivation', sa.String(length=60), nullable=False),
        sa.Column('is_fictitious', sa.Boolean(), nullable=False),
        sa.Column('sectors', sa.JSON(), nullable=False),
        sa.Column('techniques', sa.JSON(), nullable=False),
        sa.Column('kill_chain', sa.JSON(), nullable=False),
        sa.Column('objectives', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('custom_adversaries', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_custom_adversaries_org_id'), ['org_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_custom_adversaries_key'), ['key'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('custom_adversaries', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_custom_adversaries_key'))
        batch_op.drop_index(batch_op.f('ix_custom_adversaries_org_id'))
    op.drop_table('custom_adversaries')
