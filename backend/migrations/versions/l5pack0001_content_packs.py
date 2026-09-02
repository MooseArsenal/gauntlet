"""l5 content packs

Revision ID: l5pack0001
Revises: l4edu0001
Create Date: 2026-09-02 22:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'l5pack0001'
down_revision: Union[str, None] = 'l4edu0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'content_packs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=False),
        sa.Column('pack_id', sa.String(length=80), nullable=False),
        sa.Column('kind', sa.String(length=20), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('version', sa.String(length=40), nullable=False),
        sa.Column('publisher', sa.String(length=200), nullable=False),
        sa.Column('issued', sa.String(length=10), nullable=False),
        sa.Column('digest', sa.String(length=64), nullable=False),
        sa.Column('items', sa.Integer(), nullable=False),
        sa.Column('manifest', sa.JSON(), nullable=False),
        sa.Column('installed_by', sa.String(length=320), nullable=False),
        sa.Column('installed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('content_packs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_content_packs_org_id'), ['org_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_content_packs_pack_id'), ['pack_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('content_packs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_content_packs_pack_id'))
        batch_op.drop_index(batch_op.f('ix_content_packs_org_id'))
    op.drop_table('content_packs')
