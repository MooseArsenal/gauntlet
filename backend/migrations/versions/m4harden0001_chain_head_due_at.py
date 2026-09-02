"""m4 signed chain head + timer due_at

Revision ID: m4harden0001
Revises: h2mfapend0001
Create Date: 2026-09-02 00:40:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'm4harden0001'
down_revision: Union[str, None] = 'h2mfapend0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('head_seq', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('head_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('head_sig', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('due_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.drop_column('due_at')
        batch_op.drop_column('head_sig')
        batch_op.drop_column('head_hash')
        batch_op.drop_column('head_seq')
