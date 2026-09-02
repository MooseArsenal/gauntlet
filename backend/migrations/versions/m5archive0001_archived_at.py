"""m5 soft-delete (archived_at) for scenarios, environments, sessions

Revision ID: m5archive0001
Revises: m4harden0001
Create Date: 2026-09-02 01:20:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'm5archive0001'
down_revision: Union[str, None] = 'm4harden0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for table in ('scenarios', 'environments', 'sessions'):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.add_column(sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    for table in ('sessions', 'environments', 'scenarios'):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_column('archived_at')
