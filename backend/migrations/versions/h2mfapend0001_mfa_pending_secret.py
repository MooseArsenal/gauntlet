"""h2 mfa pending secret

Revision ID: h2mfapend0001
Revises: d4j0inlobby01
Create Date: 2026-09-02 00:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'h2mfapend0001'
down_revision: Union[str, None] = 'd4j0inlobby01'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('mfa_pending_secret', sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('mfa_pending_secret')
