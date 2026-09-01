"""d4 join code + lobby

Revision ID: d4j0inlobby01
Revises: a7c0adver0001
Create Date: 2026-09-01 21:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4j0inlobby01'
down_revision: Union[str, None] = 'a7c0adver0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('join_code', sa.String(length=12), nullable=True))
        batch_op.create_index(batch_op.f('ix_sessions_join_code'), ['join_code'], unique=False)

    op.create_table(
        'session_joins',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('display_name', sa.String(length=160), nullable=False),
        sa.Column('cell', sa.String(length=40), nullable=False),
        sa.Column('joined_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id', 'user_id', name='uq_session_user'),
    )
    with op.batch_alter_table('session_joins', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_session_joins_org_id'), ['org_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_session_joins_session_id'), ['session_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('session_joins', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_session_joins_session_id'))
        batch_op.drop_index(batch_op.f('ix_session_joins_org_id'))
    op.drop_table('session_joins')
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_sessions_join_code'))
        batch_op.drop_column('join_code')
