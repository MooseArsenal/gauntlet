"""l4 cohorts and cohort members; sessions.cohort_id

Revision ID: l4edu0001
Revises: l2brand0001
Create Date: 2026-09-02 20:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'l4edu0001'
down_revision: Union[str, None] = 'l2brand0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'cohorts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('code', sa.String(length=12), nullable=False),
        sa.Column('instructor_user_id', sa.Integer(), nullable=False),
        sa.Column('anonymous', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('open', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['instructor_user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('cohorts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_cohorts_code'), ['code'], unique=True)
        batch_op.create_index(batch_op.f('ix_cohorts_org_id'), ['org_id'], unique=False)
    op.create_table(
        'cohort_members',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('cohort_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('alias', sa.String(length=40), nullable=False),
        sa.Column('joined_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['cohort_id'], ['cohorts.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('cohort_members', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_cohort_members_cohort_id'), ['cohort_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_cohort_members_user_id'), ['user_id'], unique=False)
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('cohort_id', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f('ix_sessions_cohort_id'), ['cohort_id'], unique=False)
        batch_op.create_foreign_key('fk_sessions_cohort_id', 'cohorts', ['cohort_id'], ['id'])


def downgrade() -> None:
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.drop_constraint('fk_sessions_cohort_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_sessions_cohort_id'))
        batch_op.drop_column('cohort_id')
    with op.batch_alter_table('cohort_members', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_cohort_members_user_id'))
        batch_op.drop_index(batch_op.f('ix_cohort_members_cohort_id'))
    op.drop_table('cohort_members')
    with op.batch_alter_table('cohorts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_cohorts_org_id'))
        batch_op.drop_index(batch_op.f('ix_cohorts_code'))
    op.drop_table('cohorts')
