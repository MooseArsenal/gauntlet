"""m1 exercise certificates

Revision ID: m1cert0001
Revises: m5archive0001
Create Date: 2026-09-02 13:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'm1cert0001'
down_revision: Union[str, None] = 'm5archive0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'certificates',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('serial', sa.String(length=32), nullable=False),
        sa.Column('issued_by', sa.String(length=320), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('digest', sa.String(length=64), nullable=False),
        sa.Column('signature', sa.String(length=64), nullable=False),
        sa.Column('issued_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('certificates', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_certificates_org_id'), ['org_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_certificates_session_id'), ['session_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_certificates_serial'), ['serial'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('certificates', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_certificates_serial'))
        batch_op.drop_index(batch_op.f('ix_certificates_session_id'))
        batch_op.drop_index(batch_op.f('ix_certificates_org_id'))
    op.drop_table('certificates')
