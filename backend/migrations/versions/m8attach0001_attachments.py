"""m8 evidence attachments

Revision ID: m8attach0001
Revises: m7bench0001
Create Date: 2026-09-02 14:40:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'm8attach0001'
down_revision: Union[str, None] = 'm7bench0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'attachments',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('event_seq', sa.Integer(), nullable=True),
        sa.Column('about_seq', sa.Integer(), nullable=True),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('content_type', sa.String(length=120), nullable=False),
        sa.Column('size', sa.Integer(), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('uploaded_by', sa.String(length=320), nullable=False),
        sa.Column('data', sa.LargeBinary(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('attachments', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_attachments_org_id'), ['org_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_attachments_session_id'), ['session_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_attachments_sha256'), ['sha256'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('attachments', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_attachments_sha256'))
        batch_op.drop_index(batch_op.f('ix_attachments_session_id'))
        batch_op.drop_index(batch_op.f('ix_attachments_org_id'))
    op.drop_table('attachments')
