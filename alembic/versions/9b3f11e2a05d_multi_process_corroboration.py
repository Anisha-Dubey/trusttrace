"""multi_process_corroboration_coordination

Revision ID: 9b3f11e2a05d
Revises: fc4404487a31
Create Date: 2026-11-10 01:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9b3f11e2a05d'
down_revision: Union[str, Sequence[str], None] = 'fc4404487a31'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add multi-process coordination and normalized domain source-family tracking tables."""
    # 1. Community Domain Coordination
    op.create_table(
        'community_domain_coordination',
        sa.Column('normalized_domain', sa.String(length=255), primary_key=True),
        sa.Column('active_claim', sa.String(length=64), nullable=True),
        sa.Column('is_disputed', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('updated_at', sa.String(length=64), nullable=False),
    )

    # 2. Community Domain Source Families (Normalized Registry with Uniqueness Constraint)
    op.create_table(
        'community_domain_source_families',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('normalized_domain', sa.String(length=255), nullable=False),
        sa.Column('source_family', sa.String(length=128), nullable=False),
        sa.Column('first_report_id', sa.String(length=128), sa.ForeignKey('community_reports.report_id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.UniqueConstraint('normalized_domain', 'source_family', name='uq_domain_source_family'),
    )
    op.create_index(
        'ix_community_domain_source_families_normalized_domain',
        'community_domain_source_families',
        ['normalized_domain'],
    )


def downgrade() -> None:
    """Drop multi-process coordination tables."""
    op.drop_index('ix_community_domain_source_families_normalized_domain', table_name='community_domain_source_families')
    op.drop_table('community_domain_source_families')
    op.drop_table('community_domain_coordination')
