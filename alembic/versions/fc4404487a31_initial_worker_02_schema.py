"""initial_worker_02_schema

Revision ID: fc4404487a31
Revises: 
Create Date: 2026-11-09 22:49:45.607564

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fc4404487a31'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


"""initial_worker_02_schema

Revision ID: fc4404487a31
Revises: 
Create Date: 2026-11-09 22:49:45.607564

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fc4404487a31'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create complete Worker 02 schema from clean database."""
    # 1. Scans
    op.create_table(
        'scans',
        sa.Column('scan_id', sa.String(length=128), primary_key=True),
        sa.Column('submitted_url_redacted', sa.Text(), nullable=False),
        sa.Column('normalized_host', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='queued'),
        sa.Column('decision', sa.String(length=32), nullable=False, server_default='inconclusive'),
        sa.Column('policy_version', sa.String(length=64), nullable=False, server_default='1.0'),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('completed_at', sa.String(length=64), nullable=True),
        sa.Column('limitations_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('coverage_total', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('coverage_observed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('coverage_failed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('coverage_not_run', sa.Integer(), nullable=False, server_default='0'),
    )
    op.create_index('ix_scans_normalized_host', 'scans', ['normalized_host'])

    # 2. Evidence Records
    op.create_table(
        'evidence_records',
        sa.Column('evidence_id', sa.String(length=128), primary_key=True),
        sa.Column('scan_id', sa.String(length=128), sa.ForeignKey('scans.scan_id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(length=64), nullable=False),
        sa.Column('value_json', sa.Text(), nullable=True),
        sa.Column('source', sa.String(length=128), nullable=False),
        sa.Column('source_type', sa.String(length=64), nullable=False, server_default='internal_collector'),
        sa.Column('observed_at', sa.String(length=64), nullable=False),
        sa.Column('ingested_at', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('reliability', sa.String(length=64), nullable=True),
        sa.Column('limitations_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('schema_version', sa.String(length=16), nullable=False, server_default='1.0'),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
    )
    op.create_index('ix_evidence_records_scan_id', 'evidence_records', ['scan_id'])
    op.create_index('ix_evidence_records_kind', 'evidence_records', ['kind'])
    op.create_index('ix_evidence_records_source', 'evidence_records', ['source'])
    op.create_index('ix_evidence_scan_kind', 'evidence_records', ['scan_id', 'kind'])
    op.create_index('uq_evidence_scan_fingerprint', 'evidence_records', ['scan_id', 'fingerprint'], unique=True)

    # 3. Findings
    op.create_table(
        'findings',
        sa.Column('finding_id', sa.String(length=128), primary_key=True),
        sa.Column('scan_id', sa.String(length=128), sa.ForeignKey('scans.scan_id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('rule_version', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.String(length=64), nullable=False),
        sa.Column('limitations_json', sa.Text(), nullable=False, server_default='[]'),
    )
    op.create_index('ix_findings_scan_id', 'findings', ['scan_id'])

    # 4. Finding Evidence Links
    op.create_table(
        'finding_evidence_links',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('finding_id', sa.String(length=128), sa.ForeignKey('findings.finding_id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_id', sa.String(length=128), sa.ForeignKey('evidence_records.evidence_id', ondelete='RESTRICT'), nullable=False),
        sa.UniqueConstraint('finding_id', 'evidence_id', name='uq_finding_evidence'),
    )

    # 5. Community Reports
    op.create_table(
        'community_reports',
        sa.Column('report_id', sa.String(length=128), primary_key=True),
        sa.Column('normalized_domain', sa.String(length=255), nullable=False),
        sa.Column('claim_type', sa.String(length=64), nullable=False),
        sa.Column('note_redacted', sa.Text(), nullable=True),
        sa.Column('submitted_at', sa.String(length=64), nullable=False),
        sa.Column('verification_state', sa.String(length=32), nullable=False, server_default='unverified'),
        sa.Column('independent_source_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('source_family', sa.String(length=64), nullable=False, server_default='community_user'),
        sa.Column('reporter_hash', sa.String(length=64), nullable=False),
        sa.Column('reviewed_at', sa.String(length=64), nullable=True),
    )
    op.create_index('ix_community_reports_normalized_domain', 'community_reports', ['normalized_domain'])
    op.create_index('ix_community_reports_verification_state', 'community_reports', ['verification_state'])
    op.create_index('ix_comm_domain_claim', 'community_reports', ['normalized_domain', 'claim_type'])

    # 6. Community Report Evidence Links
    op.create_table(
        'community_report_evidence_links',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('report_id', sa.String(length=128), sa.ForeignKey('community_reports.report_id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_id', sa.String(length=128), sa.ForeignKey('evidence_records.evidence_id', ondelete='RESTRICT'), nullable=False),
        sa.UniqueConstraint('report_id', 'evidence_id', name='uq_comm_report_evidence'),
    )

    # 7. Community Report Audit Events
    op.create_table(
        'community_report_audit_events',
        sa.Column('event_id', sa.String(length=128), primary_key=True),
        sa.Column('report_id', sa.String(length=128), sa.ForeignKey('community_reports.report_id', ondelete='CASCADE'), nullable=False),
        sa.Column('previous_state', sa.String(length=32), nullable=True),
        sa.Column('new_state', sa.String(length=32), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('actor_ref', sa.String(length=128), nullable=False),
        sa.Column('timestamp', sa.String(length=64), nullable=False),
    )
    op.create_index('ix_community_report_audit_events_report_id', 'community_report_audit_events', ['report_id'])


def downgrade() -> None:
    """Drop all tables in reverse dependency order."""
    op.drop_table('community_report_audit_events')
    op.drop_table('community_report_evidence_links')
    op.drop_table('community_reports')
    op.drop_table('finding_evidence_links')
    op.drop_table('findings')
    op.drop_table('evidence_records')
    op.drop_table('scans')
