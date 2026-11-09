"""SQLAlchemy ORM models for TRUSTTRACE Worker 02."""

from sqlalchemy import (
    Column,
    String,
    Integer,
    Text,
    ForeignKey,
    DateTime,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .database import Base


class ScanEntity(Base):
    """Represents a triage scan record."""

    __tablename__ = "scans"

    scan_id = Column(String(128), primary_key=True)
    submitted_url_redacted = Column(Text, nullable=False)
    normalized_host = Column(String(255), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="queued")
    decision = Column(String(32), nullable=False, default="inconclusive")
    policy_version = Column(String(64), nullable=False, default="1.0")
    created_at = Column(String(64), nullable=False)
    completed_at = Column(String(64), nullable=True)
    limitations_json = Column(Text, nullable=False, default="[]")
    
    # Pre-calculated coverage cached on scan
    coverage_total = Column(Integer, nullable=False, default=0)
    coverage_observed = Column(Integer, nullable=False, default=0)
    coverage_failed = Column(Integer, nullable=False, default=0)
    coverage_not_run = Column(Integer, nullable=False, default=0)

    # Relationships
    evidence_items = relationship("EvidenceEntity", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("FindingEntity", back_populates="scan", cascade="all, delete-orphan")


class EvidenceEntity(Base):
    """Persistent representation of an immutable evidence record."""

    __tablename__ = "evidence_records"

    evidence_id = Column(String(128), primary_key=True)
    scan_id = Column(String(128), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(64), nullable=False, index=True)
    value_json = Column(Text, nullable=True)
    source = Column(String(128), nullable=False, index=True)
    source_type = Column(String(64), nullable=False, default="internal_collector")
    observed_at = Column(String(64), nullable=False)
    ingested_at = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False)  # observed, unavailable, failed, not_run, blocked
    reliability = Column(String(64), nullable=True)  # direct_observation, provider_assertion, etc.
    limitations_json = Column(Text, nullable=False, default="[]")
    schema_version = Column(String(16), nullable=False, default="1.0")
    
    # Idempotency fingerprint: sha256(scan_id + kind + source + canonical_value)
    fingerprint = Column(String(64), nullable=False, index=True)

    scan = relationship("ScanEntity", back_populates="evidence_items")
    finding_links = relationship("FindingEvidenceLinkEntity", back_populates="evidence", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_evidence_scan_kind", "scan_id", "kind"),
        Index("ix_evidence_fingerprint", "scan_id", "fingerprint"),
    )


class FindingEntity(Base):
    """Evaluated finding linked to supporting evidence records."""

    __tablename__ = "findings"

    finding_id = Column(String(128), primary_key=True)
    scan_id = Column(String(128), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False)
    summary = Column(Text, nullable=False)
    rule_id = Column(String(64), nullable=False)
    rule_version = Column(String(32), nullable=False)
    created_at = Column(String(64), nullable=False)
    limitations_json = Column(Text, nullable=False, default="[]")

    scan = relationship("ScanEntity", back_populates="findings")
    evidence_links = relationship("FindingEvidenceLinkEntity", back_populates="finding", cascade="all, delete-orphan")


class FindingEvidenceLinkEntity(Base):
    """Explicit junction table binding findings to their supporting evidence."""

    __tablename__ = "finding_evidence_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(128), ForeignKey("findings.finding_id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String(128), ForeignKey("evidence_records.evidence_id", ondelete="RESTRICT"), nullable=False, index=True)

    finding = relationship("FindingEntity", back_populates="evidence_links")
    evidence = relationship("EvidenceEntity", back_populates="finding_links")

    __table_args__ = (
        UniqueConstraint("finding_id", "evidence_id", name="uq_finding_evidence"),
    )


class CommunityReportEntity(Base):
    """Community threat intelligence report record."""

    __tablename__ = "community_reports"

    report_id = Column(String(128), primary_key=True)
    normalized_domain = Column(String(255), nullable=False, index=True)
    claim_type = Column(String(64), nullable=False)
    note_redacted = Column(String(1000), nullable=True)
    submitted_at = Column(String(64), nullable=False)
    verification_state = Column(String(32), nullable=False, default="unverified", index=True)
    independent_source_count = Column(Integer, nullable=False, default=1)
    source_family = Column(String(128), nullable=False, default="community_user")
    
    # Salted hash of reporter metadata (IP/user ID). Raw identity is NEVER stored.
    reporter_hash = Column(String(64), nullable=False)
    
    reviewed_at = Column(String(64), nullable=True)

    evidence_links = relationship("CommunityReportEvidenceLinkEntity", back_populates="report", cascade="all, delete-orphan")
    audit_events = relationship("ReportAuditEntity", back_populates="report", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_comm_domain_claim", "normalized_domain", "claim_type"),
    )


class CommunityReportEvidenceLinkEntity(Base):
    """Junction linking community reports to supporting evidence IDs."""

    __tablename__ = "community_report_evidence_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String(128), ForeignKey("community_reports.report_id", ondelete="CASCADE"), nullable=False)
    evidence_id = Column(String(128), ForeignKey("evidence_records.evidence_id", ondelete="RESTRICT"), nullable=False)

    report = relationship("CommunityReportEntity", back_populates="evidence_links")


class ReportAuditEntity(Base):
    """Append-only audit trail for community report moderation and transitions."""

    __tablename__ = "community_report_audit_events"

    event_id = Column(String(128), primary_key=True)
    report_id = Column(String(128), ForeignKey("community_reports.report_id", ondelete="CASCADE"), nullable=False, index=True)
    previous_state = Column(String(32), nullable=True)
    new_state = Column(String(32), nullable=False)
    action = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    actor_ref = Column(String(128), nullable=False)
    timestamp = Column(String(64), nullable=False)

    report = relationship("CommunityReportEntity", back_populates="audit_events")
