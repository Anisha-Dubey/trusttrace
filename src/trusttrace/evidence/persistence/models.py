"""SQLAlchemy ORM models for TRUSTTRACE Worker 02."""

from typing import Optional, Any
from sqlalchemy import (
    String,
    Integer,
    Text,
    ForeignKey,
    DateTime,
    Index,
    UniqueConstraint,
    Boolean,
)
from sqlalchemy.orm import relationship, Mapped, mapped_column

from .database import Base


class ScanEntity(Base):
    """Represents a triage scan record."""

    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    submitted_url_redacted: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    decision: Mapped[str] = mapped_column(String(32), nullable=False, default="inconclusive")
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False, default="1.0")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    limitations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    
    # Pre-calculated coverage cached on scan
    coverage_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    coverage_observed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    coverage_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    coverage_not_run: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Relationships
    evidence_items = relationship("EvidenceEntity", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("FindingEntity", back_populates="scan", cascade="all, delete-orphan")


class EvidenceEntity(Base):
    """Persistent representation of an immutable evidence record."""

    __tablename__ = "evidence_records"

    evidence_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(128), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    value_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False, default="internal_collector")
    observed_at: Mapped[str] = mapped_column(String(64), nullable=False)
    ingested_at: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # observed, unavailable, failed, not_run, blocked
    reliability: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # direct_observation, provider_assertion, etc.
    limitations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    
    # Idempotency fingerprint: sha256(scan_id + kind + source + observed_at + status + canonical_value)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    scan = relationship("ScanEntity", back_populates="evidence_items")
    finding_links = relationship("FindingEvidenceLinkEntity", back_populates="evidence", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_evidence_scan_kind", "scan_id", "kind"),
        Index(
            "uq_evidence_scan_fingerprint",
            "scan_id",
            "fingerprint",
            unique=True,
        ),
    )


class FindingEntity(Base):
    """Evaluated finding linked to supporting evidence records."""

    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(128), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    limitations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    scan = relationship("ScanEntity", back_populates="findings")
    evidence_links = relationship("FindingEvidenceLinkEntity", back_populates="finding", cascade="all, delete-orphan")


class FindingEvidenceLinkEntity(Base):
    """Explicit junction table binding findings to their supporting evidence."""

    __tablename__ = "finding_evidence_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(128), ForeignKey("findings.finding_id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(128), ForeignKey("evidence_records.evidence_id", ondelete="RESTRICT"), nullable=False, index=True)

    finding = relationship("FindingEntity", back_populates="evidence_links")
    evidence = relationship("EvidenceEntity", back_populates="finding_links")

    __table_args__ = (
        UniqueConstraint("finding_id", "evidence_id", name="uq_finding_evidence"),
    )


class CommunityReportEntity(Base):
    """Community threat intelligence report record."""

    __tablename__ = "community_reports"

    report_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    normalized_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    claim_type: Mapped[str] = mapped_column(String(64), nullable=False)
    note_redacted: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    submitted_at: Mapped[str] = mapped_column(String(64), nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified", index=True)
    independent_source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    source_family: Mapped[str] = mapped_column(String(128), nullable=False, default="community_user")
    
    # Salted hash of reporter metadata (IP/user ID). Raw identity is NEVER stored.
    reporter_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    
    reviewed_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    evidence_links = relationship("CommunityReportEvidenceLinkEntity", back_populates="report", cascade="all, delete-orphan")
    audit_events = relationship("ReportAuditEntity", back_populates="report", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_comm_domain_claim", "normalized_domain", "claim_type"),
    )


class CommunityReportEvidenceLinkEntity(Base):
    """Junction linking community reports to supporting evidence IDs."""

    __tablename__ = "community_report_evidence_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(String(128), ForeignKey("community_reports.report_id", ondelete="CASCADE"), nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(128), ForeignKey("evidence_records.evidence_id", ondelete="RESTRICT"), nullable=False)

    report = relationship("CommunityReportEntity", back_populates="evidence_links")
    evidence = relationship("EvidenceEntity")

    __table_args__ = (
        UniqueConstraint("report_id", "evidence_id", name="uq_comm_report_evidence"),
    )


class ReportAuditEntity(Base):
    """Append-only audit trail for community report moderation and transitions."""

    __tablename__ = "community_report_audit_events"

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    report_id: Mapped[str] = mapped_column(String(128), ForeignKey("community_reports.report_id", ondelete="CASCADE"), nullable=False, index=True)
    previous_state: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    new_state: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False)

    report = relationship("CommunityReportEntity", back_populates="audit_events")


class CommunityDomainSourceFamilyEntity(Base):
    """Normalized registry binding domains to distinct verified source families.
    
    Database-level uniqueness constraint guarantees that concurrent submissions
    from the same source family can never artificially inflate independent counts (TASK 5).
    """

    __tablename__ = "community_domain_source_families"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    normalized_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_family: Mapped[str] = mapped_column(String(128), nullable=False)
    first_report_id: Mapped[str] = mapped_column(String(128), ForeignKey("community_reports.report_id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    report = relationship("CommunityReportEntity")

    __table_args__ = (
        UniqueConstraint("normalized_domain", "source_family", name="uq_domain_source_family"),
    )


class CommunityDomainCoordinationEntity(Base):
    """Domain-level coordination entity providing multi-process consistency across workers.
    
    Supports row-level locking (SELECT ... FOR UPDATE) on PostgreSQL and transactional
    coordination on SQLite (TASK 5).
    """

    __tablename__ = "community_domain_coordination"

    normalized_domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    active_claim: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_disputed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
