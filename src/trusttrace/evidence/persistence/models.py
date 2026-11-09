"""SQLAlchemy ORM models for TRUSTTRACE Worker 02."""

from typing import Optional, Any
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

    scan_id: str = Column(String(128), primary_key=True)  # type: ignore
    submitted_url_redacted: str = Column(Text, nullable=False)  # type: ignore
    normalized_host: Optional[str] = Column(String(255), nullable=True, index=True)  # type: ignore
    status: str = Column(String(32), nullable=False, default="queued")  # type: ignore
    decision: str = Column(String(32), nullable=False, default="inconclusive")  # type: ignore
    policy_version: str = Column(String(64), nullable=False, default="1.0")  # type: ignore
    created_at: str = Column(String(64), nullable=False)  # type: ignore
    completed_at: Optional[str] = Column(String(64), nullable=True)  # type: ignore
    limitations_json: str = Column(Text, nullable=False, default="[]")  # type: ignore
    
    # Pre-calculated coverage cached on scan
    coverage_total: int = Column(Integer, nullable=False, default=0)  # type: ignore
    coverage_observed: int = Column(Integer, nullable=False, default=0)  # type: ignore
    coverage_failed: int = Column(Integer, nullable=False, default=0)  # type: ignore
    coverage_not_run: int = Column(Integer, nullable=False, default=0)  # type: ignore

    # Relationships
    evidence_items = relationship("EvidenceEntity", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("FindingEntity", back_populates="scan", cascade="all, delete-orphan")


class EvidenceEntity(Base):
    """Persistent representation of an immutable evidence record."""

    __tablename__ = "evidence_records"

    evidence_id: str = Column(String(128), primary_key=True)  # type: ignore
    scan_id: str = Column(String(128), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)  # type: ignore
    kind: str = Column(String(64), nullable=False, index=True)  # type: ignore
    value_json: Optional[str] = Column(Text, nullable=True)  # type: ignore
    source: str = Column(String(128), nullable=False, index=True)  # type: ignore
    source_type: str = Column(String(64), nullable=False, default="internal_collector")  # type: ignore
    observed_at: str = Column(String(64), nullable=False)  # type: ignore
    ingested_at: str = Column(String(64), nullable=False)  # type: ignore
    status: str = Column(String(32), nullable=False)  # observed, unavailable, failed, not_run, blocked  # type: ignore
    reliability: Optional[str] = Column(String(64), nullable=True)  # direct_observation, provider_assertion, etc.  # type: ignore
    limitations_json: str = Column(Text, nullable=False, default="[]")  # type: ignore
    schema_version: str = Column(String(16), nullable=False, default="1.0")  # type: ignore
    
    # Idempotency fingerprint: sha256(scan_id + kind + source + observed_at + status + canonical_value)
    fingerprint: str = Column(String(64), nullable=False)  # type: ignore

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

    finding_id: str = Column(String(128), primary_key=True)  # type: ignore
    scan_id: str = Column(String(128), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)  # type: ignore
    kind: str = Column(String(64), nullable=False)  # type: ignore
    severity: str = Column(String(32), nullable=False)  # type: ignore
    summary: str = Column(Text, nullable=False)  # type: ignore
    rule_id: str = Column(String(64), nullable=False)  # type: ignore
    rule_version: str = Column(String(32), nullable=False)  # type: ignore
    created_at: str = Column(String(64), nullable=False)  # type: ignore
    limitations_json: str = Column(Text, nullable=False, default="[]")  # type: ignore

    scan = relationship("ScanEntity", back_populates="findings")
    evidence_links = relationship("FindingEvidenceLinkEntity", back_populates="finding", cascade="all, delete-orphan")


class FindingEvidenceLinkEntity(Base):
    """Explicit junction table binding findings to their supporting evidence."""

    __tablename__ = "finding_evidence_links"

    id: int = Column(Integer, primary_key=True, autoincrement=True)  # type: ignore
    finding_id: str = Column(String(128), ForeignKey("findings.finding_id", ondelete="CASCADE"), nullable=False, index=True)  # type: ignore
    evidence_id: str = Column(String(128), ForeignKey("evidence_records.evidence_id", ondelete="RESTRICT"), nullable=False, index=True)  # type: ignore

    finding = relationship("FindingEntity", back_populates="evidence_links")
    evidence = relationship("EvidenceEntity", back_populates="finding_links")

    __table_args__ = (
        UniqueConstraint("finding_id", "evidence_id", name="uq_finding_evidence"),
    )


class CommunityReportEntity(Base):
    """Community threat intelligence report record."""

    __tablename__ = "community_reports"

    report_id: str = Column(String(128), primary_key=True)  # type: ignore
    normalized_domain: str = Column(String(255), nullable=False, index=True)  # type: ignore
    claim_type: str = Column(String(64), nullable=False)  # type: ignore
    note_redacted: Optional[str] = Column(String(1000), nullable=True)  # type: ignore
    submitted_at: str = Column(String(64), nullable=False)  # type: ignore
    verification_state: str = Column(String(32), nullable=False, default="unverified", index=True)  # type: ignore
    independent_source_count: int = Column(Integer, nullable=False, default=1)  # type: ignore
    source_family: str = Column(String(128), nullable=False, default="community_user")  # type: ignore
    
    # Salted hash of reporter metadata (IP/user ID). Raw identity is NEVER stored.
    reporter_hash: str = Column(String(64), nullable=False)  # type: ignore
    
    reviewed_at: Optional[str] = Column(String(64), nullable=True)  # type: ignore

    evidence_links = relationship("CommunityReportEvidenceLinkEntity", back_populates="report", cascade="all, delete-orphan")
    audit_events = relationship("ReportAuditEntity", back_populates="report", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_comm_domain_claim", "normalized_domain", "claim_type"),
    )


class CommunityReportEvidenceLinkEntity(Base):
    """Junction linking community reports to supporting evidence IDs."""

    __tablename__ = "community_report_evidence_links"

    id: int = Column(Integer, primary_key=True, autoincrement=True)  # type: ignore
    report_id: str = Column(String(128), ForeignKey("community_reports.report_id", ondelete="CASCADE"), nullable=False)  # type: ignore
    evidence_id: str = Column(String(128), ForeignKey("evidence_records.evidence_id", ondelete="RESTRICT"), nullable=False)  # type: ignore

    report = relationship("CommunityReportEntity", back_populates="evidence_links")
    evidence = relationship("EvidenceEntity")

    __table_args__ = (
        UniqueConstraint("report_id", "evidence_id", name="uq_comm_report_evidence"),
    )


class ReportAuditEntity(Base):
    """Append-only audit trail for community report moderation and transitions."""

    __tablename__ = "community_report_audit_events"

    event_id: str = Column(String(128), primary_key=True)  # type: ignore
    report_id: str = Column(String(128), ForeignKey("community_reports.report_id", ondelete="CASCADE"), nullable=False, index=True)  # type: ignore
    previous_state: Optional[str] = Column(String(32), nullable=True)  # type: ignore
    new_state: str = Column(String(32), nullable=False)  # type: ignore
    action: str = Column(String(64), nullable=False)  # type: ignore
    reason: str = Column(Text, nullable=False)  # type: ignore
    actor_ref: str = Column(String(128), nullable=False)  # type: ignore
    timestamp: str = Column(String(64), nullable=False)  # type: ignore

    report = relationship("CommunityReportEntity", back_populates="audit_events")
