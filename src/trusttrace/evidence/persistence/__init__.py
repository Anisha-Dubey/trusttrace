"""Persistence layer exports for Worker 02."""

from .database import DatabaseManager, default_db, Base
from .models import (
    ScanEntity,
    EvidenceEntity,
    FindingEntity,
    FindingEvidenceLinkEntity,
    CommunityReportEntity,
    CommunityReportEvidenceLinkEntity,
    ReportAuditEntity,
)
from .repository import EvidenceRepository, compute_evidence_fingerprint

__all__ = [
    "DatabaseManager",
    "default_db",
    "Base",
    "ScanEntity",
    "EvidenceEntity",
    "FindingEntity",
    "FindingEvidenceLinkEntity",
    "CommunityReportEntity",
    "CommunityReportEvidenceLinkEntity",
    "ReportAuditEntity",
    "EvidenceRepository",
    "compute_evidence_fingerprint",
]
