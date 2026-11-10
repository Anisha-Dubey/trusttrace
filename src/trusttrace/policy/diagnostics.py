"""Structured Diagnostics Engine for Worker 03 Phase 03.

Provides structured diagnostic records and auditing for anomalies, policy suppressions,
unsupported evidence kinds, target mismatches, coverage deficits, and orphan findings.

Invariants:
1. Zero silent suppression: Every suppressed signal, dropped finding, or validation
   failure produces an explicit, structured DiagnosticRecord.
2. Immutability: Diagnostic records are frozen dataclasses; nested details are read-only.
3. Pure Python standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


class DiagnosticCode(str, Enum):
    """Structured diagnostic codes for evidence interpretation and triage."""

    INPUT_PARSE_ERROR = "input_parse_error"
    DUPLICATE_EVIDENCE_ID = "duplicate_evidence_id"
    UNSUPPORTED_EVIDENCE_KIND = "unsupported_evidence_kind"
    MALFORMED_PAYLOAD = "malformed_payload"
    TARGET_SCOPE_MISMATCH = "target_scope_mismatch"
    UNVERIFIED_THREAT_PROVENANCE = "unverified_threat_provenance"
    UNVERIFIED_COMMUNITY_REPORT = "unverified_community_report"
    UNLINKED_COMMUNITY_REPORT = "unlinked_community_report"
    ORPHAN_FINDING_SUPPRESSED = "orphan_finding_suppressed"
    BLOCKED_DESTINATION_POLICY = "blocked_destination_policy"
    COVERAGE_DEFICIT = "coverage_deficit"
    STALE_EVIDENCE_FLAGGED = "stale_evidence_flagged"


class DiagnosticSeverity(str, Enum):
    """Severity levels for diagnostic records."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class DiagnosticRecord:
    """Immutable structured audit record for an evidence or triage diagnostic event.

    Attributes:
        code: DiagnosticCode identifying the specific anomaly or suppression reason.
        severity: DiagnosticSeverity (info, warning, error).
        message: Human-readable diagnostic description.
        evidence_ids: Supporting or affected evidence item identifiers.
        action_taken: Explicit description of policy action taken (e.g. "Signal suppressed").
        details: Read-only mapping of auxiliary context for auditability.
    """

    code: DiagnosticCode
    severity: DiagnosticSeverity
    message: str
    evidence_ids: Tuple[str, ...] = field(default_factory=tuple)
    action_taken: str = "none"
    details: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def to_dict(self) -> Dict[str, Any]:
        """Convert diagnostic record to dictionary."""
        return {
            "code": self.code.value,
            "severity": self.severity.value,
            "message": self.message,
            "evidence_ids": list(self.evidence_ids),
            "action_taken": self.action_taken,
            "details": dict(self.details),
        }


class DiagnosticCollector:
    """Thread-safe, append-only collector for diagnostic records during pipeline execution."""

    def __init__(self) -> None:
        self._records: List[DiagnosticRecord] = []

    def record(
        self,
        code: DiagnosticCode,
        severity: DiagnosticSeverity,
        message: str,
        evidence_ids: Sequence[str] = (),
        action_taken: str = "none",
        details: Optional[Mapping[str, Any]] = None,
    ) -> DiagnosticRecord:
        """Create, append, and return a frozen DiagnosticRecord."""
        frozen_details = MappingProxyType(dict(details)) if details is not None else MappingProxyType({})
        rec = DiagnosticRecord(
            code=code,
            severity=severity,
            message=message,
            evidence_ids=tuple(evidence_ids),
            action_taken=action_taken,
            details=frozen_details,
        )
        self._records.append(rec)
        return rec

    def extend(self, records: Sequence[DiagnosticRecord]) -> None:
        """Append multiple diagnostic records."""
        self._records.extend(records)

    @property
    def records(self) -> Tuple[DiagnosticRecord, ...]:
        """Return an immutable snapshot of all collected diagnostic records."""
        return tuple(self._records)

    def has_errors(self) -> bool:
        """Return True if any collected diagnostic is of severity ERROR."""
        return any(r.severity == DiagnosticSeverity.ERROR for r in self._records)

    def by_code(self, code: DiagnosticCode) -> Tuple[DiagnosticRecord, ...]:
        """Filter collected records by diagnostic code."""
        return tuple(r for r in self._records if r.code == code)

    def to_dict_list(self) -> List[Dict[str, Any]]:
        """Serialize all records to a list of dictionaries."""
        return [r.to_dict() for r in self._records]

