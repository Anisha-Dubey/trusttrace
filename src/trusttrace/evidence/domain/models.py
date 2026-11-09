"""Domain models and DTOs for Worker 02 matching TRUSTTRACE v1 contracts."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

from .enums import (
    EvidenceStatus,
    Reliability,
    FindingSeverity,
    VerificationState,
    ClaimType,
    ScanStatus,
    ScanDecision,
    IdentityDimension,
    CertificateDimension,
    BehaviorDimension,
    EvidenceQualityDimension,
)


def utc_now_iso() -> str:
    """Return current UTC time in ISO-8601 format with trailing Z."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class EvidenceModel(BaseModel):
    """Normalized evidence record conforming to v1 schema."""

    evidence_id: str = Field(..., description="Unique evidence identifier")
    scan_id: Optional[str] = Field(None, description="Associated scan identifier")
    kind: str = Field(..., description="Evidence category/kind")
    value: Optional[Any] = Field(None, description="Raw or structured evidence payload")
    source: str = Field(..., description="Originating collector or source system")
    source_type: Optional[str] = Field("internal_collector", description="Source classification")
    observed_at: str = Field(..., description="UTC ISO-8601 observation timestamp")
    ingested_at: Optional[str] = Field(default_factory=utc_now_iso, description="UTC ISO-8601 ingestion timestamp")
    status: EvidenceStatus = Field(..., description="Observation outcome state")
    reliability: Optional[Reliability] = Field(None, description="Evidence reliability category")
    limitations: List[str] = Field(default_factory=list, description="Explicit caveats and scope limits")
    schema_version: str = Field("1.0", description="Contract version")

    @field_validator("observed_at", "ingested_at")
    @classmethod
    def validate_utc_timestamp(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            # Parse ISO 8601 string
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception as e:
            raise ValueError(f"Timestamp must be a valid ISO-8601 string: {e}")

    def to_v1_contract_dict(self) -> Dict[str, Any]:
        """Convert to dict matching scan_report.schema.json #/$defs/evidence."""
        d = {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "observed_at": self.observed_at,
            "status": self.status.value,
            "limitations": self.limitations,
        }
        if self.reliability is not None:
            d["reliability"] = self.reliability.value
        return d


class FindingModel(BaseModel):
    """Evaluated finding linked to supporting evidence records."""

    finding_id: str = Field(..., description="Unique finding identifier")
    scan_id: Optional[str] = Field(None, description="Associated scan identifier")
    kind: str = Field(..., description="Finding category/kind")
    severity: FindingSeverity = Field(..., description="Finding severity level")
    summary: str = Field(..., description="Human-readable finding description")
    evidence_ids: List[str] = Field(..., description="Non-empty list of supporting evidence IDs")
    rule_id: str = Field(..., description="Identification of evaluating rule")
    rule_version: str = Field(..., description="Version of evaluating rule")
    created_at: str = Field(default_factory=utc_now_iso, description="UTC ISO-8601 creation timestamp")
    limitations: List[str] = Field(default_factory=list, description="Finding limitations")

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, v: str) -> str:
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception as e:
            raise ValueError(f"Timestamp must be a valid ISO-8601 string: {e}")

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids_non_empty(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("A finding must reference at least one supporting evidence record.")
        return v

    def to_v1_contract_dict(self) -> Dict[str, Any]:
        """Convert to dict matching scan_report.schema.json #/$defs/finding."""
        return {
            "finding_id": self.finding_id,
            "kind": self.kind,
            "severity": self.severity.value,
            "summary": self.summary,
            "evidence_ids": self.evidence_ids,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "created_at": self.created_at,
            "limitations": self.limitations,
        }


class CoverageModel(BaseModel):
    """Coverage counts enforcing the invariant: total = observed + failed + not_run."""

    checks_total: int = Field(..., ge=0)
    checks_observed: int = Field(..., ge=0)
    checks_failed: int = Field(..., ge=0)
    checks_not_run: int = Field(..., ge=0)

    @model_validator(mode="after")
    def validate_coverage_sum(self) -> "CoverageModel":
        total_sum = self.checks_observed + self.checks_failed + self.checks_not_run
        if total_sum != self.checks_total:
            raise ValueError(
                f"Coverage invariant violated: checks_total ({self.checks_total}) "
                f"!= observed ({self.checks_observed}) + failed ({self.checks_failed}) + not_run ({self.checks_not_run})"
            )
        return self


class DimensionsModel(BaseModel):
    """Scan report assessment dimensions."""

    identity: IdentityDimension
    certificate: CertificateDimension
    behavior: BehaviorDimension
    evidence_quality: EvidenceQualityDimension


class CommunityReportModel(BaseModel):
    """Community threat report model conforming to community_report.schema.json."""

    report_id: str
    normalized_domain: str
    claim_type: ClaimType
    note_redacted: Optional[str] = Field(default="", max_length=1000)
    submitted_at: str = Field(default_factory=utc_now_iso)
    verification_state: VerificationState = Field(default=VerificationState.UNVERIFIED)
    independent_source_count: int = Field(default=1, ge=0)
    linked_evidence_ids: List[str] = Field(default_factory=list)
    reviewed_at: Optional[str] = None

    @field_validator("submitted_at")
    @classmethod
    def validate_submitted_at(cls, v: str) -> str:
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception as e:
            raise ValueError(f"submitted_at must be valid ISO-8601: {e}")

    @field_validator("reviewed_at")
    @classmethod
    def validate_reviewed_at(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception as e:
            raise ValueError(f"reviewed_at must be valid ISO-8601: {e}")

    def to_v1_contract_dict(self) -> Dict[str, Any]:
        """Convert to dict matching community_report.schema.json."""
        return {
            "report_id": self.report_id,
            "normalized_domain": self.normalized_domain,
            "claim_type": self.claim_type.value,
            "note_redacted": self.note_redacted,
            "submitted_at": self.submitted_at,
            "verification_state": self.verification_state.value,
            "independent_source_count": self.independent_source_count,
            "linked_evidence_ids": self.linked_evidence_ids,
            "reviewed_at": self.reviewed_at,
        }


class ReportAuditEntry(BaseModel):
    """Audit log entry for moderation and state transition events."""

    event_id: str
    report_id: str
    previous_state: Optional[VerificationState] = None
    new_state: VerificationState
    action: str
    reason: str
    actor_ref: str
    timestamp: str = Field(default_factory=utc_now_iso)
