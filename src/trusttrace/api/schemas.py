"""API request and response schemas for TRUSTTRACE."""

import re
import json
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field, field_validator
from datetime import datetime

from ..evidence.domain.enums import (
    EvidenceStatus,
    Reliability,
    FindingSeverity,
    VerificationState,
    ClaimType,
)


def validate_domain_name(v: str) -> str:
    """Validate that a string conforms to a valid hostname / domain name (RFC 1035 / RFC 1123)."""
    if not v or not v.strip():
        raise ValueError("Domain name cannot be empty.")
    cleaned = v.strip().lower()
    if cleaned.startswith("http://") or cleaned.startswith("https://") or "://" in cleaned or "/" in cleaned or "?" in cleaned or "#" in cleaned:
        raise ValueError("Domain must be a clean hostname/domain, not a URL (protocols, paths, queries, and fragments prohibited).")
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]
    if len(cleaned) > 253:
        raise ValueError("Domain name exceeds maximum RFC 1035 length of 253 characters.")
    try:
        encoded = cleaned.encode("idna").decode("ascii")
    except Exception:
        raise ValueError(f"Domain '{v}' cannot be converted to valid IDNA Punycode.")
    labels = encoded.split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError(f"Domain label '{label}' is invalid or exceeds 63 characters.")
        if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", label):
            raise ValueError(f"Domain label '{label}' contains invalid characters.")
    return cleaned


class IngestEvidenceRequest(BaseModel):
    """Payload for submitting an observation directly or from collectors."""
    scan_id: str = Field(..., min_length=1, max_length=128)
    kind: str = Field(..., min_length=1, max_length=64)
    value: Optional[Any] = None
    source: str = Field(..., min_length=1, max_length=128)
    source_type: Optional[str] = Field("internal_collector", max_length=64)
    observed_at: Optional[str] = None
    status: EvidenceStatus
    reliability: Optional[Reliability] = None
    limitations: List[str] = Field(default_factory=list, max_length=50)
    schema_version: str = "1.0"

    @field_validator("value")
    @classmethod
    def validate_value_size(cls, v: Optional[Any]) -> Optional[Any]:
        if v is not None:
            serialized = json.dumps(v, default=str)
            if len(serialized) > 1024 * 1024:  # 1MB limit
                raise ValueError("Evidence payload value exceeds maximum allowed size of 1MB.")
        return v


class CreateFindingRequest(BaseModel):
    """Payload for creating a finding referencing evidence."""
    kind: str = Field(..., min_length=1, max_length=64)
    severity: FindingSeverity
    summary: str = Field(..., min_length=1, max_length=2000)
    evidence_ids: List[str] = Field(..., min_length=1, max_length=100)
    rule_id: str = Field(..., min_length=1, max_length=64)
    rule_version: str = Field(..., min_length=1, max_length=32)
    limitations: List[str] = Field(default_factory=list, max_length=50)


class SubmitCommunityReportRequest(BaseModel):
    """Payload for submitting a community threat intelligence claim."""
    normalized_domain: str = Field(..., min_length=1, max_length=255)
    claim_type: ClaimType
    note: Optional[str] = Field("", max_length=1000)
    source_family: Optional[str] = "community_user"
    linked_evidence_ids: List[str] = Field(default_factory=list, max_length=50)

    @field_validator("normalized_domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return validate_domain_name(v)


class ReviewCommunityReportRequest(BaseModel):
    """Payload for moderating or transitioning a community report.
    
    Moderator identity is derived exclusively from the authenticated session token.
    Independent corroboration counts are strictly computed server-side.
    """
    target_state: VerificationState
    reason: str = Field(..., min_length=5, max_length=1000)


class StandardResponse(BaseModel):
    """Standard unified response envelope."""
    status: str = "success"
    data: Any
    message: Optional[str] = None


class PaginatedResponse(BaseModel):
    """Pagination wrapper."""
    items: List[Any]
    total: int
    limit: int
    offset: int
