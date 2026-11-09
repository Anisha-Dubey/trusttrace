"""API request and response schemas for TRUSTTRACE."""

from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field
from datetime import datetime

from ..evidence.domain.enums import (
    EvidenceStatus,
    Reliability,
    FindingSeverity,
    VerificationState,
    ClaimType,
)


class IngestEvidenceRequest(BaseModel):
    """Payload for submitting an observation directly or from collectors."""
    scan_id: str
    kind: str
    value: Optional[Any] = None
    source: str
    source_type: Optional[str] = "internal_collector"
    observed_at: Optional[str] = None
    status: EvidenceStatus
    reliability: Optional[Reliability] = None
    limitations: List[str] = Field(default_factory=list)
    schema_version: str = "1.0"


class CreateFindingRequest(BaseModel):
    """Payload for creating a finding referencing evidence."""
    kind: str
    severity: FindingSeverity
    summary: str
    evidence_ids: List[str]
    rule_id: str
    rule_version: str
    limitations: List[str] = Field(default_factory=list)


class SubmitCommunityReportRequest(BaseModel):
    """Payload for submitting a community threat intelligence claim."""
    normalized_domain: str
    claim_type: ClaimType
    note: Optional[str] = Field("", max_length=1000)
    source_family: Optional[str] = "community_user"
    linked_evidence_ids: List[str] = Field(default_factory=list)


class ReviewCommunityReportRequest(BaseModel):
    """Payload for moderating or transitioning a community report.
    
    Moderator identity is derived exclusively from the authenticated session token.
    Independent corroboration counts are strictly computed server-side.
    """
    target_state: VerificationState
    reason: str = Field(..., min_length=5)


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
