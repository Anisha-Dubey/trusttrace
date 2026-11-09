"""API routes for Community Intelligence lifecycle, deduplication, and moderation."""

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, Request, Security, status

from ..schemas import (
    SubmitCommunityReportRequest,
    ReviewCommunityReportRequest,
    StandardResponse,
    PaginatedResponse,
)
from ..auth import AuthenticatedUser, require_roles, verify_bearer_token
from ...evidence.community.service import CommunityIntelligenceService
from ...evidence.community.moderation import ModerationService
from ...evidence.community.rate_limiter import (
    default_rate_limiter,
    RateLimitExceededError,
    ReplaySubmissionError,
)
from ...evidence.community.state_machine import InvalidStateTransitionError
from ...evidence.domain.enums import VerificationState, ClaimType

router = APIRouter(prefix="/api/v1/community", tags=["Community Intelligence"])
community_service = CommunityIntelligenceService()
moderation_service = ModerationService(community_service=community_service)


@router.post("/reports", status_code=status.HTTP_201_CREATED, response_model=StandardResponse)
def submit_community_report(payload: SubmitCommunityReportRequest, request: Request):
    """Submit a community threat report.
    
    Security controls applied:
    - Sliding window rate limiting per IP and domain.
    - Replay protection against rapid burst resubmissions.
    - Source family verification: only authenticated provider feeds can claim verified feed identities.
    - Text sanitization against stored XSS (COMM-004).
    - Salted HMAC-SHA256 reporter pseudonymization (DATA-002).
    - Default unverified verification state.
    """
    client_ip = request.client.host if request.client else "unknown_client"

    # 1. Rate limiting & replay protection
    try:
        default_rate_limiter.check_and_record(
            client_ip=client_ip,
            normalized_domain=payload.normalized_domain,
            claim_type=payload.claim_type.value,
        )
    except (RateLimitExceededError, ReplaySubmissionError) as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
            headers={"Retry-After": "60"},
        )

    # 2. Check for authenticated feed provider privileges
    is_provider = False
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        user = verify_bearer_token(token)
        if user and (user.has_role("collector") or user.has_role("admin")):
            is_provider = True

    try:
        report, dedup_res = community_service.submit_report(
            normalized_domain=payload.normalized_domain,
            claim_type=payload.claim_type.value,
            note=payload.note,
            raw_reporter_identifier=client_ip,
            source_family=payload.source_family,
            linked_evidence_ids=payload.linked_evidence_ids,
            is_authenticated_provider=is_provider,
        )
        return StandardResponse(
            status="success",
            data={
                "report": report.to_v1_contract_dict(),
                "deduplication": {
                    "category": dedup_res.category.value,
                    "matched_report_id": dedup_res.matched_report_id,
                    "explanation": dedup_res.explanation,
                    "is_conflict": dedup_res.is_conflict,
                },
            },
            message="Report submitted successfully",
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/reports", response_model=PaginatedResponse)
def list_community_reports(
    domain: Optional[str] = Query(None, description="Filter by normalized domain"),
    state: Optional[VerificationState] = Query(None, description="Filter by verification state"),
    claim_type: Optional[ClaimType] = Query(None, description="Filter by claim type"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List community reports with optional filtering by domain, verification state, and claim type."""
    with community_service.db.session_scope() as session:
        entities = community_service.repo.find_community_reports(
            session=session,
            normalized_domain=domain.lower() if domain else None,
            verification_state=state,
            claim_type=claim_type,
        )
        total = len(entities)
        paginated_entities = entities[offset : offset + limit]

        reports = []
        for e in paginated_entities:
            rep = community_service.repo.get_community_report(session, e.report_id)
            if rep:
                reports.append(rep.to_v1_contract_dict())

        return PaginatedResponse(
            items=reports,
            total=total,
            limit=limit,
            offset=offset,
        )


@router.get("/reports/{report_id}", response_model=StandardResponse)
def get_community_report(report_id: str):
    """Retrieve a single community report by ID."""
    rep = community_service.get_report(report_id)
    if not rep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Community report '{report_id}' not found.")
    return StandardResponse(status="success", data=rep.to_v1_contract_dict())


@router.post("/reports/{report_id}/review", response_model=StandardResponse)
def review_community_report(
    report_id: str,
    payload: ReviewCommunityReportRequest,
    moderator: AuthenticatedUser = Security(require_roles(["moderator", "admin"])),
):
    """Perform an authenticated moderation review on a community report.
    
    Security controls applied:
    - Enforces verified Bearer token with 'moderator' or 'admin' role.
    - Moderator identity is strictly derived from the authenticated session (never from client request body).
    - Corroboration count override is prohibited; counts are strictly derived server-side.
    """
    try:
        updated = moderation_service.review_report(
            report_id=report_id,
            target_state=payload.target_state,
            reason=payload.reason,
            moderator_ref=moderator.username,
        )
        return StandardResponse(
            status="success",
            data=updated.to_v1_contract_dict(),
            message=f"Report state updated to '{updated.verification_state.value}' by {moderator.username}",
        )
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Community report '{report_id}' not found.")
    except (ValueError, InvalidStateTransitionError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/reports/{report_id}/audit", response_model=StandardResponse)
def get_report_audit_trail(report_id: str):
    """Retrieve the chronological audit history for a report."""
    trail = moderation_service.get_audit_trail(report_id)
    return StandardResponse(
        status="success",
        data=[item.model_dump() for item in trail],
    )


@router.get("/domain/{domain}/audit", response_model=StandardResponse)
def get_domain_audit_history(domain: str):
    """Retrieve the collective audit history across all reports filed for a domain."""
    domain_history = moderation_service.get_domain_audit_history(domain)
    return StandardResponse(
        status="success",
        data=[item.model_dump() for item in domain_history],
    )
