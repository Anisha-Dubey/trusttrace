"""API routes for Evidence ingestion, retrieval, provenance, and findings."""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, status

from ..schemas import (
    IngestEvidenceRequest,
    CreateFindingRequest,
    StandardResponse,
    PaginatedResponse,
)
from ...evidence.services.evidence_service import EvidenceService
from ...evidence.services.provenance import ProvenanceEngine, ReferentialIntegrityError
from ...evidence.domain.models import EvidenceModel, FindingModel

router = APIRouter(prefix="/api/v1", tags=["Evidence & Findings"])
evidence_service = EvidenceService()
provenance_engine = ProvenanceEngine()


@router.post("/evidence/ingest", status_code=status.HTTP_201_CREATED, response_model=StandardResponse)
def ingest_evidence(payload: IngestEvidenceRequest):
    """Ingest a validated observation record idempotently."""
    try:
        model, was_created = evidence_service.ingest_single_observation(
            scan_id=payload.scan_id,
            payload=payload.model_dump(),
        )
        return StandardResponse(
            status="success",
            data={
                "evidence": model.to_v1_contract_dict(),
                "was_created": was_created,
            },
            message="Evidence created" if was_created else "Duplicate evidence recognized (idempotent)",
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/scans/{scan_id}/evidence", response_model=PaginatedResponse)
def get_scan_evidence(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """Retrieve all evidence observations linked to a specific scan."""
    with evidence_service.db.session_scope() as session:
        items = evidence_service.repo.get_evidence_by_scan(session, scan_id)
        total = len(items)
        paginated = items[offset : offset + limit]
        return PaginatedResponse(
            items=[e.to_v1_contract_dict() for e in paginated],
            total=total,
            limit=limit,
            offset=offset,
        )


@router.get("/evidence/{evidence_id}", response_model=StandardResponse)
def get_single_evidence(evidence_id: str):
    """Retrieve a single evidence record by ID."""
    with evidence_service.db.session_scope() as session:
        model = evidence_service.repo.get_evidence_by_id(session, evidence_id)
        if not model:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found.")
        return StandardResponse(status="success", data=model.to_v1_contract_dict())


@router.post("/scans/{scan_id}/findings", status_code=status.HTTP_201_CREATED, response_model=StandardResponse)
def create_finding(scan_id: str, payload: CreateFindingRequest):
    """Create an evaluated finding linked to supporting evidence records."""
    try:
        finding = evidence_service.add_finding(scan_id=scan_id, finding_payload=payload.model_dump())
        return StandardResponse(status="success", data=finding.to_v1_contract_dict())
    except (ValueError, ReferentialIntegrityError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/scans/{scan_id}/findings", response_model=StandardResponse)
def get_scan_findings(scan_id: str):
    """Retrieve all evaluated findings and their supporting evidence IDs for a scan."""
    with evidence_service.db.session_scope() as session:
        findings = evidence_service.repo.get_findings_by_scan(session, scan_id)
        return StandardResponse(
            status="success",
            data=[f.to_v1_contract_dict() for f in findings],
        )


@router.get("/scans/{scan_id}/coverage", response_model=StandardResponse)
def get_scan_coverage(scan_id: str):
    """Retrieve check coverage arithmetic (total = observed + failed + not_run)."""
    with evidence_service.db.session_scope() as session:
        evidence_items = evidence_service.repo.get_evidence_by_scan(session, scan_id)
        cov = evidence_service.calculate_coverage(evidence_items)
        return StandardResponse(status="success", data=cov.model_dump())


@router.get("/scans/{scan_id}/provenance", response_model=StandardResponse)
def get_scan_provenance(scan_id: str):
    """Retrieve comprehensive provenance, latency, and freshness metadata."""
    summary = provenance_engine.get_scan_provenance_summary(scan_id)
    return StandardResponse(status="success", data=summary)


@router.get("/scans/{scan_id}/report", response_model=StandardResponse)
def get_full_scan_report(scan_id: str):
    """Assemble and retrieve a canonical scan report conforming to scan_report.schema.json."""
    report = evidence_service.get_scan_report(scan_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")
    return StandardResponse(status="success", data=report)
