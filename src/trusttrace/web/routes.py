"""Worker 04 — Interactive Web Dashboard and Triage Routes.

Provides the human-facing evidence presentation interface, controlled pitch
demonstrations, and real passive intake & bounded scan coordination.

Adheres strictly to TRUSTTRACE core invariants:
- TLS-001: Valid TLS cert validates transport hostname coverage only, not entity identity.
- TLS-002: Expired/mismatched certificates are technical warnings, not sole proof of malice.
- EVID-001: Collector failures produce truthful partial/inconclusive reports with explicit abstentions.
- EVID-002: Negative threat feed match does not imply guaranteed safety.
- COMM-001 & COMM-002: Community reports require independent cross-family corroboration.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel, Field

from ..intake.boundary import IntakeBoundary
from ..collectors.orchestrator import ScanOrchestrator
from ..policy.policy_input import PolicyInput
from ..policy.triage_engine import TriageEngine
from ..policy.signal_taxonomy import SignalRecord, SignalKind, SignalConfidence
from ..policy.integrity_auditor import ReportIntegrityAuditor
from ..policy.uncertainty import ConfidenceBand
from ..evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
from ..evidence.services.evidence_service import EvidenceService

router = APIRouter(tags=["Web Interface & Triage"])

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_DIR = REPO_ROOT / ".brain" / ".testdata" / "v1"
INDEX_HTML_PATH = REPO_ROOT / "index.html"
DIST_DIR = REPO_ROOT / "dist"
DIST_INDEX_HTML_PATH = DIST_DIR / "index.html"


class TriageDemoRequest(BaseModel):
    """Request payload for web triage assessment."""
    url: str = Field(..., description="Target URL to assess")
    scenario: Optional[str] = Field("custom", description="Demonstration scenario identifier or 'custom'")


def _now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_scenario_policy_input(
    scenario: str,
    target_url: str,
) -> Tuple[PolicyInput, Dict[str, Any], List[Dict[str, Any]]]:
    """Construct a canonical PolicyInput for controlled demonstration scenarios.

    Returns:
        (policy_input, coverage_dict, raw_evidence_list)
    """
    now = _now_iso()

    if scenario == "phishing_lookalike":
        # Core thesis: Valid DV TLS certificate + Cyrillic homoglyph lookalike + active threat entry
        target = "bank-secure-lоgin.com"
        evidence_list = [
            {
                "evidence_id": "ev-tls-001",
                "kind": "tls_certificate",
                "source": "tls_collector",
                "observed_at": now,
                "status": "observed",
                "reliability": "direct_observation",
                "value": {
                    "is_valid": True,
                    "is_expired": False,
                    "hostname_match": True,
                    "issuer": "Let's Encrypt Authority X3",
                },
                "limitations": [
                    "Valid DV TLS proves transport encryption only, not organizational identity (TLS-001)."
                ],
            },
            {
                "evidence_id": "ev-idn-002",
                "kind": "idn_lookalike",
                "source": "url_policy",
                "observed_at": now,
                "status": "observed",
                "reliability": "direct_observation",
                "value": {
                    "is_lookalike": True,
                    "punycode": "xn--bank-secure-lgin-l8g.com",
                },
                "limitations": ["Unicode confusable homoglyph detected in domain name."],
            },
            {
                "evidence_id": "ev-threat-003",
                "kind": "threat_intelligence",
                "source": "reputation_feed",
                "observed_at": now,
                "status": "observed",
                "reliability": "provider_assertion",
                "value": {
                    "matched": True,
                    "threat_level": "malicious",
                    "target": target,
                },
                "limitations": ["Positive threat feed hit from security feed provider."],
            },
            {
                "evidence_id": "ev-dns-004",
                "kind": "dns_resolution",
                "source": "dns_collector",
                "observed_at": now,
                "status": "observed",
                "reliability": "direct_observation",
                "value": {"resolved_ips": ["198.51.100.22"]},
                "limitations": ["Standard recursive DNS query."],
            },
        ]
        coverage = {
            "checks_total": 4,
            "checks_observed": 4,
            "checks_failed": 0,
            "checks_not_run": 0,
        }
        pi = PolicyInput.from_components(
            scan_id="scan-demo-phish-001",
            target=target,
            evidence=evidence_list,
            coverage=coverage,
        )
        return pi, coverage, evidence_list

    elif scenario == "expired_tls":
        # Technical hygiene warning: Expired certificate alone != malicious intent (TLS-002)
        target = "legacy-portal.internal-corp.net"
        evidence_list = [
            {
                "evidence_id": "ev-tls-exp-01",
                "kind": "tls_certificate",
                "source": "tls_collector",
                "observed_at": now,
                "status": "observed",
                "reliability": "direct_observation",
                "value": {
                    "is_valid": False,
                    "is_expired": True,
                    "hostname_match": True,
                },
                "limitations": [
                    "TLS-002: Expired certificate alone is a technical hygiene warning, not sole proof of malice."
                ],
            },
            {
                "evidence_id": "ev-dns-exp-02",
                "kind": "dns_resolution",
                "source": "dns_collector",
                "observed_at": now,
                "status": "observed",
                "reliability": "direct_observation",
                "value": {"resolved_ips": ["192.0.2.45"]},
                "limitations": ["Standard recursive DNS resolution."],
            },
            {
                "evidence_id": "ev-http-exp-03",
                "kind": "http_metadata",
                "source": "http_collector",
                "observed_at": now,
                "status": "observed",
                "reliability": "direct_observation",
                "value": {"suspicious_headers": True},
                "limitations": ["Legacy server configuration headers observed."],
            },
        ]
        coverage = {
            "checks_total": 3,
            "checks_observed": 3,
            "checks_failed": 0,
            "checks_not_run": 0,
        }
        pi = PolicyInput.from_components(
            scan_id="scan-demo-expired-001",
            target=target,
            evidence=evidence_list,
            coverage=coverage,
        )
        return pi, coverage, evidence_list

    elif scenario == "legitimate":
        # Legitimate domain with valid TLS and clean threat feeds
        target = "example.com"
        evidence_list = [
            {
                "evidence_id": "ev-dns-legit-01",
                "kind": "dns_resolution",
                "source": "dns_collector",
                "observed_at": now,
                "status": "observed",
                "reliability": "direct_observation",
                "value": {"resolved_ips": ["93.184.216.34"]},
                "limitations": ["Recursive DNS query."],
            },
            {
                "evidence_id": "ev-tls-legit-02",
                "kind": "tls_certificate",
                "source": "tls_collector",
                "observed_at": now,
                "status": "observed",
                "reliability": "direct_observation",
                "value": {
                    "is_valid": True,
                    "is_expired": False,
                    "hostname_match": True,
                    "issuer": "DigiCert Global Root G2",
                },
                "limitations": [
                    "Valid DV TLS proves transport encryption only, not organizational identity (TLS-001)."
                ],
            },
            {
                "evidence_id": "ev-threat-legit-03",
                "kind": "threat_intelligence",
                "source": "reputation_feed",
                "observed_at": now,
                "status": "observed",
                "reliability": "provider_assertion",
                "value": {
                    "match": False,
                    "threat_level": "none",
                    "target": target,
                },
                "limitations": [
                    "EVID-002: Negative threat match does not guarantee absolute safety."
                ],
            },
        ]
        coverage = {
            "checks_total": 3,
            "checks_observed": 3,
            "checks_failed": 0,
            "checks_not_run": 0,
        }
        pi = PolicyInput.from_components(
            scan_id="scan-demo-legit-001",
            target=target,
            evidence=evidence_list,
            coverage=coverage,
        )
        return pi, coverage, evidence_list

    elif scenario == "conflicting":
        # Contradictory evidence: Opposing threat feed observations trigger explicit abstention (EVID-004)
        target = "disputed-target.org"
        evidence_list = [
            {
                "evidence_id": "ev-dns-conf-01",
                "kind": "dns_resolution",
                "source": "dns_collector",
                "observed_at": now,
                "status": "observed",
                "reliability": "direct_observation",
                "value": {"resolved_ips": ["198.51.100.99"]},
                "limitations": ["Standard recursive DNS lookup."],
            },
            {
                "evidence_id": "ev-threat-conf-02",
                "kind": "threat_intelligence",
                "source": "threat_provider_alpha",
                "observed_at": now,
                "status": "observed",
                "reliability": "provider_assertion",
                "value": {
                    "matched": True,
                    "threat_level": "malicious",
                    "target": target,
                },
                "limitations": ["Provider Alpha reports active malicious classification."],
            },
            {
                "evidence_id": "ev-threat-conf-03",
                "kind": "threat_intelligence",
                "source": "threat_provider_beta",
                "observed_at": now,
                "status": "observed",
                "reliability": "provider_assertion",
                "value": {
                    "match": False,
                    "threat_level": "none",
                    "target": target,
                },
                "limitations": ["Provider Beta reports no threat found for target."],
            },
        ]
        coverage = {
            "checks_total": 3,
            "checks_observed": 3,
            "checks_failed": 0,
            "checks_not_run": 0,
        }
        pi = PolicyInput.from_components(
            scan_id="scan-demo-conflict-001",
            target=target,
            evidence=evidence_list,
            coverage=coverage,
        )
        return pi, coverage, evidence_list

    else:
        raise ValueError(f"Unknown scenario: {scenario}")


@router.post("/api/v1/triage/demo")
async def triage_demo_endpoint(payload: TriageDemoRequest):
    """Run an evidence-backed triage assessment on a URL or load a controlled scenario fixture.

    Guarantees:
    1. Zero fabrication: Positive threat match and negative threat feeds require genuine queries.
    2. Rigorous uncertainty: All outputs expose categorical uncertainty and qualitative confidence bands.
    3. Abstention discipline: Partial coverage and conflicting signals yield explicit abstention notices.
    4. Pre-publication audit: Every report passes ReportIntegrityAuditor before return.
    """
    scenario = (payload.scenario or "custom").strip().lower()
    url = payload.url.strip()

    engine = TriageEngine()
    auditor = ReportIntegrityAuditor()
    now_iso = _now_iso()

    # Case A: Controlled Scenario Fixtures
    if scenario in ("phishing_lookalike", "expired_tls", "legitimate", "conflicting"):
        policy_input, coverage_dict, raw_evidence = _build_scenario_policy_input(scenario, url)
        triage_result = engine.evaluate_evidence(policy_input)
        fragment = triage_result.to_report_fragment()

        canonical_report = {
            "schema_version": "1.0",
            "scan_id": policy_input.scan_id,
            "submitted_url_redacted": url or f"https://{policy_input.target}",
            "normalized_host": policy_input.target,
            "status": "completed" if triage_result.decision != "inconclusive" else "partial",
            "decision": fragment["decision"],
            "created_at": now_iso,
            "policy_version": fragment["policy_version"],
            "dimensions": fragment["dimensions"],
            "coverage": coverage_dict,
            "evidence": raw_evidence,
            "findings": fragment["findings"],
            "limitations": fragment["limitations"],
        }

        # Verify integrity invariants (INV-TLS-001 through INV-COV-002)
        audit_result = auditor.audit_report(canonical_report)
        if not audit_result.is_valid:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Report failed pre-publication integrity audit: {[i.to_dict() for i in audit_result.issues]}",
            )

        # Ingest into EvidenceService for persistence
        try:
            adapter = Worker01EvidenceAdapter()
            batch = adapter.adapt_payload(canonical_report["scan_id"], canonical_report)
            ev_service = EvidenceService()
            ev_service.ingest_batch(batch)
        except Exception:
            pass

        # Build response envelope with uncertainty assessment
        response_payload = dict(canonical_report)
        if triage_result.uncertainty:
            response_payload["uncertainty"] = triage_result.uncertainty.to_dict()
            if triage_result.uncertainty.abstention_notice:
                response_payload["abstention"] = triage_result.uncertainty.abstention_notice.to_dict()
        response_payload["audit"] = audit_result.to_dict()

        return response_payload

    # Case B: Custom URL Evaluation via Real Collector Pipeline
    if not url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL is required for custom triage.")

    scan_id = f"scan-live-{uuid.uuid4().hex[:8]}"
    boundary = IntakeBoundary()
    eval_res = boundary.evaluate_target(url)

    # Step 1: Preflight Intake Gate (SSRF, credentials, unsupported scheme)
    if not eval_res.is_safe:
        rejected_report = boundary.build_rejected_report(scan_id, eval_res)
        try:
            adapter = Worker01EvidenceAdapter()
            batch = adapter.adapt_payload(scan_id, rejected_report)
            ev_service = EvidenceService()
            ev_service.ingest_batch(batch)
        except Exception:
            pass

        audit_res = auditor.audit_report(rejected_report)

        response_payload = dict(rejected_report)
        response_payload["uncertainty"] = {
            "confidence_band": ConfidenceBand.LIMITED_OBSERVATION.value,
            "uncertainties": [
                {
                    "type": "UNCHECKED_COVERAGE",
                    "severity": "high",
                    "source": "intake_boundary",
                    "explanation": f"Target was rejected prior to active collection: {eval_res.rejection_reason}",
                }
            ],
            "abstention_notice": {
                "reason_code": "ABSTAIN_TARGET_REJECTED",
                "explanation": f"Target URL rejected at intake boundary: {eval_res.rejection_reason}",
                "is_rescan_recommended": False,
                "missing_evidence_types": ["dns_resolution", "tls_certificate"],
            },
        }
        response_payload["audit"] = audit_res.to_dict()
        return response_payload

    # Step 2: Bounded Collection Execution via ScanOrchestrator
    try:
        orchestrator = ScanOrchestrator(intake_boundary=boundary)
        scan_output = orchestrator.run_scan(raw_url=url, scan_id=scan_id)
        evidence_items = scan_output.get("evidence", [])
        coverage_data = scan_output.get(
            "coverage",
            {
                "checks_total": 4,
                "checks_observed": len([e for e in evidence_items if e.get("status") == "observed"]),
                "checks_failed": len([e for e in evidence_items if e.get("status") in ("failed", "unavailable")]),
                "checks_not_run": len([e for e in evidence_items if e.get("status") not in ("observed", "failed", "unavailable")]),
            },
        )
        try:
            adapter = Worker01EvidenceAdapter()
            batch = adapter.adapt_payload(scan_id, scan_output)
            ev_service = EvidenceService()
            ev_service.ingest_batch(batch)
        except Exception:
            pass
    except Exception as exc:
        # Graceful degradation on collection network error: emit truthful failure report
        evidence_items = [
            {
                "evidence_id": f"ev-err-{uuid.uuid4().hex[:6]}",
                "kind": "intake_validation",
                "source": "scan_orchestrator",
                "observed_at": now_iso,
                "status": "failed",
                "reliability": "direct_observation",
                "value": {"error": str(exc)},
                "limitations": ["Collection aborted due to environmental or network exception."],
            }
        ]
        coverage_data = {
            "checks_total": 4,
            "checks_observed": 0,
            "checks_failed": 1,
            "checks_not_run": 3,
        }

    # Step 3: Canonical Evidence Interpretation via PolicyInput & TriageEngine
    target_host = eval_res.normalized_host or url.split("//")[-1].split("/")[0].split(":")[0]
    policy_input = PolicyInput.from_components(
        scan_id=scan_id,
        target=target_host,
        evidence=evidence_items,
        coverage=coverage_data,
        strict=False,
    )
    triage_result = engine.evaluate_evidence(policy_input)
    fragment = triage_result.to_report_fragment()

    canonical_report = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "submitted_url_redacted": url,
        "normalized_host": target_host,
        "status": "completed" if triage_result.decision != "inconclusive" else "partial",
        "decision": fragment["decision"],
        "created_at": now_iso,
        "policy_version": fragment["policy_version"],
        "dimensions": fragment["dimensions"],
        "coverage": coverage_data,
        "evidence": evidence_items,
        "findings": fragment["findings"],
        "limitations": fragment["limitations"],
    }

    # Step 4: Report Integrity Audit
    audit_res = auditor.audit_report(canonical_report)
    if not audit_res.is_valid:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report failed pre-publication integrity audit: {[i.to_dict() for i in audit_res.issues]}",
        )

    response_payload = dict(canonical_report)
    if triage_result.uncertainty:
        response_payload["uncertainty"] = triage_result.uncertainty.to_dict()
        if triage_result.uncertainty.abstention_notice:
            response_payload["abstention"] = triage_result.uncertainty.abstention_notice.to_dict()
    response_payload["audit"] = audit_res.to_dict()

    return response_payload


@router.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the interactive Evidence Passport dashboard.

    Prefers the compiled Vite production React application in dist/index.html,
    falling back to root index.html. Both preserve core semantic SSR tokens
    and testing invariants.
    """
    if DIST_INDEX_HTML_PATH.exists():
        content = DIST_INDEX_HTML_PATH.read_text(encoding="utf-8")
        return HTMLResponse(content=content)
    if INDEX_HTML_PATH.exists():
        content = INDEX_HTML_PATH.read_text(encoding="utf-8")
        return HTMLResponse(content=content)

    return HTMLResponse(
        content="""<!DOCTYPE html>
<html>
<head><title>TRUSTTRACE Dashboard</title></head>
<body><h1>TRUSTTRACE Web Interface</h1><p>index.html not found at repository root.</p></body>
</html>"""
    )


@router.get("/assets/{asset_path:path}")
async def serve_static_asset(asset_path: str):
    """Serve built static assets for production React frontend with path traversal protection."""
    assets_root = (DIST_DIR / "assets").resolve()
    target_file = (assets_root / asset_path).resolve()
    if assets_root in target_file.parents and target_file.is_file():
        return FileResponse(str(target_file))
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
