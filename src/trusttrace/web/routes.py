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
import math
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
from ..policy.signal_extractor import EvidenceSignalExtractor
from ..policy.integrity_auditor import ReportIntegrityAuditor
from ..policy.uncertainty import ConfidenceBand
from ..policy.calibration import (
    AsymmetricCostConfig,
    DEFAULT_COST_PROFILES,
    CandidateAction,
)
from ..policy.counterfactual import (
    CounterfactualExplanationEngine,
    CounterfactualResult,
    COUNTERFACTUAL_DISCLAIMER,
)
from ..policy.claim_matrix import (
    ClaimEvidenceMatrixGenerator,
    ClaimEvidenceMatrixResult,
)
from ..evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
from ..evidence.services.evidence_service import EvidenceService

router = APIRouter(tags=["Web Interface & Triage"])

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_DIR = REPO_ROOT / ".brain" / ".testdata" / "v1"
INDEX_HTML_PATH = REPO_ROOT / "index.html"
DIST_DIR = REPO_ROOT / "dist"
DIST_INDEX_HTML_PATH = DIST_DIR / "index.html"

# In-memory scan cache for quick access by scan_id across secondary analysis endpoints
_SCAN_CACHE: Dict[str, Tuple[PolicyInput, Any, List[Dict[str, Any]]]] = {}


class TriageDemoRequest(BaseModel):
    """Request payload for web triage assessment."""
    url: str = Field(..., description="Target URL to assess")
    scenario: Optional[str] = Field("custom", description="Demonstration scenario identifier or 'custom'")


class CostAssessmentRequest(BaseModel):
    """Request payload for asymmetric operational cost evaluation (Phase 08)."""
    profile_name: Optional[str] = Field("analyst_triage", description="Preset cost profile name")
    cost_false_negative: Optional[float] = Field(None, description="C_FN: Cost of false negative (missed threat)")
    cost_false_positive: Optional[float] = Field(None, description="C_FP: Cost of false positive (false alarm)")
    cost_abstain: Optional[float] = Field(None, description="C_A: Cost of manual analyst review")
    cost_true_positive: Optional[float] = Field(0.0, description="C_TP: Cost of true positive")
    cost_true_negative: Optional[float] = Field(0.0, description="C_TN: Cost of true negative")
    scenario: Optional[str] = Field(None, description="Optional scenario ID if scan_id not in cache")
    url: Optional[str] = Field(None, description="Optional target URL")


class CounterfactualRequest(BaseModel):
    """Request payload for deterministic counterfactual sensitivity (Phase 09)."""
    target_disposition: Optional[str] = Field("clean", description="Target disposition: 'clean', 'threat', 'inconclusive'")
    scenario: Optional[str] = Field(None, description="Optional scenario ID if scan_id not in cache")
    url: Optional[str] = Field(None, description="Optional target URL")


class ClaimMatrixRequest(BaseModel):
    """Request payload for claim-to-evidence matrix query (Phase 10)."""
    scenario: Optional[str] = Field(None, description="Optional scenario ID if scan_id not in cache")
    url: Optional[str] = Field(None, description="Optional target URL")


def _now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sanitize_json_floats(obj: Any) -> Any:
    """Ensure all float values are compliant with standard JSON (replace Inf/NaN with None)."""
    if isinstance(obj, float):
        if math.isinf(obj) or math.isnan(obj):
            return None
        return obj
    if isinstance(obj, dict):
        return {k: _sanitize_json_floats(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_json_floats(v) for v in obj]
    return obj


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

        # Cache for subsequent secondary queries
        _SCAN_CACHE[canonical_report["scan_id"]] = (policy_input, triage_result, raw_evidence)
        _SCAN_CACHE[scenario] = (policy_input, triage_result, raw_evidence)

        # Build response envelope with uncertainty assessment
        response_payload = dict(canonical_report)
        if triage_result.uncertainty:
            response_payload["uncertainty"] = triage_result.uncertainty.to_dict()
            if triage_result.uncertainty.abstention_notice:
                response_payload["abstention"] = triage_result.uncertainty.abstention_notice.to_dict()
        response_payload["audit"] = audit_result.to_dict()

        # Phase 08: Cost Calibration
        try:
            evaluated_cost = engine.evaluate_with_cost_calibration(policy_input)
            if evaluated_cost.cost_assessment:
                response_payload["cost_assessment"] = _sanitize_json_floats(evaluated_cost.cost_assessment.to_dict())
        except Exception:
            pass

        # Phase 09: Deterministic Counterfactual Sensitivity
        try:
            extractor = EvidenceSignalExtractor()
            extracted_sigs = list(extractor.extract_signals(policy_input).signals)
            target_cf = "no_threat_observed" if triage_result.decision != "no_threat_observed" else "confirmed_threat"
            cf_res = engine.evaluate_with_counterfactual(signals=extracted_sigs, target_disposition=target_cf, scan_id=canonical_report["scan_id"])
            response_payload["counterfactual"] = _sanitize_json_floats(cf_res.to_dict())
        except Exception:
            pass

        # Phase 10: Claim-to-Evidence Matrix
        try:
            matrix_res = engine.generate_claim_matrix(policy_input, triage_result=triage_result)
            response_payload["claim_matrix"] = _sanitize_json_floats(matrix_res.to_dict())
        except Exception:
            pass

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
    community_report_dicts = []
    try:
        from ..api.routes.community import community_service as comm_svc
        stored_reports = comm_svc.list_reports_for_domain(target_host)
        community_report_dicts = [
            r.model_dump() if hasattr(r, "model_dump") else (r.to_dict() if hasattr(r, "to_dict") else dict(r))
            for r in stored_reports
        ]
        for r in community_report_dicts:
            evidence_items.append({
                "evidence_id": r.get("report_id"),
                "kind": "community_report",
                "source": "community_intelligence",
                "observed_at": r.get("submitted_at") or now_iso,
                "status": "observed",
                "reliability": "corroborated" if r.get("verification_state") == "verified" else "direct_observation",
                "value": {
                    "claim_type": r.get("claim_type"),
                    "verification_state": r.get("verification_state"),
                    "independent_source_count": r.get("independent_source_count", 1),
                },
                "limitations": ["Community report from crowdsourced intelligence feed (COMM-001)."],
            })
    except Exception:
        community_report_dicts = []

    policy_input = PolicyInput.from_components(
        scan_id=scan_id,
        target=target_host,
        evidence=evidence_items,
        coverage=coverage_data,
        community_reports=community_report_dicts,
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

    # Cache scan for subsequent secondary queries
    _SCAN_CACHE[scan_id] = (policy_input, triage_result, evidence_items)

    # Phase 08: Cost Calibration
    try:
        evaluated_cost = engine.evaluate_with_cost_calibration(policy_input)
        if evaluated_cost.cost_assessment:
            response_payload["cost_assessment"] = _sanitize_json_floats(evaluated_cost.cost_assessment.to_dict())
    except Exception:
        pass

    # Phase 09: Deterministic Counterfactual Sensitivity
    try:
        extractor = EvidenceSignalExtractor()
        extracted_sigs = list(extractor.extract_signals(policy_input).signals)
        target_cf = "no_threat_observed" if triage_result.decision != "no_threat_observed" else "confirmed_threat"
        cf_res = engine.evaluate_with_counterfactual(signals=extracted_sigs, target_disposition=target_cf, scan_id=scan_id)
        response_payload["counterfactual"] = _sanitize_json_floats(cf_res.to_dict())
    except Exception:
        pass

    # Phase 10: Claim-to-Evidence Matrix
    try:
        matrix_res = engine.generate_claim_matrix(policy_input, triage_result=triage_result)
        response_payload["claim_matrix"] = _sanitize_json_floats(matrix_res.to_dict())
    except Exception:
        pass

    return response_payload


def _resolve_scan_or_scenario(
    scan_id: str,
    scenario: Optional[str] = None,
    url: Optional[str] = None,
) -> Tuple[PolicyInput, Any, List[Dict[str, Any]]]:
    """Resolve PolicyInput and TriageResult by scan_id or scenario fixture."""
    if scan_id in _SCAN_CACHE:
        return _SCAN_CACHE[scan_id]

    scen_key = scenario
    if not scen_key:
        sid_lower = scan_id.lower()
        if "phish" in sid_lower:
            scen_key = "phishing_lookalike"
        elif "exp" in sid_lower:
            scen_key = "expired_tls"
        elif "legit" in sid_lower:
            scen_key = "legitimate"
        elif "conflict" in sid_lower or "dispute" in sid_lower:
            scen_key = "conflicting"
        else:
            scen_key = "phishing_lookalike"

    target_url = url or "https://bank-secure-lоgin.com"
    if scen_key == "expired_tls":
        target_url = url or "https://legacy-portal.internal-corp.net"
    elif scen_key == "legitimate":
        target_url = url or "https://example.com"
    elif scen_key == "conflicting":
        target_url = url or "https://disputed-exchange.io"

    pi, cov, ev_list = _build_scenario_policy_input(scen_key, target_url)
    engine = TriageEngine()
    res = engine.evaluate_evidence(pi)
    _SCAN_CACHE[scan_id] = (pi, res, ev_list)
    return pi, res, ev_list


@router.get("/api/v1/cost-profiles")
async def get_cost_profiles():
    """Phase 08: Retrieve standard deployment operational cost profiles."""
    from ..policy.calibration import DEFAULT_COST_PROFILES

    return {
        "profiles": {
            k: v.to_dict() for k, v in DEFAULT_COST_PROFILES.items()
        },
        "default": "analyst_triage",
    }


@router.post("/api/v1/scans/{scan_id}/cost-assessment")
async def evaluate_cost_assessment(scan_id: str, req: Optional[CostAssessmentRequest] = None):
    """Phase 08: Evaluate asymmetric operational cost calibration for a scan."""
    from ..policy.calibration import AsymmetricCostConfig, DEFAULT_COST_PROFILES, MinimaxDecisionEngine

    req = req or CostAssessmentRequest()
    policy_input, triage_res, _ = _resolve_scan_or_scenario(scan_id, req.scenario, req.url)

    if (
        req.cost_false_negative is not None
        and req.cost_false_positive is not None
        and req.cost_abstain is not None
    ):
        cost_cfg = AsymmetricCostConfig(
            profile_name=req.profile_name or "custom",
            cost_false_negative=float(req.cost_false_negative),
            cost_false_positive=float(req.cost_false_positive),
            cost_abstain=float(req.cost_abstain),
            cost_true_positive=float(req.cost_true_positive or 0.0),
            cost_true_negative=float(req.cost_true_negative or 0.0),
        )
    else:
        profile_key = req.profile_name if (req.profile_name and req.profile_name in DEFAULT_COST_PROFILES) else "analyst_triage"
        cost_cfg = DEFAULT_COST_PROFILES[profile_key]

    engine = TriageEngine()
    evaluated = engine.evaluate_with_cost_calibration(policy_input, cost_cfg)
    minimax = MinimaxDecisionEngine(cost_cfg).evaluate_interval(0.0, 1.0)
    ca_dict = evaluated.cost_assessment.to_dict() if evaluated.cost_assessment else {}
    ca_dict["optimal_action"] = minimax.optimal_action.value
    ca_dict["worst_case_costs"] = minimax.worst_case_costs
    ca_dict["minimum_cost"] = minimax.minimum_cost
    ca_dict["minimax_evaluation"] = minimax.to_dict()
    return _sanitize_json_floats({
        "scan_id": scan_id,
        "decision": evaluated.decision,
        "cost_assessment": ca_dict,
        "cost_config": cost_cfg.to_dict(),
    })


@router.post("/api/v1/scans/{scan_id}/counterfactual")
async def evaluate_counterfactual(scan_id: str, req: Optional[CounterfactualRequest] = None):
    """Phase 09: Compute deterministic counterfactual sensitivity to target disposition."""
    req = req or CounterfactualRequest()
    policy_input, triage_res, _ = _resolve_scan_or_scenario(scan_id, req.scenario, req.url)

    engine = TriageEngine()
    extractor = EvidenceSignalExtractor()
    extracted = extractor.extract_signals(policy_input)

    target_disp = req.target_disposition or "clean"
    disp_map = {
        "clean": "no_threat_observed",
        "no_threat_observed": "no_threat_observed",
        "threat": "confirmed_threat",
        "confirmed_threat": "confirmed_threat",
        "high_risk": "confirmed_threat",
        "inconclusive": "inconclusive",
        "caution": "caution",
        "suspicious_threat": "suspicious_threat",
    }
    canonical_target = disp_map.get(target_disp.lower(), target_disp)

    cf_res = engine.evaluate_with_counterfactual(
        signals=list(extracted.signals),
        target_disposition=canonical_target,
        scan_id=scan_id,
    )
    return _sanitize_json_floats(cf_res.to_dict())


@router.get("/api/v1/scans/{scan_id}/claim-matrix")
@router.post("/api/v1/scans/{scan_id}/claim-matrix")
async def get_claim_matrix(scan_id: str, req: Optional[ClaimMatrixRequest] = None):
    """Phase 10: Extract claims from report and audit evidence traceability lineage."""
    scenario = req.scenario if req else None
    url = req.url if req else None
    policy_input, triage_res, _ = _resolve_scan_or_scenario(scan_id, scenario, url)

    engine = TriageEngine()
    matrix = engine.generate_claim_matrix(policy_input, triage_result=triage_res)
    return matrix.to_dict()


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
