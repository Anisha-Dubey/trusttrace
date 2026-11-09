"""Unified Intake & Safe Scan Boundary for Worker 01 Phase 01.

Provides the single entry point for URL intake, policy enforcement,
deterministic rejection reporting conforming to scan_report.schema.json,
and fixture-only vertical slice support.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import uuid
import json
from pathlib import Path

from .url_policy import parse_and_validate_url, URLParseResult
from .dns_resolver import SafeDNSResolver, DNSResolutionResult
from .redirect_policy import RedirectPolicy


@dataclass(frozen=True)
class IntakeEvaluationResult:
    is_safe: bool
    rejection_reason: Optional[str] = None
    submitted_url_redacted: str = ""
    normalized_host: Optional[str] = None
    url_result: Optional[URLParseResult] = None
    dns_result: Optional[DNSResolutionResult] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


class IntakeBoundary:
    """The authoritative gatekeeper for all URL intake and egress boundaries."""

    def __init__(
        self,
        resolver: Optional[SafeDNSResolver] = None,
        policy_version: str = "demo-v1",
        fixtures_dir: Optional[Path] = None
    ):
        self.resolver = resolver or SafeDNSResolver()
        self.policy_version = policy_version
        self.redirect_policy = RedirectPolicy(resolver=self.resolver)
        self.fixtures_dir = fixtures_dir

    def evaluate_target(self, raw_url: str) -> IntakeEvaluationResult:
        """Run all Phase 01 pre-egress checks on an untrusted URL target.
        
        Evaluates:
        1. URL syntax, scheme, credential check, port safety, token redaction.
        2. DNS resolution and SSRF IP safety classification.
        """
        # Step 1: URL Syntax & Policy
        url_res = parse_and_validate_url(raw_url)
        if not url_res.is_valid:
            evidence = [{
                "evidence_id": f"ev-url-policy-{uuid.uuid4().hex[:6]}",
                "kind": "target_policy",
                "value": {"reason": url_res.rejection_reason},
                "source": "url_safety_policy",
                "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "status": "blocked",
                "reliability": "direct_observation",
                "limitations": ["Rejected at URL parser boundary; no network request attempted."]
            }]
            return IntakeEvaluationResult(
                is_safe=False,
                rejection_reason=url_res.rejection_reason,
                submitted_url_redacted=url_res.submitted_url_redacted,
                normalized_host=None,
                url_result=url_res,
                evidence=evidence,
                limitations=url_res.limitations
            )

        # Step 2: DNS & SSRF Safety
        dns_res = self.resolver.resolve(url_res.ascii_host, url_res.port)
        combined_evidence = list(url_res.evidence)

        if not dns_res.is_safe:
            combined_evidence.append({
                "evidence_id": f"ev-ssrf-block-{uuid.uuid4().hex[:6]}",
                "kind": "target_policy",
                "value": {
                    "reason": dns_res.rejection_reason,
                    "resolved_ips": dns_res.resolved_ips
                },
                "source": "url_safety_policy",
                "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "status": "blocked",
                "reliability": "direct_observation",
                "limitations": ["Rejected by SSRF destination classification; no outbound connection attempted."]
            })
            return IntakeEvaluationResult(
                is_safe=False,
                rejection_reason=dns_res.rejection_reason,
                submitted_url_redacted=url_res.submitted_url_redacted,
                normalized_host=url_res.normalized_host,
                url_result=url_res,
                dns_result=dns_res,
                evidence=combined_evidence,
                limitations=dns_res.limitations
            )

        # All checks passed
        return IntakeEvaluationResult(
            is_safe=True,
            submitted_url_redacted=url_res.submitted_url_redacted,
            normalized_host=url_res.normalized_host,
            url_result=url_res,
            dns_result=dns_res,
            evidence=combined_evidence,
            limitations=[]
        )

    def build_rejected_report(
        self,
        scan_id: str,
        evaluation: IntakeEvaluationResult
    ) -> Dict[str, Any]:
        """Produce a canonical rejection report strictly conforming to scan_report.schema.json."""
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        limitations = list(evaluation.limitations)
        if not limitations:
            limitations = [f"Destination rejected by policy: {evaluation.rejection_reason}."]

        return {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "submitted_url_redacted": evaluation.submitted_url_redacted,
            "normalized_host": evaluation.normalized_host,
            "status": "rejected",
            "decision": "rejected",
            "created_at": now_iso,
            "completed_at": None,
            "policy_version": self.policy_version,
            "dimensions": {
                "identity": "unknown",
                "certificate": "not_checked",
                "behavior": "unknown",
                "evidence_quality": "unavailable"
            },
            "coverage": {
                "checks_total": 4,
                "checks_observed": 0,
                "checks_failed": 0,
                "checks_not_run": 4
            },
            "evidence": evaluation.evidence,
            "findings": [],
            "limitations": limitations
        }

    def process_scan_request(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process an incoming scan request according to profile and safety gates."""
        scan_id = request_payload.get("client_request_id") or f"scan-{uuid.uuid4().hex[:8]}"
        url = request_payload.get("url", "")
        profile = request_payload.get("profile", "fixture")

        eval_res = self.evaluate_target(url)
        if not eval_res.is_safe:
            return self.build_rejected_report(scan_id, eval_res)

        # In fixture mode (safe vertical slice), return fixture or stub
        if profile == "fixture":
            return {
                "schema_version": "1.0",
                "scan_id": scan_id,
                "submitted_url_redacted": eval_res.submitted_url_redacted,
                "normalized_host": eval_res.normalized_host,
                "status": "completed",
                "decision": "no_threat_observed",
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "policy_version": self.policy_version,
                "dimensions": {
                    "identity": "unverified",
                    "certificate": "valid",
                    "behavior": "no_threat_observed",
                    "evidence_quality": "direct"
                },
                "coverage": {
                    "checks_total": 4,
                    "checks_observed": 4,
                    "checks_failed": 0,
                    "checks_not_run": 0
                },
                "evidence": eval_res.evidence,
                "findings": [],
                "limitations": ["Fixture-backed scan profile; passive low-impact validation."]
            }

        # For passive metadata, ready for Worker 01 Phase 02 collectors
        return {
            "scan_id": scan_id,
            "status": "validating",
            "evaluation": eval_res
        }
