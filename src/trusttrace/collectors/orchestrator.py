"""Scan Orchestrator for Worker 01 Phase 02.

Coordinates bounded collectors, enforces rate limits, handles cancellation,
and produces full or partial scan reports conforming to scan_report.schema.json.

Implements:
- LIMIT-001: Timeout budget and partial result
- LIMIT-002: Bounded body/header allocations
- LIMIT-003: Rate and concurrency limits
- LIMIT-004: In-flight scan cancellation
- TLS-001: Valid TLS sets certificate=valid_for_hostname, identity=unverified
- TLS-002: Certificate technical error is not sole proof of phishing
- EVID-001: Collector failures produce truthful partial/inconclusive reports
"""

import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import uuid

from .dns_collector import DNSCollector
from .tls_collector import TLSCollector
from .http_collector import BoundedHTTPCollector
from .rate_limiter import RateLimiter
from .base import CollectorResult
from trusttrace.intake.boundary import IntakeBoundary


class CancellationToken:
    """Thread-safe cancellation flag for in-flight scans (LIMIT-004)."""

    def __init__(self):
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._is_cancelled


class ScanOrchestrator:
    """Orchestrates passive metadata collectors under strict resource bounds and safety gates."""

    def __init__(
        self,
        intake_boundary: Optional[IntakeBoundary] = None,
        dns_collector: Optional[DNSCollector] = None,
        tls_collector: Optional[TLSCollector] = None,
        http_collector: Optional[BoundedHTTPCollector] = None,
        rate_limiter: Optional[RateLimiter] = None,
        policy_version: str = "demo-v1"
    ):
        self.boundary = intake_boundary or IntakeBoundary()
        self.dns_collector = dns_collector or DNSCollector()
        self.tls_collector = tls_collector or TLSCollector()
        self.http_collector = http_collector or BoundedHTTPCollector()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.policy_version = policy_version

    def run_scan(
        self,
        raw_url: str,
        scan_id: Optional[str] = None,
        client_id: str = "default",
        cancel_token: Optional[CancellationToken] = None
    ) -> Dict[str, Any]:
        """Execute bounded scan on a URL target."""
        scan_id = scan_id or f"scan-{uuid.uuid4().hex[:8]}"
        now_start = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # 1. Rate & Concurrency Check (LIMIT-003)
        acquired, limit_reason = self.rate_limiter.acquire(client_id)
        if not acquired:
            return {
                "schema_version": "1.0",
                "scan_id": scan_id,
                "submitted_url_redacted": raw_url,
                "normalized_host": None,
                "status": "rejected",
                "decision": "rejected",
                "created_at": now_start,
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
                "evidence": [{
                    "evidence_id": f"ev-limit-{uuid.uuid4().hex[:6]}",
                    "kind": "target_policy",
                    "value": {"reason": limit_reason},
                    "source": "rate_limiter",
                    "observed_at": now_start,
                    "status": "blocked",
                    "reliability": "direct_observation",
                    "limitations": [f"Request throttled by resource limits: {limit_reason}."]
                }],
                "findings": [],
                "limitations": [f"Scan rejected under resource policy: {limit_reason}."]
            }

        try:
            # 2. Preflight Intake Gate (URL syntax, credentials, SSRF)
            eval_res = self.boundary.evaluate_target(raw_url)
            if not eval_res.is_safe:
                return self.boundary.build_rejected_report(scan_id, eval_res)

            hostname = eval_res.url_result.ascii_host
            port = eval_res.url_result.port
            scheme = eval_res.url_result.scheme

            evidence_items: List[Dict[str, Any]] = list(eval_res.evidence)
            checks_observed = 0
            checks_failed = 0
            checks_not_run = 0
            limitations_list = list(eval_res.limitations)

            # Check 1: DNS
            if cancel_token and cancel_token.is_cancelled:
                # LIMIT-004: In-flight cancellation
                return self._build_cancelled_report(scan_id, eval_res, now_start, "Cancelled before DNS collection.")

            dns_ev = self.dns_collector.collect(hostname, port)
            evidence_items.append(dns_ev.to_dict())
            if dns_ev.status == "observed":
                checks_observed += 1
            else:
                checks_failed += 1
                limitations_list.extend(dns_ev.limitations)

            # Check 2: TLS (if HTTPS)
            if cancel_token and cancel_token.is_cancelled:
                return self._build_cancelled_report(scan_id, eval_res, now_start, "Cancelled before TLS collection.")

            cert_status = "not_checked"
            if scheme == "https":
                pinned_ip = dns_ev.value.get("pinned_ip") if dns_ev.status == "observed" else None
                tls_ev = self.tls_collector.collect(hostname, port=port or 443, pinned_ip=pinned_ip)
                evidence_items.append(tls_ev.to_dict())
                if tls_ev.status == "observed":
                    checks_observed += 1
                    cert_status = "valid_for_hostname" if tls_ev.value.get("is_valid") else "invalid_or_expired"
                else:
                    checks_failed += 1
                    cert_status = "unavailable"
                    limitations_list.extend(tls_ev.limitations)
            else:
                checks_not_run += 1
                limitations_list.append("TLS check not applicable for plain HTTP target.")

            # Check 3 & 4: HTTP Headers & Redirects
            if cancel_token and cancel_token.is_cancelled:
                return self._build_cancelled_report(scan_id, eval_res, now_start, "Cancelled before HTTP collection.")

            http_ev_list = self.http_collector.collect(raw_url)
            for h_ev in http_ev_list:
                evidence_items.append(h_ev.to_dict())
                if h_ev.status == "observed":
                    checks_observed += 1
                elif h_ev.status == "blocked":
                    checks_failed += 1
                    limitations_list.extend(h_ev.limitations)
                else:
                    checks_failed += 1
                    limitations_list.extend(h_ev.limitations)

            # Coverage calculation
            checks_total = checks_observed + checks_failed + checks_not_run
            # Ensure checks_total has minimum 4 (URL, DNS, TLS, HTTP)
            if checks_total < 4:
                checks_not_run += (4 - checks_total)
                checks_total = 4

            # Evaluate dimensions and status (EVID-001, TLS-001, TLS-002)
            has_failures = checks_failed > 0
            if has_failures:
                scan_status = "partial"
                decision = "inconclusive"
                ev_quality = "partial" if checks_observed > 0 else "unavailable"
            else:
                scan_status = "completed"
                decision = "no_threat_observed"
                ev_quality = "strong"

            # Invariant TLS-001: identity remains unverified even if TLS is valid
            identity_dim = "unverified"

            now_completed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

            return {
                "schema_version": "1.0",
                "scan_id": scan_id,
                "submitted_url_redacted": eval_res.submitted_url_redacted,
                "normalized_host": eval_res.normalized_host,
                "status": scan_status,
                "decision": decision,
                "created_at": now_start,
                "completed_at": now_completed,
                "policy_version": self.policy_version,
                "dimensions": {
                    "identity": identity_dim,
                    "certificate": cert_status,
                    "behavior": "no_threat_observed" if not has_failures else "unknown",
                    "evidence_quality": ev_quality
                },
                "coverage": {
                    "checks_total": checks_total,
                    "checks_observed": checks_observed,
                    "checks_failed": checks_failed,
                    "checks_not_run": checks_not_run
                },
                "evidence": evidence_items,
                "findings": [],
                "limitations": limitations_list
            }

        finally:
            self.rate_limiter.release(client_id)

    def _build_cancelled_report(
        self,
        scan_id: str,
        eval_res: Any,
        now_start: str,
        reason: str
    ) -> Dict[str, Any]:
        """Produce truthful report when scan is cancelled in-flight (LIMIT-004)."""
        now_completed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "submitted_url_redacted": eval_res.submitted_url_redacted,
            "normalized_host": eval_res.normalized_host,
            "status": "partial",
            "decision": "inconclusive",
            "created_at": now_start,
            "completed_at": now_completed,
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
            "evidence": [{
                "evidence_id": f"ev-cancel-{uuid.uuid4().hex[:6]}",
                "kind": "target_policy",
                "value": {"reason": "scan_cancelled_by_user"},
                "source": "scan_orchestrator",
                "observed_at": now_completed,
                "status": "blocked",
                "reliability": "direct_observation",
                "limitations": [reason]
            }],
            "findings": [],
            "limitations": [reason]
        }
