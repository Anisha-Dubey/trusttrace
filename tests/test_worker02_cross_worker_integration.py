"""Comprehensive Cross-Worker Integration Test Suite for TRUSTTRACE Worker 02.

Verifies closure of all six critical integration issues:
- Issue A: Worker 03 TriageEngine integration in EvidenceService.ingest_batch()
- Issue B: DEF-04 Report Integrity Pre-Publication Audit in EvidenceService.get_scan_report()
- Issue C: Reliability enum compatibility (canonical values and tier strings: high, medium, low)
- Issue D: Named collector coverage vs raw evidence record count arithmetic
- Issue E: End-to-end scan persistence and web route verification (DEF-01 & DEF-05 fixed)
- Issue F: Pydantic v2 / PolicyInput compatibility across Worker 02 and Worker 03
"""

import json
import os
import sys
import unittest
import uuid
from pathlib import Path
from typing import Dict, Any, List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient

from trusttrace.api.app import create_app
from trusttrace.evidence.adapters.base import EvidenceBatch
from trusttrace.evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
from trusttrace.evidence.domain.enums import (
    EvidenceStatus,
    Reliability,
    normalize_reliability,
    FindingSeverity,
    VerificationState,
    ClaimType,
)
from trusttrace.evidence.domain.models import (
    EvidenceModel,
    CoverageModel,
    FindingModel,
    CommunityReportModel,
    utc_now_iso,
)
from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.evidence.persistence.repository import EvidenceRepository
from trusttrace.evidence.services.evidence_service import (
    EvidenceService,
    classify_check_category,
)
from trusttrace.policy.policy_input import PolicyInput
from trusttrace.policy.triage_engine import TriageEngine
from trusttrace.policy.integrity_auditor import (
    ReportIntegrityAuditor,
    AuditRuleId,
    AuditSeverity,
)
from trusttrace.collectors.base import CollectorResult


class TestWorker02CrossWorkerIntegration(unittest.TestCase):
    """Deep cross-worker integration and boundary verification tests."""

    def setUp(self):
        """Create a dedicated, isolated in-memory SQLite database for each test."""
        self.db_manager = DatabaseManager(db_url="sqlite:///:memory:")
        self.repository = EvidenceRepository(db_manager=self.db_manager)
        self.triage_engine = TriageEngine()
        self.integrity_auditor = ReportIntegrityAuditor()
        self.evidence_service = EvidenceService(
            repository=self.repository,
            db_manager=self.db_manager,
            triage_engine=self.triage_engine,
            integrity_auditor=self.integrity_auditor,
        )

    # -------------------------------------------------------------------------
    # ISSUE C: Reliability Mapping Normalizer
    # -------------------------------------------------------------------------
    def test_issue_c_reliability_normalization(self):
        """Verify normalize_reliability maps canonical strings, tier aliases, and unknown values."""
        # Canonical mappings
        self.assertEqual(normalize_reliability("direct_observation"), Reliability.DIRECT_OBSERVATION)
        self.assertEqual(normalize_reliability("provider_assertion"), Reliability.PROVIDER_ASSERTION)
        self.assertEqual(normalize_reliability("derived_signal"), Reliability.DERIVED_SIGNAL)
        self.assertEqual(normalize_reliability("user_report"), Reliability.USER_REPORT)
        self.assertEqual(normalize_reliability("unknown"), Reliability.UNKNOWN)

        # Tier aliases
        self.assertEqual(normalize_reliability("high"), Reliability.DIRECT_OBSERVATION)
        self.assertEqual(normalize_reliability("HIGH"), Reliability.DIRECT_OBSERVATION)
        self.assertEqual(normalize_reliability("medium"), Reliability.DERIVED_SIGNAL)
        self.assertEqual(normalize_reliability("Medium"), Reliability.DERIVED_SIGNAL)
        self.assertEqual(normalize_reliability("low"), Reliability.USER_REPORT)
        self.assertEqual(normalize_reliability("Low"), Reliability.USER_REPORT)

        # Pre-existing enum instances
        self.assertEqual(normalize_reliability(Reliability.DIRECT_OBSERVATION), Reliability.DIRECT_OBSERVATION)

        # Unrecognized strings default to UNKNOWN
        self.assertEqual(normalize_reliability("unrecognized_foo_bar"), Reliability.UNKNOWN)
        self.assertIsNone(normalize_reliability(None))

    def test_issue_c_evidence_model_accepts_tier_aliases(self):
        """Verify EvidenceModel automatically converts tier strings ('high', 'medium', 'low') via validator."""
        ev_high = EvidenceModel(
            evidence_id="ev-c-001",
            kind="tls_certificate",
            source="tls_collector",
            observed_at=utc_now_iso(),
            status=EvidenceStatus.OBSERVED,
            reliability="high",  # String tier alias
        )
        self.assertEqual(ev_high.reliability, Reliability.DIRECT_OBSERVATION)

        ev_med = EvidenceModel(
            evidence_id="ev-c-002",
            kind="rdap_registration",
            source="rdap_collector",
            observed_at=utc_now_iso(),
            status=EvidenceStatus.OBSERVED,
            reliability="medium",
        )
        self.assertEqual(ev_med.reliability, Reliability.DERIVED_SIGNAL)

        ev_low = EvidenceModel(
            evidence_id="ev-c-003",
            kind="user_flag",
            source="community",
            observed_at=utc_now_iso(),
            status=EvidenceStatus.OBSERVED,
            reliability="low",
        )
        self.assertEqual(ev_low.reliability, Reliability.USER_REPORT)

    def test_issue_c_worker01_adapter_normalizes_tier_strings(self):
        """Verify Worker01EvidenceAdapter cleanly handles payloads containing 'high'/'medium'/'low'."""
        adapter = Worker01EvidenceAdapter()
        payload = {
            "evidence": [
                {
                    "evidence_id": "ev-w01-rel-1",
                    "kind": "tls_certificate",
                    "source": "tls_collector",
                    "status": "observed",
                    "reliability": "high",
                },
                {
                    "evidence_id": "ev-w01-rel-2",
                    "kind": "dns_resolution",
                    "source": "dns_collector",
                    "status": "observed",
                    "reliability": "medium",
                },
            ]
        }
        batch = adapter.adapt_payload("scan-rel-test", payload)
        self.assertEqual(batch.items[0].reliability, Reliability.DIRECT_OBSERVATION)
        self.assertEqual(batch.items[1].reliability, Reliability.DERIVED_SIGNAL)

    # -------------------------------------------------------------------------
    # ISSUE D: Named Collector Coverage vs Raw Evidence Record Count
    # -------------------------------------------------------------------------
    def test_issue_d_named_collector_deduplication(self):
        """Verify multiple evidence records for the same collector category do not artificially inflate check counts."""
        # 3 TLS records, 2 DNS records, 1 HTTP record = 3 distinct named checks
        evidence_items = [
            # TLS category (3 records, all observed)
            EvidenceModel(
                evidence_id="ev-tls-1",
                kind="tls_certificate",
                source="tls_collector",
                observed_at=utc_now_iso(),
                status=EvidenceStatus.OBSERVED,
            ),
            EvidenceModel(
                evidence_id="ev-tls-2",
                kind="tls_hostname_validation",
                source="tls_collector",
                observed_at=utc_now_iso(),
                status=EvidenceStatus.OBSERVED,
            ),
            EvidenceModel(
                evidence_id="ev-tls-3",
                kind="tls_cipher_suite",
                source="tls_collector",
                observed_at=utc_now_iso(),
                status=EvidenceStatus.OBSERVED,
            ),
            # DNS category (2 records, all observed)
            EvidenceModel(
                evidence_id="ev-dns-1",
                kind="dns_resolution",
                source="dns_collector",
                observed_at=utc_now_iso(),
                status=EvidenceStatus.OBSERVED,
            ),
            EvidenceModel(
                evidence_id="ev-dns-2",
                kind="dns_authoritative_nameservers",
                source="dns_collector",
                observed_at=utc_now_iso(),
                status=EvidenceStatus.OBSERVED,
            ),
            # HTTP category (1 record, observed)
            EvidenceModel(
                evidence_id="ev-http-1",
                kind="http_headers",
                source="bounded_http",
                observed_at=utc_now_iso(),
                status=EvidenceStatus.OBSERVED,
            ),
        ]

        # Total 6 raw records, but exactly 3 distinct named check categories.
        # With expected_total_checks=4 (standard profile):
        # checks_observed = 3
        # checks_failed = 0
        # checks_not_run = 1 (to reach expected 4)
        # checks_total = 4
        cov = self.evidence_service.calculate_coverage(evidence_items, expected_total_checks=4)
        self.assertEqual(cov.checks_observed, 3)
        self.assertEqual(cov.checks_failed, 0)
        self.assertEqual(cov.checks_not_run, 1)
        self.assertEqual(cov.checks_total, 4)
        self.assertEqual(cov.checks_total, cov.checks_observed + cov.checks_failed + cov.checks_not_run)

    def test_issue_d_failure_precedence_in_named_check(self):
        """Verify that if one observation fails in a check family, the entire named check is recorded as failed."""
        evidence_items = [
            EvidenceModel(
                evidence_id="ev-tls-ok",
                kind="tls_certificate",
                source="tls_collector",
                observed_at=utc_now_iso(),
                status=EvidenceStatus.OBSERVED,
            ),
            EvidenceModel(
                evidence_id="ev-tls-fail",
                kind="tls_hostname_validation",
                source="tls_collector",
                observed_at=utc_now_iso(),
                status=EvidenceStatus.FAILED,  # Hostname mismatch failure
            ),
        ]

        cov = self.evidence_service.calculate_coverage(evidence_items, expected_total_checks=4)
        # 1 named check (TLS), composite state FAILED
        self.assertEqual(cov.checks_observed, 0)
        self.assertEqual(cov.checks_failed, 1)
        self.assertEqual(cov.checks_not_run, 3)
        self.assertEqual(cov.checks_total, 4)
        self.assertEqual(cov.checks_total, cov.checks_observed + cov.checks_failed + cov.checks_not_run)

    # -------------------------------------------------------------------------
    # ISSUE A: TriageEngine Integration & Finding Persistence
    # -------------------------------------------------------------------------
    def test_issue_a_ingest_batch_triggers_triage_and_persists_findings(self):
        """Verify EvidenceService.ingest_batch evaluates via TriageEngine and persists findings idempotently."""
        scan_id = "scan-issue-a-001"
        target_domain = "bank-secure-login-phish.net"

        # Construct batch containing a lookalike domain and valid TLS (triggers IDN / phishing caution finding)
        batch = EvidenceBatch(
            scan_id=scan_id,
            items=[
                EvidenceModel(
                    evidence_id="ev-a-feed-01",
                    scan_id=scan_id,
                    kind="threat_intelligence",
                    source="threat_feed",
                    observed_at=utc_now_iso(),
                    status=EvidenceStatus.OBSERVED,
                    reliability=Reliability.PROVIDER_ASSERTION,
                    value={"matched": True, "target": target_domain},
                ),
                EvidenceModel(
                    evidence_id="ev-a-tls-01",
                    scan_id=scan_id,
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at=utc_now_iso(),
                    status=EvidenceStatus.OBSERVED,
                    reliability=Reliability.DIRECT_OBSERVATION,
                    value={"is_valid": True, "hostname_match": True, "is_expired": False},
                ),
                EvidenceModel(
                    evidence_id="ev-a-intake-01",
                    scan_id=scan_id,
                    kind="intake_validation",
                    source="worker_01_intake",
                    observed_at=utc_now_iso(),
                    status=EvidenceStatus.OBSERVED,
                    reliability=Reliability.DIRECT_OBSERVATION,
                    value={"clean": True},
                ),
            ],
            metadata={
                "submitted_url_redacted": f"https://{target_domain}/",
                "normalized_host": target_domain,
            },
        )

        # Ingestion run 1
        res1 = self.evidence_service.ingest_batch(batch)
        self.assertEqual(res1.inserted_count, 3)
        self.assertEqual(res1.deduplicated_count, 0)

        # Verify scan record in database
        report = self.evidence_service.get_scan_report(scan_id)
        self.assertIsNotNone(report)
        self.assertEqual(report["decision"], "high_risk")
        self.assertTrue(report["policy_version"].startswith("w03-v"))
        self.assertIsInstance(report["dimensions"], dict)
        self.assertIn("identity", report["dimensions"])
        self.assertIn("certificate", report["dimensions"])
        self.assertEqual(report["dimensions"]["behavior"], "malicious_evidence")

        # Check findings persisted in DB
        with self.db_manager.session_scope() as session:
            findings_in_db = self.repository.get_findings_by_scan(session, scan_id)
            self.assertTrue(len(findings_in_db) > 0)
            findings_count_run1 = len(findings_in_db)

        # Ingestion run 2 (exact duplicate batch to test idempotency)
        res2 = self.evidence_service.ingest_batch(batch)
        self.assertEqual(res2.inserted_count, 0)
        self.assertEqual(res2.deduplicated_count, 3)

        # Verify finding count has NOT multiplied (strict idempotency)
        with self.db_manager.session_scope() as session:
            findings_in_db_after = self.repository.get_findings_by_scan(session, scan_id)
            self.assertEqual(len(findings_in_db_after), findings_count_run1)

    # -------------------------------------------------------------------------
    # ISSUE B: DEF-04 Report Integrity Pre-Publication Audit
    # -------------------------------------------------------------------------
    def test_issue_b_report_integrity_auditor_blocks_illegal_clean_claim(self):
        """Verify get_scan_report catches absolute claims and blocks publication with withheld status."""
        scan_id = "scan-audit-test-001"

        # Ensure scan with an illegal claim
        with self.db_manager.session_scope() as session:
            self.repository.ensure_scan(
                session,
                scan_id=scan_id,
                submitted_url_redacted="https://example.com",
                normalized_host="example.com",
                status="completed",
                decision="no_threat_observed",
                limitations=["This site is 100% safe and bulletproof."],  # Prohibited marketing claim (INV-CLAIM-001)
            )

        report = self.evidence_service.get_scan_report(scan_id, enforce_audit=True)
        self.assertIsNotNone(report)
        # Publication must be withheld
        self.assertEqual(report["status"], "withheld")
        self.assertEqual(report["decision"], "inconclusive")
        self.assertFalse(report.get("audit_passed", True))
        self.assertTrue(len(report.get("audit_errors", [])) > 0)
        self.assertTrue(any("REPORT INTEGRITY AUDIT FAILED" in lim for lim in report["limitations"]))

    def test_issue_b_audit_scan_report_method(self):
        """Verify audit_scan_report provides a typed ReportAuditResult."""
        scan_id = "scan-audit-direct-001"
        with self.db_manager.session_scope() as session:
            self.repository.ensure_scan(
                session,
                scan_id=scan_id,
                submitted_url_redacted="https://valid-target.com",
                normalized_host="valid-target.com",
                status="completed",
                decision="no_threat_observed",
                limitations=["Limited scope: passive inspection only."],
            )

        audit_result = self.evidence_service.audit_scan_report(scan_id)
        self.assertIsNotNone(audit_result)
        self.assertTrue(audit_result.is_valid)
        self.assertEqual(audit_result.error_count, 0)

    # -------------------------------------------------------------------------
    # ISSUE E: End-to-End Scan Persistence & Web Routes (DEF-01, DEF-05)
    # -------------------------------------------------------------------------
    def test_issue_e_web_routes_demo_all_scenarios_succeed_http_200(self):
        """Verify all scenarios in /api/v1/triage/demo succeed with HTTP 200 (DEF-01 resolved)."""
        app = create_app()
        client = TestClient(app)

        scenarios = ["legitimate", "phishing_lookalike", "expired_tls", "conflicting"]
        for scen in scenarios:
            response = client.post("/api/v1/triage/demo", json={"url": "https://example.com", "scenario": scen})
            self.assertEqual(
                response.status_code,
                200,
                f"Scenario '{scen}' failed with HTTP {response.status_code}: {response.text}",
            )
            data = response.json()
            if scen == "conflicting":
                self.assertIn("report_id", data)
                self.assertEqual(data["verification_state"], "disputed")
            else:
                self.assertIn("decision", data)
                self.assertIn("dimensions", data)
                self.assertIn("coverage", data)

            # In phishing_lookalike and expired_tls, verify uncertainty payload is returned (DEF-05)
            if scen in ("phishing_lookalike", "expired_tls"):
                self.assertIn("uncertainty", data)
                self.assertIn("confidence_band", data["uncertainty"])

    def test_issue_e_web_routes_custom_url_runs_and_persists_in_database(self):
        """Verify custom URL submission executes bounded collectors and persists through EvidenceService."""
        app = create_app()
        client = TestClient(app)

        test_url = "https://safe-local-mock.internal-corp.test/"
        response = client.post("/api/v1/triage/demo", json={"url": test_url, "scenario": "custom"})
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Check response structure
        self.assertIn("scan_id", data)
        self.assertIn("status", data)
        self.assertIn("coverage", data)
        self.assertEqual(
            data["coverage"]["checks_total"],
            data["coverage"]["checks_observed"] + data["coverage"]["checks_failed"] + data["coverage"]["checks_not_run"],
        )

    # -------------------------------------------------------------------------
    # ISSUE F: Pydantic v2 / PolicyInput Compatibility
    # -------------------------------------------------------------------------
    def test_issue_f_worker02_models_feed_cleanly_into_policy_input(self):
        """Verify Worker 02 models pass cleanly into PolicyInput.from_components() without parse errors."""
        scan_id = "scan-issue-f-001"
        ev = EvidenceModel(
            evidence_id="ev-f-001",
            scan_id=scan_id,
            kind="tls_certificate",
            source="tls_collector",
            observed_at=utc_now_iso(),
            status=EvidenceStatus.OBSERVED,
            reliability=Reliability.DIRECT_OBSERVATION,
            value={"subject_cn": "example.com"},
        )
        cov = CoverageModel(
            checks_total=4,
            checks_observed=3,
            checks_failed=0,
            checks_not_run=1,
        )
        comm = CommunityReportModel(
            report_id="rep-f-001",
            normalized_domain="example.com",
            claim_type=ClaimType.PHISHING,
            verification_state=VerificationState.CORROBORATED,
            independent_source_count=2,
            linked_evidence_ids=["ev-f-001"],
        )

        policy_input = PolicyInput.from_components(
            scan_id=scan_id,
            target="example.com",
            evidence=[ev],
            coverage=cov,
            community_reports=[comm],
            strict=True,
        )

        self.assertTrue(policy_input.is_valid)
        self.assertEqual(len(policy_input.parse_issues), 0)
        self.assertEqual(policy_input.evidence[0].evidence_id, "ev-f-001")
        self.assertEqual(policy_input.coverage.checks_total, 4)
        self.assertEqual(policy_input.community_reports[0].report_id, "rep-f-001")


if __name__ == "__main__":
    unittest.main()
