"""End-to-End Integration Verification Suite for Worker 01 + Worker 02.

Validates the complete execution flow:
URL Intake -> URL Safety Boundary -> Bounded Collectors -> Validated Output Contract ->
Worker 02 Evidence Adapter -> Evidence Ingestion & Persistence -> Findings Linkage ->
Coverage Calculation -> Policy Triage Assessment.
"""

import os
import sys
import json
import uuid
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from jsonschema import Draft202012Validator, FormatChecker

# Worker 01 Components
from trusttrace.intake.boundary import IntakeBoundary
from trusttrace.intake.dns_resolver import SafeDNSResolver
from trusttrace.collectors.base import CollectorResult

# Worker 02 Components
from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.evidence.persistence.repository import EvidenceRepository, compute_evidence_fingerprint
from trusttrace.evidence.persistence.models import EvidenceEntity
from trusttrace.evidence.services.evidence_service import EvidenceService
from trusttrace.evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
from trusttrace.evidence.community.service import CommunityIntelligenceService
from trusttrace.evidence.domain.models import EvidenceModel, FindingModel
from trusttrace.evidence.domain.enums import (
    EvidenceStatus,
    Reliability,
    FindingSeverity,
    VerificationState,
    ClaimType,
)

# Worker 03 Policy Components
from trusttrace.policy.triage_engine import TriageEngine
from trusttrace.policy.signal_taxonomy import SignalRecord, SignalKind


class TestWorker01Worker02E2EIntegration(unittest.TestCase):
    """End-to-End integration test suite verifying Worker 01 and Worker 02 coordination."""

    def setUp(self):
        self.db = DatabaseManager("sqlite:///:memory:")
        self.repo = EvidenceRepository(self.db)
        self.ev_service = EvidenceService(db_manager=self.db, repository=self.repo)
        self.comm_service = CommunityIntelligenceService(db_manager=self.db, repository=self.repo)
        self.boundary = IntakeBoundary()
        self.triage_engine = TriageEngine()

        schema_path = ROOT / ".brain/.work/contracts/v1/scan_report.schema.json"
        self.report_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.validator = Draft202012Validator(self.report_schema, format_checker=FormatChecker())

    def tearDown(self):
        if hasattr(self, "db") and self.db:
            self.db.engine.dispose()

    # =========================================================================
    # 1. Full Happy Path: Intake -> Collectors -> Adapter -> Persistence -> Linkage
    # =========================================================================

    def test_01_e2e_valid_url_full_lifecycle(self):
        """E2E-01: Valid target flows from intake through collectors, adapter, persistence, and triage."""
        target_url = "https://secure-portal.example.org/login"
        scan_id = f"e2e-scan-{uuid.uuid4().hex[:8]}"

        # Step 1: Worker 01 Intake URL validation with deterministic safe resolver
        mock_resolver = SafeDNSResolver(custom_lookup_fn=lambda host, port: ["93.184.216.34"])
        boundary = IntakeBoundary(resolver=mock_resolver)
        eval_res = boundary.evaluate_target(target_url)
        self.assertTrue(eval_res.is_safe, "Safe public URL must pass intake boundary")
        self.assertEqual(eval_res.normalized_host, "secure-portal.example.org")

        # Step 2: Worker 01 Bounded Collection simulation (DNS, TLS, HTTP)
        dns_ev = CollectorResult(
            kind="dns_resolution",
            value={"ip": "93.184.216.34", "records": ["A 93.184.216.34"]},
            source="worker01_dns",
            status="observed",
            reliability="direct_observation",
        )
        tls_ev = CollectorResult(
            kind="tls_hostname_validation",
            value={"hostname_matches": True, "issuer": "DigiCert Global Root G2"},
            source="worker01_tls",
            status="observed",
            reliability="direct_observation",
        )
        http_ev = CollectorResult(
            kind="http_headers",
            value={"status_code": 200, "server": "cloudflare"},
            source="worker01_http",
            status="observed",
            reliability="direct_observation",
        )

        w01_report = {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "submitted_url_redacted": target_url,
            "normalized_host": eval_res.normalized_host,
            "status": "completed",
            "decision": "inconclusive",
            "created_at": "2026-11-10T03:00:00Z",
            "completed_at": "2026-11-10T03:00:02Z",
            "policy_version": "1.0",
            "dimensions": {
                "identity": "unverified",
                "certificate": "valid_for_hostname",
                "behavior": "unknown",
                "evidence_quality": "strong",
            },
            "coverage": {
                "checks_total": 3,
                "checks_observed": 3,
                "checks_failed": 0,
                "checks_not_run": 0,
            },
            "evidence": [dns_ev.to_dict(), tls_ev.to_dict(), http_ev.to_dict()],
            "findings": [],
            "limitations": [],
        }

        # Step 3: Verify Worker 01 report strictly validates against contract schema
        errors = list(self.validator.iter_errors(w01_report))
        self.assertEqual(len(errors), 0, f"Worker 01 output violated contract schema: {errors}")

        # Step 4: Worker 02 Adapter translates contract payload to EvidenceBatch
        adapter = Worker01EvidenceAdapter()
        batch = adapter.adapt_payload(scan_id=scan_id, payload=w01_report)
        self.assertEqual(batch.scan_id, scan_id)
        self.assertEqual(len(batch.items), 3)

        # Step 5: Worker 02 Evidence Ingestion & Persistence
        ingest_res = self.ev_service.ingest_batch(batch)
        self.assertEqual(ingest_res.inserted_count, 3)
        self.assertEqual(ingest_res.deduplicated_count, 0)

        # Step 6: Verify evidence provenance and persistence in DB
        with self.db.session_scope() as session:
            persisted = self.repo.get_evidence_by_scan(session, scan_id)
            self.assertEqual(len(persisted), 3)
            kinds = {e.kind for e in persisted}
            self.assertEqual(kinds, {"dns_resolution", "tls_hostname_validation", "http_headers"})

            for ev in persisted:
                self.assertEqual(ev.source_type, "worker_01_intake")
                # Query entity to verify database-persisted fingerprint
                entity = session.get(EvidenceEntity, ev.evidence_id)
                self.assertIsNotNone(entity)
                self.assertIsNotNone(entity.fingerprint)
                # Recomputed fingerprint must match persisted fingerprint
                expected_fp = compute_evidence_fingerprint(
                    scan_id=scan_id,
                    kind=ev.kind,
                    source=ev.source,
                    value=ev.value,
                    observed_at=ev.observed_at,
                    status=ev.status,
                )
                self.assertEqual(entity.fingerprint, expected_fp)

        # Step 7: Coverage verification
        cov = self.ev_service.calculate_coverage(batch.items, expected_total_checks=3)
        self.assertEqual(cov.checks_total, 3)
        self.assertEqual(cov.checks_observed, 3)
        self.assertEqual(cov.checks_failed, 0)
        self.assertEqual(cov.checks_not_run, 0)

        # Step 8: Findings linkage to persisted evidence
        tls_ev_id = next(e.evidence_id for e in batch.items if e.kind == "tls_hostname_validation")
        finding = FindingModel(
            finding_id=f"find-{uuid.uuid4().hex[:8]}",
            scan_id=scan_id,
            kind="tls_certificate_valid",
            severity=FindingSeverity.INFO,
            summary="TLS certificate matches hostname but domain identity remains unverified absent authorization.",
            evidence_ids=[tls_ev_id],
            rule_id="RULE-TLS-001",
            rule_version="1.0",
        )
        with self.db.session_scope() as session:
            self.repo.save_finding(session, scan_id, finding)
            retrieved_findings = self.repo.get_findings_by_scan(session, scan_id)
            self.assertEqual(len(retrieved_findings), 1)
            self.assertEqual(retrieved_findings[0].evidence_ids, [tls_ev_id])

        # Step 9: Worker 03 Policy Assessment: non-threat evidence must never be auto-labeled 'safe'
        sig = SignalRecord(
            kind=SignalKind.TLS_VALID,
            evidence_ids=[tls_ev_id],
            source="worker01_tls",
            confidence="direct_observation",
        )
        triage = self.triage_engine.evaluate([sig])
        self.assertNotEqual(triage.decision, "safe", "Valid TLS alone must never warrant 'safe' decision")
        self.assertIn(triage.decision, ("inconclusive", "caution", "no_threat_observed"))

    # =========================================================================
    # 2. SSRF, Loopback & Credential Prohibited Targets Flow
    # =========================================================================

    def test_02_e2e_prohibited_ssrf_rejection_flow(self):
        """E2E-02: SSRF and credentialed URLs are blocked at intake, adapted, and stored truthfully."""
        blocked_targets = [
            ("http://127.0.0.1:8080/internal/admin", "loopback_blocked"),
            ("http://169.254.169.254/latest/meta-data/", "metadata_blocked"),
            ("https://admin:secret123@target-phish.test/", "credentials_blocked"),
            ("file:///etc/shadow", "unsupported_scheme_blocked"),
        ]

        for raw_url, tag in blocked_targets:
            scan_id = f"e2e-block-{tag}-{uuid.uuid4().hex[:6]}"

            # Worker 01 Intake evaluates target
            eval_res = self.boundary.evaluate_target(raw_url)
            self.assertFalse(eval_res.is_safe, f"{raw_url} must be flagged unsafe by intake boundary")

            # Worker 01 builds rejection report
            rejected_report = self.boundary.build_rejected_report(scan_id=scan_id, evaluation=eval_res)
            self.assertEqual(rejected_report["status"], "rejected")
            self.assertEqual(rejected_report["decision"], "rejected")

            # Contract schema validation
            errors = list(self.validator.iter_errors(rejected_report))
            self.assertEqual(len(errors), 0, f"Rejection report violated contract: {errors}")

            # Worker 02 Adapter ingests rejection report
            adapter = Worker01EvidenceAdapter()
            batch = adapter.adapt_payload(scan_id, rejected_report)
            self.assertGreaterEqual(len(batch.items), 1)

            # Ingest batch
            ingest_res = self.ev_service.ingest_batch(batch)
            self.assertEqual(ingest_res.inserted_count, len(batch.items))

            # Verify persisted evidence reflects rejection
            with self.db.session_scope() as session:
                persisted = self.repo.get_evidence_by_scan(session, scan_id)
                self.assertTrue(
                    any(e.status in (EvidenceStatus.BLOCKED, EvidenceStatus.UNAVAILABLE) for e in persisted)
                )

    # =========================================================================
    # 3. Partial Collection & Missingness Representation
    # =========================================================================

    def test_03_e2e_partial_collection_and_missingness_handling(self):
        """E2E-03: Collector timeout produces truthful partial coverage; missing evidence is never 'safe'."""
        scan_id = f"e2e-partial-{uuid.uuid4().hex[:8]}"

        # 1 observed check, 2 failed/timed out checks
        dns_ev = CollectorResult(
            kind="dns_resolution",
            value={"ip": "1.2.3.4"},
            source="worker01_dns",
            status="observed",
        )
        tls_ev = CollectorResult(
            kind="tls_hostname_validation",
            value={"error": "Connection timed out after 3.0s budget"},
            source="worker01_tls",
            status="failed",
            limitations=["timeout_budget_exceeded"],
        )
        http_ev = CollectorResult(
            kind="http_headers",
            value={"error": "Collector cancelled"},
            source="worker01_http",
            status="unavailable",
            limitations=["scan_timeout"],
        )

        partial_report = {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "submitted_url_redacted": "https://slow-target.example.org/",
            "normalized_host": "slow-target.example.org",
            "status": "partial",
            "decision": "inconclusive",
            "created_at": "2026-11-10T03:00:00Z",
            "completed_at": "2026-11-10T03:00:03Z",
            "policy_version": "1.0",
            "dimensions": {
                "identity": "unknown",
                "certificate": "not_checked",
                "behavior": "unknown",
                "evidence_quality": "weak",
            },
            "coverage": {
                "checks_total": 3,
                "checks_observed": 1,
                "checks_failed": 1,
                "checks_not_run": 1,
            },
            "evidence": [dns_ev.to_dict(), tls_ev.to_dict(), http_ev.to_dict()],
            "findings": [],
            "limitations": ["scan_timeout"],
        }

        # Validate schema
        errors = list(self.validator.iter_errors(partial_report))
        self.assertEqual(len(errors), 0)

        # Worker 02 ingests partial batch
        adapter = Worker01EvidenceAdapter()
        batch = adapter.adapt_payload(scan_id, partial_report)
        ingest_res = self.ev_service.ingest_batch(batch)
        self.assertEqual(ingest_res.inserted_count, 3)

        # Calculate coverage through EvidenceService
        cov = self.ev_service.calculate_coverage(batch.items, expected_total_checks=3)
        self.assertEqual(cov.checks_total, 3)
        self.assertEqual(cov.checks_observed, 1)
        self.assertEqual(cov.checks_failed, 1)
        self.assertEqual(cov.checks_not_run, 1)

        # Triage assessment with partial evidence
        sig_success = SignalRecord(
            kind=SignalKind.COLLECTOR_SUCCESS,
            evidence_ids=[batch.items[0].evidence_id],
            source="worker01_dns",
            confidence="direct_observation",
        )
        sig_fail = SignalRecord(
            kind=SignalKind.COLLECTOR_FAILURE,
            evidence_ids=[batch.items[1].evidence_id],
            source="worker01_tls",
            confidence="heuristic",
        )
        triage = self.triage_engine.evaluate([sig_success, sig_fail])
        self.assertEqual(triage.decision, "inconclusive", "Partial/missing evidence must yield inconclusive")
        self.assertEqual(triage.dimensions["evidence_quality"], "partial")

    # =========================================================================
    # 4. Referential Integrity & Dangling Evidence Prevention
    # =========================================================================

    def test_04_e2e_referential_integrity_and_dangling_evidence_prevention(self):
        """E2E-04: Findings referencing nonexistent or cross-scan evidence are strictly rejected."""
        scan_id_a = f"scan-a-{uuid.uuid4().hex[:6]}"
        scan_id_b = f"scan-b-{uuid.uuid4().hex[:6]}"

        # Ingest evidence for scan A
        ev_a = EvidenceModel(
            evidence_id="ev-real-a",
            scan_id=scan_id_a,
            kind="dns_resolution",
            value={"ip": "10.0.0.1"},
            source="worker01_dns",
            observed_at="2026-11-10T03:00:00Z",
            status=EvidenceStatus.OBSERVED,
        )
        with self.db.session_scope() as session:
            self.repo.save_evidence(session, scan_id_a, ev_a)

        # Finding with dangling evidence ID (does not exist anywhere)
        dangling_finding = FindingModel(
            finding_id="find-dangling",
            scan_id=scan_id_a,
            kind="suspicious_signal",
            severity=FindingSeverity.MEDIUM,
            summary="Test dangling link",
            evidence_ids=["ev-nonexistent-999"],
            rule_id="RULE-TEST-001",
            rule_version="1.0",
        )
        with self.assertRaises(ValueError) as ctx:
            with self.db.session_scope() as session:
                self.repo.save_finding(session, scan_id_a, dangling_finding)
        self.assertIn("Referential integrity violation", str(ctx.exception))

        # Finding referencing evidence from scan A but filed under scan B (cross-scan injection)
        cross_scan_finding = FindingModel(
            finding_id="find-cross",
            scan_id=scan_id_b,
            kind="suspicious_signal",
            severity=FindingSeverity.MEDIUM,
            summary="Cross-scan attempt",
            evidence_ids=["ev-real-a"],
            rule_id="RULE-TEST-002",
            rule_version="1.0",
        )
        with self.assertRaises(ValueError) as ctx2:
            with self.db.session_scope() as session:
                self.repo.save_finding(session, scan_id_b, cross_scan_finding)
        self.assertIn("Referential integrity violation", str(ctx2.exception))

    # =========================================================================
    # 5. Community Intelligence & Scan Evidence Cross-Reference
    # =========================================================================

    def test_05_e2e_community_report_with_persisted_scan_evidence(self):
        """E2E-05: Community report linking scan evidence verifies matching domain and lifecycle."""
        domain = "phish-bank.test"
        scan_id = f"scan-comm-{uuid.uuid4().hex[:6]}"
        ev_id = f"ev-tls-{uuid.uuid4().hex[:6]}"

        # Step 1: Ingest scan evidence for domain
        evidence = EvidenceModel(
            evidence_id=ev_id,
            scan_id=scan_id,
            kind="tls_hostname_validation",
            value={"hostname": domain, "matches": False},
            source="worker01_tls",
            observed_at="2026-11-10T03:00:00Z",
            status=EvidenceStatus.OBSERVED,
        )
        with self.db.session_scope() as session:
            self.repo.ensure_scan(session, scan_id=scan_id, normalized_host=domain)
            self.repo.save_evidence(session, scan_id, evidence)

        # Step 2: Submit community report referencing the valid scan evidence
        rep, dedup = self.comm_service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            note="Fake credential harvester observed",
            raw_reporter_identifier="reporter_user_1",
            linked_evidence_ids=[ev_id],
        )

        self.assertEqual(rep.verification_state, VerificationState.UNVERIFIED)
        self.assertEqual(rep.independent_source_count, 1)
        self.assertEqual(rep.linked_evidence_ids, [ev_id])

        # Step 3: Unverified community report does NOT auto-label
        sig = SignalRecord(
            kind=SignalKind.COMMUNITY_REPORT_UNVERIFIED,
            evidence_ids=[rep.report_id],
            source="community_intelligence",
            confidence="unverified_third_party",
        )
        triage = self.triage_engine.evaluate([sig])
        self.assertNotEqual(triage.decision, "high_risk", "Unverified community report cannot trigger high_risk")

        # Step 4: Submission with cross-domain evidence link is rejected
        other_domain = "unrelated-corp.test"
        with self.assertRaises(ValueError) as ctx:
            self.comm_service.submit_report(
                normalized_domain=other_domain,
                claim_type="phishing",
                raw_reporter_identifier="reporter_user_2",
                linked_evidence_ids=[ev_id],  # ev_id belongs to phish-bank.test!
            )
        self.assertIn("does not match report domain", str(ctx.exception))

    # =========================================================================
    # 6. Duplicate Evidence Idempotency & Corroboration Count Protection
    # =========================================================================

    def test_06_e2e_duplicate_evidence_idempotency(self):
        """E2E-06: Repeated ingestion of identical evidence is idempotent and never inflates count."""
        scan_id = f"scan-idempotent-{uuid.uuid4().hex[:6]}"
        batch = Worker01EvidenceAdapter().adapt_payload(
            scan_id,
            {"evidence": [{"evidence_id": "ev-idemp-1", "kind": "dns_resolution", "value": {"ip": "1.1.1.1"}, "source": "worker01_dns"}]}
        )

        res1 = self.ev_service.ingest_batch(batch)
        self.assertEqual(res1.inserted_count, 1)

        # Ingest exact same batch a second time
        res2 = self.ev_service.ingest_batch(batch)
        self.assertEqual(res2.inserted_count, 0)
        self.assertEqual(res2.deduplicated_count, 1)

        with self.db.session_scope() as session:
            records = self.repo.get_evidence_by_scan(session, scan_id)
            self.assertEqual(len(records), 1, "Duplicate evidence must not create multiple DB rows")


if __name__ == "__main__":
    unittest.main()
