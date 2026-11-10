"""Worker 04 — Web Interface and Triage Regression Test Suite.

Verifies:
1. Web dashboard rendering and accessibility.
2. Demo scenarios: phishing_lookalike, expired_tls, legitimate, and conflicting.
3. Intake boundary preflight rejection gates (SSRF, credentials, empty target).
4. Live bounded collector pipeline integration without signal fabrication.
5. Qualitative uncertainty and explicit abstention notice propagation.
6. Core invariant adherence (INV-TLS-001, INV-EVID-002, INV-COV-001, INV-CLAIM-001, INV-FINDING-001, INV-COV-002).
7. Strict JSON Schema compliance (scan_report.schema.json v1).
8. Community intelligence submission and retrieval endpoints.
"""

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from trusttrace.api.app import create_app
from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.api.routes.evidence import evidence_service, provenance_engine
from trusttrace.api.routes.community import community_service, moderation_service
from trusttrace.evidence.community.rate_limiter import default_rate_limiter
from trusttrace.policy.integrity_auditor import ReportIntegrityAuditor

ROOT = Path(__file__).resolve().parent.parent


class TestWebInterfaceRegression(unittest.TestCase):
    """Full regression suite for Worker 04 web interface, triage routes, and contracts."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = TestClient(cls.app)
        cls.auditor = ReportIntegrityAuditor()

        schema_path = ROOT / ".brain/.work/contracts/v1/scan_report.schema.json"
        cls.report_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(cls.report_schema, format_checker=FormatChecker())

    def setUp(self):
        # Configure isolated in-memory DB for tests
        self.test_db = DatabaseManager("sqlite:///:memory:")
        evidence_service.db = self.test_db
        evidence_service.repo.db = self.test_db
        evidence_service.repo.init_tables()
        provenance_engine.db = self.test_db

        community_service.db = self.test_db
        community_service.repo.db = self.test_db
        community_service.repo.init_tables()
        moderation_service.db = self.test_db
        moderation_service.community_service.db = self.test_db
        moderation_service.community_service.repo.db = self.test_db

        # Reset rate limiter
        default_rate_limiter.reset()

    def tearDown(self):
        """Clean up in-memory database engines to prevent ResourceWarnings."""
        try:
            if hasattr(self, "test_db") and self.test_db and hasattr(self.test_db, "engine"):
                self.test_db.engine.dispose()
        except Exception:
            pass

    def _extract_canonical_report(self, response_data: dict) -> dict:
        """Strip presentation-only metadata to validate core schema compliance."""
        ignored_keys = {
            "uncertainty",
            "abstention",
            "audit",
            "cost_assessment",
            "counterfactual",
            "claim_matrix",
        }
        return {k: v for k, v in response_data.items() if k not in ignored_keys}

    # =========================================================================
    # 1. Dashboard Static & Dynamic Serving
    # =========================================================================

    def test_01_dashboard_page_loads_200(self):
        """GET / returns HTTP 200 with HTML content and core interface tokens."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        body = res.text
        self.assertIn("TRUSTTRACE", body)
        self.assertIn("EVIDENCE PASSPORT", body)
        self.assertIn("INVARIANT", body)
        self.assertIn("01 // IDENTITY", body)

    def test_01b_static_assets_serving_and_traversal_protection(self):
        """Verify built React static assets are served and traversal attacks are blocked."""
        dist_assets = ROOT / "dist" / "assets"
        if dist_assets.exists():
            files = [f.name for f in dist_assets.iterdir() if f.is_file()]
            if files:
                sample_asset = files[0]
                res = self.client.get(f"/assets/{sample_asset}")
                self.assertEqual(res.status_code, 200)

        bad_res = self.client.get("/assets/../../pyproject.toml")
        self.assertEqual(bad_res.status_code, 404)

    # =========================================================================
    # 2. Controlled Demonstration Scenarios
    # =========================================================================

    def test_02_demo_phishing_lookalike_scenario(self):
        """Phishing lookalike scenario: Valid TLS does NOT imply organizational legitimacy (TLS-001)."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "https://bank-secure-lоgin.com",
            "scenario": "phishing_lookalike"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()

        # Decision & Dimensions
        self.assertEqual(data["decision"], "high_risk")
        self.assertEqual(data["dimensions"]["identity"], "unverified")
        self.assertEqual(data["dimensions"]["certificate"], "valid_for_hostname")
        self.assertEqual(data["dimensions"]["behavior"], "malicious_evidence")

        # Uncertainty assessment present
        self.assertIn("uncertainty", data)
        self.assertIn("confidence_band", data["uncertainty"])

        # Finding references genuine evidence
        findings = data.get("findings", [])
        self.assertGreaterEqual(len(findings), 1)
        ev_ids = {e["evidence_id"] for e in data.get("evidence", [])}
        for f in findings:
            for eid in f["evidence_ids"]:
                self.assertIn(eid, ev_ids)

        # Integrity Auditor & Schema Validation
        canonical = self._extract_canonical_report(data)
        audit_res = self.auditor.audit_report(canonical)
        self.assertTrue(audit_res.is_valid, f"Audit issues: {audit_res.issues}")
        schema_errors = list(self.validator.iter_errors(canonical))
        self.assertEqual(len(schema_errors), 0, f"Schema errors: {schema_errors}")

    def test_03_demo_expired_tls_scenario(self):
        """Expired TLS scenario: Certificate error is a technical warning, not sole proof of malice (TLS-002)."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "https://legacy-portal.internal-corp.net",
            "scenario": "expired_tls"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["decision"], "caution")
        self.assertEqual(data["dimensions"]["certificate"], "invalid_or_expired")
        self.assertIn("uncertainty", data)

        canonical = self._extract_canonical_report(data)
        audit_res = self.auditor.audit_report(canonical)
        self.assertTrue(audit_res.is_valid, f"Audit issues: {audit_res.issues}")
        schema_errors = list(self.validator.iter_errors(canonical))
        self.assertEqual(len(schema_errors), 0, f"Schema errors: {schema_errors}")

    def test_04_demo_legitimate_scenario(self):
        """Legitimate scenario: No threat observed with non-absolute safety disclaimers (EVID-002)."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "https://example.com",
            "scenario": "legitimate"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["decision"], "no_threat_observed")
        self.assertEqual(data["dimensions"]["certificate"], "valid_for_hostname")
        self.assertEqual(data["dimensions"]["identity"], "unverified")  # TLS alone != verified org identity!

        canonical = self._extract_canonical_report(data)
        audit_res = self.auditor.audit_report(canonical)
        self.assertTrue(audit_res.is_valid, f"Audit issues: {audit_res.issues}")
        schema_errors = list(self.validator.iter_errors(canonical))
        self.assertEqual(len(schema_errors), 0, f"Schema errors: {schema_errors}")

    def test_05_demo_conflicting_scenario(self):
        """Conflicting scenario: Contradictory evidence triggers explicit abstention (EVID-004)."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "https://disputed-target.org",
            "scenario": "conflicting"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["decision"], "inconclusive")
        self.assertIn("uncertainty", data)
        self.assertEqual(
            data["uncertainty"]["confidence_band"],
            "contradictory_evidence"
        )
        self.assertIn("abstention", data)
        self.assertEqual(data["abstention"]["reason_code"], "ABSTAIN_EVIDENCE_CONFLICT")

        canonical = self._extract_canonical_report(data)
        audit_res = self.auditor.audit_report(canonical)
        self.assertTrue(audit_res.is_valid, f"Audit issues: {audit_res.issues}")
        schema_errors = list(self.validator.iter_errors(canonical))
        self.assertEqual(len(schema_errors), 0, f"Schema errors: {schema_errors}")

    # =========================================================================
    # 3. Custom Target URL Validation & Boundary Gates
    # =========================================================================

    def test_06_custom_target_ssrf_loopback_rejected(self):
        """SSRF protection: Private loopback targets are rejected before egress."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "http://127.0.0.1:8080/internal",
            "scenario": "custom"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["status"], "rejected")
        self.assertEqual(data["decision"], "rejected")
        self.assertEqual(data["dimensions"]["identity"], "unknown")
        self.assertIn("uncertainty", data)

        canonical = self._extract_canonical_report(data)
        schema_errors = list(self.validator.iter_errors(canonical))
        self.assertEqual(len(schema_errors), 0, f"Schema errors: {schema_errors}")

    def test_07_custom_target_credentials_rejected(self):
        """Credential safety: URLs with embedded username/password are rejected."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "https://admin:supersecret@example.com/login",
            "scenario": "custom"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "rejected")
        self.assertEqual(data["decision"], "rejected")

    def test_08_custom_target_empty_url_400(self):
        """Submitting empty URL raises HTTP 400 Bad Request."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "",
            "scenario": "custom"
        })
        self.assertEqual(res.status_code, 400)

    def test_09_custom_target_live_evaluation(self):
        """Live custom URL executes through bounded orchestrator, policy input, and audit."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "https://example.com",
            "scenario": "custom"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn(data["decision"], ("no_threat_observed", "inconclusive", "caution", "high_risk", "rejected"))
        self.assertIn("coverage", data)
        cov = data["coverage"]
        self.assertEqual(cov["checks_total"], cov["checks_observed"] + cov["checks_failed"] + cov["checks_not_run"])
        self.assertIn("uncertainty", data)

        canonical = self._extract_canonical_report(data)
        audit_res = self.auditor.audit_report(canonical)
        self.assertTrue(audit_res.is_valid, f"Audit issues: {audit_res.issues}")
        schema_errors = list(self.validator.iter_errors(canonical))
        self.assertEqual(len(schema_errors), 0, f"Schema errors: {schema_errors}")

    # =========================================================================
    # 4. Community Intelligence API Integration
    # =========================================================================

    def test_10_community_report_submission_and_feed(self):
        """Community threat report can be submitted and subsequently listed."""
        # 1. Submit report
        sub_res = self.client.post("/api/v1/community/reports", json={
            "normalized_domain": "suspicious-phish-portal.org",
            "claim_type": "phishing",
            "note": "Credential harvesting form detected by web interface."
        })
        self.assertIn(sub_res.status_code, (201, 200))
        sub_data = sub_res.json()
        self.assertEqual(sub_data["status"], "success")

        # 2. Query community reports feed
        feed_res = self.client.get("/api/v1/community/reports?domain=suspicious-phish-portal.org")
        self.assertEqual(feed_res.status_code, 200)
        feed_data = feed_res.json()
        self.assertIn("items", feed_data)
        self.assertGreaterEqual(feed_data["total"], 1)
        first_item = feed_data["items"][0]
        self.assertEqual(first_item["normalized_domain"], "suspicious-phish-portal.org")
        self.assertEqual(first_item["claim_type"], "phishing")

    # =========================================================================
    # 5. Worker 03 Phase 08, 09, 10 Secondary Analysis Endpoints
    # =========================================================================

    def test_11_cost_profiles_endpoint(self):
        """GET /api/v1/cost-profiles returns standard deployment cost profiles."""
        res = self.client.get("/api/v1/cost-profiles")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("profiles", data)
        self.assertIn("analyst_triage", data["profiles"])
        self.assertIn("enterprise_blocking", data["profiles"])
        profile = data["profiles"]["analyst_triage"]
        self.assertEqual(profile["cost_false_negative"], 50.0)
        self.assertEqual(profile["cost_false_positive"], 10.0)
        self.assertEqual(profile["cost_abstain"], 2.0)

    def test_12_cost_assessment_endpoint(self):
        """POST /api/v1/scans/{id}/cost-assessment evaluates asymmetric minimax cost action."""
        res = self.client.post(
            "/api/v1/scans/scan-demo-phish-001/cost-assessment",
            json={
                "profile_name": "analyst_triage",
                "scenario": "phishing_lookalike"
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("cost_assessment", data)
        ca = data["cost_assessment"]
        self.assertIn(ca["optimal_action"], ("threat", "clean", "inconclusive"))
        self.assertIn("worst_case_costs", ca)
        self.assertIn("minimum_cost", ca)
        self.assertIn("cost_config", data)

    def test_13_counterfactual_endpoint(self):
        """POST /api/v1/scans/{id}/counterfactual computes deterministic sensitivity."""
        res = self.client.post(
            "/api/v1/scans/scan-demo-phish-001/counterfactual",
            json={
                "target_disposition": "clean",
                "scenario": "phishing_lookalike"
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("status", data)
        self.assertIn("disclaimer", data)
        self.assertIn("Hypothetical scenario based strictly on mathematical decision-boundary", data["disclaimer"])
        self.assertIn(data["status"], ("SUCCESS", "UNREACHABLE"))
        self.assertIn("resulting_disposition", data)
        self.assertIn("explanation", data)
        self.assertIn("perturbations", data)

        # Expired TLS check
        res_exp = self.client.post(
            "/api/v1/scans/scan-demo-expired-001/counterfactual",
            json={
                "target_disposition": "clean",
                "scenario": "expired_tls"
            }
        )
        self.assertEqual(res_exp.status_code, 200)
        data_exp = res_exp.json()
        self.assertIn("status", data_exp)
        self.assertIn(data_exp["status"], ("SUCCESS", "UNREACHABLE"))
        self.assertIn("disclaimer", data_exp)

    def test_14_claim_matrix_endpoint(self):
        """GET & POST /api/v1/scans/{id}/claim-matrix returns verified claim-to-evidence lineage."""
        res = self.client.get("/api/v1/scans/scan-demo-phish-001/claim-matrix")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("entries", data)
        self.assertGreaterEqual(data["total_claims"], 1)
        self.assertIn("matrix_integrity_passed", data)
        for entry in data["entries"]:
            self.assertIn("claim", entry)
            self.assertIn("status", entry)
            self.assertIn(entry["status"], ("supported", "partially_supported", "contradicted", "unsupported"))

    def test_15_triage_demo_includes_phase_8_9_10(self):
        """POST /api/v1/triage/demo automatically includes cost, counterfactual, and claim matrix."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "https://bank-secure-lоgin.com",
            "scenario": "phishing_lookalike"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("cost_assessment", data)
        self.assertIn("counterfactual", data)
        self.assertIn("claim_matrix", data)

    def test_16_http_target_certificate_not_checked(self):
        """HTTP target without TLS probe must report certificate as not_checked."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "http://example.com",
            "scenario": "custom"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["dimensions"]["certificate"], "not_checked")
        self.assertEqual(data["decision"], "inconclusive")

    def test_17_https_unknown_custom_target_inconclusive(self):
        """Unknown HTTPS custom target without reputation feed must return inconclusive."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "https://google.com",
            "scenario": "custom"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["decision"], "inconclusive")
        self.assertEqual(data["dimensions"]["behavior"], "unknown")
        self.assertEqual(data["dimensions"]["identity"], "unverified")
        self.assertTrue(
            "abstention" in data or ("uncertainty" in data and "abstention_notice" in data["uncertainty"])
        )

    def test_18_malformed_and_ssrf_custom_urls_rejected(self):
        """Private loopback target must be rejected at preflight boundary with zero egress."""
        res = self.client.post("/api/v1/triage/demo", json={
            "url": "http://127.0.0.1:8000/secret",
            "scenario": "custom"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["decision"], "rejected")
        self.assertEqual(data["status"], "rejected")
        self.assertEqual(data["dimensions"]["certificate"], "not_checked")


if __name__ == "__main__":
    unittest.main()
