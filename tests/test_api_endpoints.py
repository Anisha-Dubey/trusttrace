"""Integration tests for Worker 02 REST API endpoints."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import unittest
from fastapi.testclient import TestClient

from trusttrace.api.app import app
from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.api.routes.evidence import evidence_service, provenance_engine
from trusttrace.api.routes.community import community_service, moderation_service
from trusttrace.evidence.community.rate_limiter import default_rate_limiter


class TestAPIEndpoints(unittest.TestCase):
    """End-to-end API test suite using FastAPI TestClient."""

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

        self.client = TestClient(app)

    def test_health_check_endpoint(self):
        """GET /health returns 200 and subsystem statuses."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertEqual(json_data["status"], "ok")
        self.assertEqual(json_data["service"], "trusttrace_worker_02")
        self.assertEqual(json_data["subsystems"]["rbac_authorization"], "operational")

    def test_evidence_ingestion_and_retrieval_api(self):
        """Test POST /api/v1/evidence/ingest and GET /api/v1/scans/{scan_id}/evidence."""
        payload = {
            "scan_id": "api-scan-001",
            "kind": "tls_hostname_validation",
            "value": {"subject": "api-test.test"},
            "source": "api_test_collector",
            "observed_at": "2026-11-09T10:00:00Z",
            "status": "observed",
            "reliability": "direct_observation",
            "limitations": ["API test observation"],
        }
        # Ingest
        res = self.client.post("/api/v1/evidence/ingest", json=payload)
        self.assertEqual(res.status_code, 201)
        res_json = res.json()
        self.assertEqual(res_json["status"], "success")
        self.assertTrue(res_json["data"]["was_created"])
        ev_id = res_json["data"]["evidence"]["evidence_id"]

        # Duplicate ingest (idempotency check)
        res_dup = self.client.post("/api/v1/evidence/ingest", json=payload)
        self.assertEqual(res_dup.status_code, 201)
        self.assertFalse(res_dup.json()["data"]["was_created"])

        # Retrieve by scan
        res_list = self.client.get("/api/v1/scans/api-scan-001/evidence")
        self.assertEqual(res_list.status_code, 200)
        list_json = res_list.json()
        self.assertEqual(list_json["total"], 1)
        self.assertEqual(list_json["items"][0]["evidence_id"], ev_id)

        # Retrieve single evidence by ID
        res_single = self.client.get(f"/api/v1/evidence/{ev_id}")
        self.assertEqual(res_single.status_code, 200)
        self.assertEqual(res_single.json()["data"]["evidence_id"], ev_id)

    def test_finding_creation_and_retrieval_api(self):
        """Test POST /api/v1/scans/{scan_id}/findings and GET /api/v1/scans/{scan_id}/findings."""
        # 1. Ingest supporting evidence
        ev_res = self.client.post(
            "/api/v1/evidence/ingest",
            json={
                "scan_id": "scan-finding-api",
                "kind": "dns_lookup",
                "value": {"ips": ["1.2.3.4"]},
                "source": "dns",
                "status": "observed",
            },
        )
        ev_id = ev_res.json()["data"]["evidence"]["evidence_id"]

        # 2. Create valid finding referencing that evidence
        finding_payload = {
            "kind": "dns_consistency",
            "severity": "info",
            "summary": "DNS record consistent with expectation",
            "evidence_ids": [ev_id],
            "rule_id": "dns-rule-01",
            "rule_version": "1.0",
        }
        res_finding = self.client.post("/api/v1/scans/scan-finding-api/findings", json=finding_payload)
        self.assertEqual(res_finding.status_code, 201)
        f_data = res_finding.json()["data"]
        self.assertEqual(f_data["evidence_ids"], [ev_id])

        # 3. Try creating orphan finding (non-existent evidence) -> 400 Bad Request
        bad_payload = {
            "kind": "dns_consistency",
            "severity": "high",
            "summary": "Dangling finding",
            "evidence_ids": ["ev-missing-999"],
            "rule_id": "dns-rule-01",
            "rule_version": "1.0",
        }
        bad_res = self.client.post("/api/v1/scans/scan-finding-api/findings", json=bad_payload)
        self.assertEqual(bad_res.status_code, 400)
        self.assertIn("Referential integrity violation", bad_res.json()["detail"])

        # 4. Retrieve findings
        get_res = self.client.get("/api/v1/scans/scan-finding-api/findings")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(len(get_res.json()["data"]), 1)

    def test_coverage_and_provenance_api(self):
        """Test GET coverage and provenance endpoints."""
        self.client.post(
            "/api/v1/evidence/ingest",
            json={
                "scan_id": "scan-cov-api",
                "kind": "dns",
                "source": "dns",
                "status": "observed",
            },
        )
        cov_res = self.client.get("/api/v1/scans/scan-cov-api/coverage")
        self.assertEqual(cov_res.status_code, 200)
        cov_data = cov_res.json()["data"]
        self.assertEqual(cov_data["checks_observed"], 1)
        self.assertEqual(cov_data["checks_total"], 4)

        prov_res = self.client.get("/api/v1/scans/scan-cov-api/provenance")
        self.assertEqual(prov_res.status_code, 200)
        prov_data = prov_res.json()["data"]
        self.assertEqual(prov_data["evidence_count"], 1)

    def test_community_reports_api_lifecycle(self):
        """Test community report submission, listing, authenticated review, and audit trail via REST."""
        # 1. Submit community report as a community user
        submit_payload = {
            "normalized_domain": "api-phish.test",
            "claim_type": "phishing",
            "note": "Credential harvester observed on login page",
            "source_family": "community_user",
        }
        res_submit = self.client.post("/api/v1/community/reports", json=submit_payload)
        self.assertEqual(res_submit.status_code, 201)
        rep_data = res_submit.json()["data"]["report"]
        report_id = rep_data["report_id"]
        self.assertEqual(rep_data["verification_state"], "unverified")

        # 2. List community reports by domain
        res_list = self.client.get("/api/v1/community/reports?domain=api-phish.test")
        self.assertEqual(res_list.status_code, 200)
        self.assertEqual(res_list.json()["total"], 1)

        # 3. Moderation review with valid Bearer token
        review_payload = {
            "target_state": "reviewed",
            "reason": "Confirmed against threat feed logs",
        }
        res_review = self.client.post(
            f"/api/v1/community/reports/{report_id}/review",
            json=review_payload,
            headers={"Authorization": "Bearer mod-secret-token-key-2026"},
        )
        self.assertEqual(res_review.status_code, 200)
        self.assertEqual(res_review.json()["data"]["verification_state"], "reviewed")

        # 4. Fetch audit trail (unauthenticated should be 401, authenticated viewer 200)
        res_audit_unauth = self.client.get(f"/api/v1/community/reports/{report_id}/audit")
        self.assertEqual(res_audit_unauth.status_code, 401)

        res_audit = self.client.get(
            f"/api/v1/community/reports/{report_id}/audit",
            headers={"Authorization": "Bearer viewer-secret-token-key-2026"},
        )
        self.assertEqual(res_audit.status_code, 200)
        audit_events = res_audit.json()["data"]
        self.assertEqual(len(audit_events), 2)
        self.assertEqual(audit_events[0]["action"], "submitted")
        self.assertEqual(audit_events[1]["new_state"], "reviewed")

        # 5. Verify correlation ID middleware and readiness probe
        self.assertIn("x-request-id", res_audit.headers)
        res_ready = self.client.get("/ready")
        self.assertEqual(res_ready.status_code, 200)
        self.assertEqual(res_ready.json()["status"], "ready")


if __name__ == "__main__":
    unittest.main()
