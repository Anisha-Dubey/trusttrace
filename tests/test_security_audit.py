"""Focused Negative Security Audit Test Suite for TRUSTTRACE Worker 02."""

import sys
import os
import unittest
from pathlib import Path

# Ensure src is in sys.path when running standalone
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient

from trusttrace.api.app import app, get_cors_configuration
from trusttrace.api.auth import validate_token_configuration
from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.evidence.persistence.repository import EvidenceRepository
from trusttrace.api.routes.evidence import evidence_service, provenance_engine
from trusttrace.api.routes.community import community_service, moderation_service
from trusttrace.evidence.community.rate_limiter import default_rate_limiter
from trusttrace.evidence.community.sanitizer import get_reporter_salt
from trusttrace.evidence.domain.models import EvidenceModel
from trusttrace.evidence.domain.enums import EvidenceStatus


class TestSecurityAudit(unittest.TestCase):
    """Rigorous negative tests verifying all security remediation gates (SEC-01 through SEC-23)."""

    def setUp(self):
        # Fresh isolated DB
        self.test_db = DatabaseManager("sqlite:///:memory:")
        self.repo = EvidenceRepository(db_manager=self.test_db)
        self.repo.init_tables()

        evidence_service.db = self.test_db
        evidence_service.repo = self.repo
        provenance_engine.db = self.test_db

        community_service.db = self.test_db
        community_service.repo = self.repo
        moderation_service.db = self.test_db
        moderation_service.community_service.db = self.test_db
        moderation_service.community_service.repo = self.repo

        default_rate_limiter.reset()
        self.client = TestClient(app)

    def tearDown(self):
        default_rate_limiter.reset()
        if hasattr(self, "test_db") and self.test_db and hasattr(self.test_db, "engine"):
            self.test_db.engine.dispose()

    def _create_sample_report(self, domain="security-test.test") -> str:
        """Helper to create an unverified report for moderation tests."""
        res = self.client.post(
            "/api/v1/community/reports",
            json={
                "normalized_domain": domain,
                "claim_type": "phishing",
                "note": "Initial suspicious observation",
                "source_family": "community_user",
            },
        )
        return res.json()["data"]["report"]["report_id"]

    # --- 1. Authentication Tests ---

    def test_unauthenticated_moderation_rejected_401(self):
        """SEC-01: Moderation endpoints MUST reject requests without Bearer credentials with 401."""
        report_id = self._create_sample_report("sec-unauth.test")
        payload = {
            "target_state": "reviewed",
            "reason": "Attempting unauthenticated moderation",
        }
        res = self.client.post(f"/api/v1/community/reports/{report_id}/review", json=payload)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Missing authentication credentials", res.json()["detail"])

    def test_invalid_token_moderation_rejected_401(self):
        """SEC-02: Moderation endpoints MUST reject malformed or fabricated tokens with 401."""
        report_id = self._create_sample_report("sec-invalid-token.test")
        payload = {
            "target_state": "reviewed",
            "reason": "Attempting bogus token moderation",
        }
        res = self.client.post(
            f"/api/v1/community/reports/{report_id}/review",
            json=payload,
            headers={"Authorization": "Bearer bogus-forged-token-xyz"},
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("Invalid or expired authentication credentials", res.json()["detail"])

    # --- 2. Authorization (RBAC) Tests ---

    def test_unauthorized_role_moderation_rejected_403(self):
        """SEC-03: Authenticated users lacking 'moderator' or 'admin' role MUST be rejected with 403."""
        report_id = self._create_sample_report("sec-rbac-fail.test")
        payload = {
            "target_state": "reviewed",
            "reason": "Viewer role attempting moderation action",
        }
        # viewer token is valid, but role is 'viewer' (not moderator or admin)
        res = self.client.post(
            f"/api/v1/community/reports/{report_id}/review",
            json=payload,
            headers={"Authorization": "Bearer viewer-secret-token-key-2026"},
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn("Insufficient privileges", res.json()["detail"])

    def test_authorized_moderator_role_accepted_200(self):
        """SEC-04: Authenticated user with 'moderator' role is permitted to review."""
        report_id = self._create_sample_report("sec-rbac-pass.test")
        payload = {
            "target_state": "reviewed",
            "reason": "Valid review by certified moderator",
        }
        res = self.client.post(
            f"/api/v1/community/reports/{report_id}/review",
            json=payload,
            headers={"Authorization": "Bearer mod-secret-token-key-2026"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["data"]["verification_state"], "reviewed")

    # --- 3. Moderator Identity Spoofing Prevention ---

    def test_moderator_identity_spoofing_prevented(self):
        """SEC-05: Client cannot spoof moderator_ref in request body; identity is derived from verified token."""
        report_id = self._create_sample_report("sec-spoof-mod.test")
        payload = {
            "target_state": "reviewed",
            "reason": "Valid review action",
            "moderator_ref": "fake_chief_security_officer",  # Spoofed name attempt
        }
        res = self.client.post(
            f"/api/v1/community/reports/{report_id}/review",
            json=payload,
            headers={"Authorization": "Bearer mod-secret-token-key-2026"},
        )
        self.assertEqual(res.status_code, 200)

        # Inspect audit history: Actor MUST be bound to authenticated token username, NOT spoofed name
        audit_res = self.client.get(
            f"/api/v1/community/reports/{report_id}/audit",
            headers={"Authorization": "Bearer viewer-secret-token-key-2026"},
        )
        self.assertEqual(audit_res.status_code, 200)
        audit_events = audit_res.json()["data"]
        review_event = [e for e in audit_events if e["action"] == "transition_to_reviewed"][0]
        self.assertEqual(review_event["actor_ref"], "moderator:security_moderator")
        self.assertNotIn("fake_chief_security_officer", review_event["actor_ref"])

    # --- 4. Corroboration Count Manipulation Prevention ---

    def test_corroboration_count_manipulation_prevented(self):
        """SEC-06: Client cannot supply independent_count_override to inflate corroboration."""
        report_id = self._create_sample_report("sec-count-manip.test")
        payload = {
            "target_state": "reviewed",
            "reason": "Reviewing report",
            "independent_count_override": 9999,  # Artificially high count attempt
        }
        res = self.client.post(
            f"/api/v1/community/reports/{report_id}/review",
            json=payload,
            headers={"Authorization": "Bearer mod-secret-token-key-2026"},
        )
        self.assertEqual(res.status_code, 200)
        # Server-derived count must remain 1 (single domain report)
        self.assertEqual(res.json()["data"]["independent_source_count"], 1)

    # --- 5. Source-Family Spoofing Prevention ---

    def test_source_family_spoofing_prevented_for_unauthenticated_client(self):
        """SEC-07: Unauthenticated clients attempting to claim verified provider families are rejected."""
        payload = {
            "normalized_domain": "spoof-feed.test",
            "claim_type": "phishing",
            "note": "Attacker trying to masquerade as PhishTank feed",
            "source_family": "phishtank",  # Privileged feed provider
        }
        res = self.client.post("/api/v1/community/reports", json=payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Unauthorized source family claim", res.json()["detail"])

    def test_source_family_allowed_for_authenticated_provider(self):
        """SEC-08: Authenticated provider/collector is permitted to claim verified feed families."""
        payload = {
            "normalized_domain": "verified-feed.test",
            "claim_type": "phishing",
            "note": "Legitimate automated feed ingestion",
            "source_family": "phishtank",
        }
        res = self.client.post(
            "/api/v1/community/reports",
            json=payload,
            headers={"Authorization": "Bearer collector-secret-token-key-2026"},
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["data"]["deduplication"]["category"], "new_report")

    # --- 6. CORS Configuration & Wildcard Invariant ---

    def test_cors_wildcard_with_credentials_prohibited(self):
        """SEC-09: CORS configuration must NEVER permit wildcard '*' when allow_credentials=True."""
        # 1. Test normal configuration
        origins, allow_creds = get_cors_configuration()
        if "*" in origins:
            self.assertFalse(
                allow_creds, "CRITICAL: Wildcard origin '*' MUST NOT be configured with credentials enabled!"
            )
        else:
            self.assertTrue(allow_creds)

        # 2. Test response headers for preflight request
        headers = {
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
        }
        res = self.client.options("/api/v1/community/reports", headers=headers)
        self.assertEqual(res.headers.get("access-control-allow-origin"), "http://localhost:3000")
        self.assertNotEqual(res.headers.get("access-control-allow-origin"), "*")

    # --- 7. Rate Limiting & Replay Protection ---

    def test_replay_burst_submission_rejected_429(self):
        """SEC-10: Immediate duplicate replay within burst window is rejected with 429."""
        payload = {
            "normalized_domain": "replay-test.test",
            "claim_type": "phishing",
            "note": "Legitimate claim",
        }
        res1 = self.client.post("/api/v1/community/reports", json=payload)
        self.assertEqual(res1.status_code, 201)

        # Rapid replay immediately
        res2 = self.client.post("/api/v1/community/reports", json=payload)
        self.assertEqual(res2.status_code, 429)
        self.assertIn("replayed too rapidly", res2.json()["detail"])
        self.assertEqual(res2.headers.get("Retry-After"), "60")

    def test_ip_rate_limiting_exceeded_429(self):
        """SEC-11: Burst submissions exceeding limit per minute trigger 429 Too Many Requests."""
        # Submit 10 unique domains rapidly
        for i in range(10):
            res = self.client.post(
                "/api/v1/community/reports",
                json={
                    "normalized_domain": f"rate-limit-test-{i}.test",
                    "claim_type": "phishing",
                    "note": f"Report #{i}",
                },
            )
            self.assertEqual(res.status_code, 201)

        # 11th submission from same IP must be rate limited
        res_limit = self.client.post(
            "/api/v1/community/reports",
            json={
                "normalized_domain": "rate-limit-test-11.test",
                "claim_type": "phishing",
                "note": "Excess report",
            },
        )
        self.assertEqual(res_limit.status_code, 429)
        self.assertIn("Rate limit exceeded", res_limit.json()["detail"])

    # --- 8. Production Salt Enforcement ---

    def test_production_mode_requires_secure_reporter_salt(self):
        """SEC-12: In production mode, missing or default REPORTER_SALT raises RuntimeError."""
        old_env = os.environ.get("TRUSTTRACE_ENV")
        old_salt = os.environ.get("REPORTER_SALT")
        try:
            os.environ["TRUSTTRACE_ENV"] = "production"
            os.environ.pop("REPORTER_SALT", None)

            # Must raise RuntimeError
            with self.assertRaises(RuntimeError) as ctx:
                get_reporter_salt()
            self.assertIn("FATAL CONFIGURATION ERROR", str(ctx.exception))

            # Must reject default insecure salt
            os.environ["REPORTER_SALT"] = "trusttrace-salt-hackmatrix26"
            with self.assertRaises(RuntimeError):
                get_reporter_salt()

            # High entropy salt must pass
            os.environ["REPORTER_SALT"] = "high-entropy-production-secret-salt-xyz-2026"
            salt = get_reporter_salt()
            self.assertEqual(salt, b"high-entropy-production-secret-salt-xyz-2026")
        finally:
            if old_env is not None:
                os.environ["TRUSTTRACE_ENV"] = old_env
            else:
                os.environ.pop("TRUSTTRACE_ENV", None)
            if old_salt is not None:
                os.environ["REPORTER_SALT"] = old_salt
            else:
                os.environ.pop("REPORTER_SALT", None)

    # --- 9. Production Auth Token & Credential Validation Tests ---

    def test_production_mode_fails_if_tokens_missing(self):
        """SEC-21: In production mode, missing required tokens MUST raise RuntimeError."""
        old_env = os.environ.get("TRUSTTRACE_ENV")
        try:
            os.environ["TRUSTTRACE_ENV"] = "production"
            for var in ["TRUSTTRACE_MODERATOR_TOKEN", "TRUSTTRACE_ADMIN_TOKEN", "TRUSTTRACE_COLLECTOR_TOKEN", "TRUSTTRACE_VIEWER_TOKEN"]:
                if var in os.environ:
                    del os.environ[var]
            with self.assertRaises(RuntimeError) as ctx:
                validate_token_configuration()
            self.assertIn("Missing required authentication token", str(ctx.exception))
        finally:
            if old_env is not None:
                os.environ["TRUSTTRACE_ENV"] = old_env
            else:
                os.environ.pop("TRUSTTRACE_ENV", None)

    def test_production_mode_fails_on_insecure_default_tokens(self):
        """SEC-21B: In production mode, insecure default tokens MUST raise RuntimeError."""
        old_env = os.environ.get("TRUSTTRACE_ENV")
        try:
            os.environ["TRUSTTRACE_ENV"] = "production"
            os.environ["TRUSTTRACE_MODERATOR_TOKEN"] = "mod-secret-token-key-2026"
            os.environ["TRUSTTRACE_ADMIN_TOKEN"] = "a" * 32
            os.environ["TRUSTTRACE_COLLECTOR_TOKEN"] = "b" * 32
            os.environ["TRUSTTRACE_VIEWER_TOKEN"] = "c" * 32
            with self.assertRaises(RuntimeError) as ctx:
                validate_token_configuration()
            self.assertIn("Insecure or weak token detected", str(ctx.exception))
        finally:
            if old_env is not None:
                os.environ["TRUSTTRACE_ENV"] = old_env
            else:
                os.environ.pop("TRUSTTRACE_ENV", None)
            for var in ["TRUSTTRACE_MODERATOR_TOKEN", "TRUSTTRACE_ADMIN_TOKEN", "TRUSTTRACE_COLLECTOR_TOKEN", "TRUSTTRACE_VIEWER_TOKEN"]:
                os.environ.pop(var, None)

    def test_empty_or_whitespace_tokens_rejected(self):
        """SEC-22: Tokens configured as empty or whitespace MUST be rejected with ValueError."""
        try:
            os.environ["TRUSTTRACE_MODERATOR_TOKEN"] = "   "
            with self.assertRaises(ValueError) as ctx:
                validate_token_configuration()
            self.assertIn("cannot be empty or whitespace", str(ctx.exception))
        finally:
            os.environ.pop("TRUSTTRACE_MODERATOR_TOKEN", None)

    def test_duplicate_tokens_across_roles_rejected(self):
        """SEC-23: Identical tokens configured across different roles MUST be rejected with ValueError."""
        try:
            os.environ["TRUSTTRACE_MODERATOR_TOKEN"] = "shared-duplicate-token-12345678"
            os.environ["TRUSTTRACE_VIEWER_TOKEN"] = "shared-duplicate-token-12345678"
            with self.assertRaises(ValueError) as ctx:
                validate_token_configuration()
            self.assertIn("Duplicate credentials error", str(ctx.exception))
        finally:
            os.environ.pop("TRUSTTRACE_MODERATOR_TOKEN", None)
            os.environ.pop("TRUSTTRACE_VIEWER_TOKEN", None)

    # --- 10. Role Escalation & Audit Authorization Tests ---

    def test_collector_role_cannot_escalate_to_moderation_or_audit(self):
        """SEC-03B: Collector role MUST NOT be allowed to perform moderation or read audits."""
        report_id = self._create_sample_report("sec-role-escalate.test")
        collector_headers = {"Authorization": "Bearer collector-secret-token-key-2026"}

        res_mod = self.client.post(
            f"/api/v1/community/reports/{report_id}/review",
            json={"target_state": "reviewed", "reason": "Collector attempting moderation"},
            headers=collector_headers,
        )
        self.assertEqual(res_mod.status_code, 403)

        res_audit = self.client.get(
            f"/api/v1/community/reports/{report_id}/audit",
            headers=collector_headers,
        )
        self.assertEqual(res_audit.status_code, 403)

    def test_audit_endpoints_require_authentication(self):
        """SEC-11: Audit endpoints MUST reject unauthenticated requests with 401."""
        res1 = self.client.get("/api/v1/community/reports/cr-any-id/audit")
        self.assertEqual(res1.status_code, 401)

        res2 = self.client.get("/api/v1/community/domain/example.test/audit")
        self.assertEqual(res2.status_code, 401)

    def test_audit_endpoints_permit_viewer_and_admin(self):
        """SEC-11B: Authenticated viewer and admin roles MUST be permitted to access audit endpoints."""
        report_id = self._create_sample_report("sec-audit-access.test")
        viewer_hdr = {"Authorization": "Bearer viewer-secret-token-key-2026"}
        admin_hdr = {"Authorization": "Bearer admin-secret-token-key-2026"}

        res_v_rep = self.client.get(f"/api/v1/community/reports/{report_id}/audit", headers=viewer_hdr)
        self.assertEqual(res_v_rep.status_code, 200)

        res_v_dom = self.client.get("/api/v1/community/domain/sec-audit-access.test/audit", headers=viewer_hdr)
        self.assertEqual(res_v_dom.status_code, 200)

        res_a_dom = self.client.get("/api/v1/community/domain/sec-audit-access.test/audit", headers=admin_hdr)
        self.assertEqual(res_a_dom.status_code, 200)

    # --- 11. Evidence Reference Integrity & Context Isolation Tests ---

    def test_community_report_with_valid_evidence_reference(self):
        """SEC-13: Community report linking existing evidence from the matching domain succeeds."""
        with self.test_db.session_scope() as session:
            self.repo.ensure_scan(session, scan_id="scan-domain-match", normalized_host="match-domain.test")
            ev = EvidenceModel(
                evidence_id="ev-valid-ref-1",
                scan_id="scan-domain-match",
                kind="dns_lookup",
                source="dns_resolver",
                observed_at="2026-11-09T10:00:00Z",
                status=EvidenceStatus.OBSERVED,
                value={"ip": "1.2.3.4"},
            )
            self.repo.save_evidence(session, "scan-domain-match", ev)

        res = self.client.post(
            "/api/v1/community/reports",
            json={
                "normalized_domain": "match-domain.test",
                "claim_type": "phishing",
                "linked_evidence_ids": ["ev-valid-ref-1"],
            },
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["data"]["report"]["linked_evidence_ids"], ["ev-valid-ref-1"])

    def test_community_report_with_nonexistent_evidence_reference_fails_and_rolls_back(self):
        """SEC-13B: Referenced evidence ID that does not exist MUST fail with 400 and roll back."""
        res = self.client.post(
            "/api/v1/community/reports",
            json={
                "normalized_domain": "missing-ev.test",
                "claim_type": "phishing",
                "linked_evidence_ids": ["ev-does-not-exist-999"],
            },
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("does not exist", res.json()["detail"])

        with self.test_db.session_scope() as session:
            reps = self.repo.find_community_reports(session, normalized_domain="missing-ev.test")
            self.assertEqual(len(reps), 0)

    def test_community_report_cross_record_evidence_context_violation_fails(self):
        """SEC-14: Cross-record injection (linking evidence from an unrelated domain) MUST be rejected."""
        with self.test_db.session_scope() as session:
            self.repo.ensure_scan(session, scan_id="scan-bank", normalized_host="legitimate-bank.test")
            ev = EvidenceModel(
                evidence_id="ev-bank-cert",
                scan_id="scan-bank",
                kind="tls_certificate",
                source="cert_inspector",
                observed_at="2026-11-09T10:00:00Z",
                status=EvidenceStatus.OBSERVED,
            )
            self.repo.save_evidence(session, "scan-bank", ev)

        res = self.client.post(
            "/api/v1/community/reports",
            json={
                "normalized_domain": "completely-unrelated-malware.test",
                "claim_type": "malware_delivery",
                "linked_evidence_ids": ["ev-bank-cert"],
            },
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("Cross-record context violation", res.json()["detail"])

    def test_community_report_duplicate_linked_evidence_ids_rejected(self):
        """SEC-15: Duplicate evidence IDs in the submission list MUST be rejected."""
        with self.test_db.session_scope() as session:
            self.repo.ensure_scan(session, scan_id="scan-dup-ev", normalized_host="dup-ev.test")
            ev = EvidenceModel(
                evidence_id="ev-dup-ref-1",
                scan_id="scan-dup-ev",
                kind="dns_lookup",
                source="dns",
                observed_at="2026-11-09T10:00:00Z",
                status=EvidenceStatus.OBSERVED,
            )
            self.repo.save_evidence(session, "scan-dup-ev", ev)

        res = self.client.post(
            "/api/v1/community/reports",
            json={
                "normalized_domain": "dup-ev.test",
                "claim_type": "phishing",
                "linked_evidence_ids": ["ev-dup-ref-1", "ev-dup-ref-1"],
            },
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("Duplicate linked evidence reference detected", res.json()["detail"])

    # --- 12. Input Validation & Abuse Resistance Tests ---

    def test_url_versus_domain_confusion_rejected(self):
        """SEC-16: URLs with schemes, paths, or query parameters submitted as domains MUST be rejected."""
        invalid_domains = [
            "https://phish.test/login?param=1",
            "http://malware.test",
            "ftp://files.test/exploit.exe",
            "phish.test/login",
            "phish.test?token=abc",
            "phish.test#frag",
            "invalid domain with spaces.test",
            "evil*domain.test",
            "",
            "   ",
        ]
        for inv in invalid_domains:
            res = self.client.post(
                "/api/v1/community/reports",
                json={"normalized_domain": inv, "claim_type": "phishing"},
            )
            self.assertIn(res.status_code, (400, 422), f"Domain '{inv}' should be rejected with 400 or 422")

    def test_oversized_evidence_payload_rejected(self):
        """SEC-17: Oversized evidence payload (>1MB) MUST be rejected with 422 or 400."""
        huge_val = {"huge_blob": "X" * (1024 * 1024 + 100)}
        payload = {
            "scan_id": "scan-oversize",
            "kind": "payload_test",
            "source": "probe",
            "status": "observed",
            "value": huge_val,
        }
        res = self.client.post("/api/v1/evidence/ingest", json=payload)
        self.assertIn(res.status_code, (400, 422))


if __name__ == "__main__":
    unittest.main()
