"""Focused Negative Security Audit Test Suite for TRUSTTRACE Worker 02."""

import unittest
import os
from fastapi.testclient import TestClient

from trusttrace.api.app import app, get_cors_configuration
from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.api.routes.evidence import evidence_service, provenance_engine
from trusttrace.api.routes.community import community_service, moderation_service
from trusttrace.evidence.community.rate_limiter import default_rate_limiter
from trusttrace.evidence.community.sanitizer import get_reporter_salt


class TestSecurityAudit(unittest.TestCase):
    """Rigorous negative tests verifying all 7 security remediation gates."""

    def setUp(self):
        # Fresh isolated DB
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

        default_rate_limiter.reset()
        self.client = TestClient(app)

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


if __name__ == "__main__":
    unittest.main()
