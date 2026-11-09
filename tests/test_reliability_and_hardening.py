"""Comprehensive Security Hardening and Reliability Verification Suite for TRUSTTRACE Worker 02."""

import os
import sys
import unittest
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock

# Ensure src is in sys.path when running standalone
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient

from trusttrace.api.app import app
from trusttrace.api.auth import (
    validate_token_configuration,
    verify_bearer_token,
    get_current_user,
    AuthenticatedUser,
)
from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.evidence.persistence.repository import EvidenceRepository
from trusttrace.evidence.services.evidence_service import EvidenceService
from trusttrace.evidence.community.service import CommunityIntelligenceService
from trusttrace.evidence.community.moderation import ModerationService
from trusttrace.evidence.community.deduplicator import SourceFamilyAnalyzer
from trusttrace.evidence.community.rate_limiter import (
    CommunityRateLimiter,
    InMemoryRateLimiterBackend,
    RedisRateLimiterBackend,
    RateLimitExceededError,
    ReplaySubmissionError,
    RateLimiterBackendError,
    default_rate_limiter,
)
from trusttrace.evidence.domain.models import EvidenceModel
from trusttrace.evidence.domain.enums import EvidenceStatus, Reliability, ClaimType, VerificationState
from trusttrace.api.routes.evidence import evidence_service, provenance_engine
from trusttrace.api.routes.community import community_service, moderation_service


class TestSecurityHardeningAndReliability(unittest.TestCase):
    """Rigorous tests covering SEC-001 through SEC-005 and REL-001 through REL-003."""

    def setUp(self):
        # Isolate in-memory SQLite database
        self.test_db = DatabaseManager("sqlite:///:memory:")
        self.repo = EvidenceRepository(db_manager=self.test_db)
        self.repo.init_tables()

        evidence_service.db = self.test_db
        evidence_service.repo = self.repo
        provenance_engine.db = self.test_db

        self.comm_service = CommunityIntelligenceService(db_manager=self.test_db, repository=self.repo)
        community_service.db = self.test_db
        community_service.repo = self.repo
        moderation_service.db = self.test_db
        moderation_service.community_service = self.comm_service

        default_rate_limiter.reset()
        self.client = TestClient(app)

    # =========================================================================
    # SEC-001: Authentication & Token Configuration Hardening
    # =========================================================================

    def test_production_mode_fails_if_tokens_missing(self):
        """SEC-001: In production mode, missing required tokens MUST raise RuntimeError."""
        old_env = os.environ.get("TRUSTTRACE_ENV")
        try:
            os.environ["TRUSTTRACE_ENV"] = "production"
            # Ensure tokens are not set
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
        """SEC-001: In production mode, insecure default tokens MUST raise RuntimeError."""
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
        """SEC-001: Tokens configured as empty or whitespace MUST be rejected with ValueError."""
        try:
            os.environ["TRUSTTRACE_MODERATOR_TOKEN"] = "   "
            with self.assertRaises(ValueError) as ctx:
                validate_token_configuration()
            self.assertIn("cannot be empty or whitespace", str(ctx.exception))
        finally:
            os.environ.pop("TRUSTTRACE_MODERATOR_TOKEN", None)

    def test_duplicate_tokens_across_roles_rejected(self):
        """SEC-001: Identical tokens configured across different roles MUST be rejected."""
        try:
            os.environ["TRUSTTRACE_MODERATOR_TOKEN"] = "shared-duplicate-token-12345678"
            os.environ["TRUSTTRACE_VIEWER_TOKEN"] = "shared-duplicate-token-12345678"
            with self.assertRaises(ValueError) as ctx:
                validate_token_configuration()
            self.assertIn("Duplicate credentials error", str(ctx.exception))
        finally:
            os.environ.pop("TRUSTTRACE_MODERATOR_TOKEN", None)
            os.environ.pop("TRUSTTRACE_VIEWER_TOKEN", None)

    def test_collector_role_cannot_escalate_to_moderation_or_audit(self):
        """SEC-001 / SEC-003: Collector role MUST NOT be allowed to perform moderation or read audits."""
        # Setup sample report
        res_sub = self.client.post(
            "/api/v1/community/reports",
            json={"normalized_domain": "sec-role-escalate.test", "claim_type": "phishing"},
        )
        report_id = res_sub.json()["data"]["report"]["report_id"]

        collector_headers = {"Authorization": "Bearer collector-secret-token-key-2026"}

        # Attempt moderation with collector token -> 403 Forbidden
        res_mod = self.client.post(
            f"/api/v1/community/reports/{report_id}/review",
            json={"target_state": "reviewed", "reason": "Collector attempting moderation"},
            headers=collector_headers,
        )
        self.assertEqual(res_mod.status_code, 403)

        # Attempt audit retrieval with collector token -> 403 Forbidden
        res_audit = self.client.get(
            f"/api/v1/community/reports/{report_id}/audit",
            headers=collector_headers,
        )
        self.assertEqual(res_audit.status_code, 403)

    # =========================================================================
    # SEC-002: Server-Controlled Source-Family Identity
    # =========================================================================

    def test_public_user_cannot_claim_any_provider_or_arbitrary_source_family(self):
        """SEC-002: Unauthenticated clients attempting to claim provider feeds or arbitrary strings MUST be rejected."""
        forbidden_families = [
            "virustotal",
            "phishtank",
            "openphish",
            "urlhaus",
            "internal_collector",
            "cert_feed",
            "arbitrary_fake_source_family",
        ]
        for family in forbidden_families:
            res = self.client.post(
                "/api/v1/community/reports",
                json={
                    "normalized_domain": f"sec-fam-{family.replace('_', '-')}.test",
                    "claim_type": "phishing",
                    "source_family": family,
                },
            )
            self.assertEqual(res.status_code, 400, f"Public claim of '{family}' should return 400")
            self.assertIn("Unauthorized source family claim", res.json()["detail"])

    def test_authenticated_collector_claiming_approved_provider_family_accepted(self):
        """SEC-002: Authenticated collector with an approved provider family is accepted."""
        headers = {"Authorization": "Bearer collector-secret-token-key-2026"}
        res = self.client.post(
            "/api/v1/community/reports",
            json={
                "normalized_domain": "sec-auth-collector.test",
                "claim_type": "phishing",
                "source_family": "openphish",
            },
            headers=headers,
        )
        self.assertEqual(res.status_code, 201)
        # Verify persistence in database with approved provider family
        with self.test_db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain="sec-auth-collector.test")
            self.assertEqual(len(reports), 1)
            self.assertEqual(reports[0].source_family, "openphish")

    def test_authenticated_collector_claiming_unknown_provider_rejected(self):
        """SEC-002: Authenticated collector attempting an unknown/unregistered provider family is rejected."""
        headers = {"Authorization": "Bearer collector-secret-token-key-2026"}
        res = self.client.post(
            "/api/v1/community/reports",
            json={
                "normalized_domain": "sec-unknown-collector.test",
                "claim_type": "phishing",
                "source_family": "completely_unknown_threat_feed",
            },
            headers=headers,
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("Unknown or unauthorized provider family", res.json()["detail"])

    # =========================================================================
    # SEC-003: Audit Endpoint Authorization
    # =========================================================================

    def test_audit_endpoints_require_authentication(self):
        """SEC-003: Both report and domain audit endpoints MUST reject unauthenticated requests with 401."""
        # 1. Report audit
        res1 = self.client.get("/api/v1/community/reports/cr-any-id/audit")
        self.assertEqual(res1.status_code, 401)
        self.assertIn("Missing authentication credentials", res1.json()["detail"])

        # 2. Domain audit
        res2 = self.client.get("/api/v1/community/domain/example.test/audit")
        self.assertEqual(res2.status_code, 401)
        self.assertIn("Missing authentication credentials", res2.json()["detail"])

    def test_audit_endpoints_permit_viewer_and_admin(self):
        """SEC-003: Authenticated viewer, moderator, and admin roles MUST be permitted to access audit endpoints."""
        # Create a report first
        res_sub = self.client.post(
            "/api/v1/community/reports",
            json={"normalized_domain": "sec-audit-access.test", "claim_type": "phishing"},
        )
        report_id = res_sub.json()["data"]["report"]["report_id"]

        viewer_hdr = {"Authorization": "Bearer viewer-secret-token-key-2026"}
        admin_hdr = {"Authorization": "Bearer admin-secret-token-key-2026"}

        # Viewer can read report audit
        res_v_rep = self.client.get(f"/api/v1/community/reports/{report_id}/audit", headers=viewer_hdr)
        self.assertEqual(res_v_rep.status_code, 200)

        # Viewer can read domain audit
        res_v_dom = self.client.get("/api/v1/community/domain/sec-audit-access.test/audit", headers=viewer_hdr)
        self.assertEqual(res_v_dom.status_code, 200)

        # Admin can read domain audit
        res_a_dom = self.client.get("/api/v1/community/domain/sec-audit-access.test/audit", headers=admin_hdr)
        self.assertEqual(res_a_dom.status_code, 200)

    # =========================================================================
    # SEC-004: Evidence Reference Integrity & Context Validation
    # =========================================================================

    def test_community_report_with_valid_evidence_reference(self):
        """SEC-004: Community report linking existing evidence from the matching domain succeeds."""
        # Seed scan and evidence
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
        rep = res.json()["data"]["report"]
        self.assertEqual(rep["linked_evidence_ids"], ["ev-valid-ref-1"])

    def test_community_report_with_nonexistent_evidence_reference_fails_and_rolls_back(self):
        """SEC-004: Referenced evidence ID that does not exist MUST fail with 400 and roll back."""
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

        # Verify atomic rollback: no report was persisted in database
        with self.test_db.session_scope() as session:
            reps = self.repo.find_community_reports(session, normalized_domain="missing-ev.test")
            self.assertEqual(len(reps), 0)

    def test_community_report_cross_record_evidence_context_violation_fails(self):
        """SEC-004: Cross-record injection (linking evidence from an unrelated domain) MUST be rejected."""
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

        # Attacker tries to attach legitimate bank evidence to malicious domain report
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
        """SEC-004: Duplicate evidence IDs in the submission list MUST be rejected."""
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

    # =========================================================================
    # SEC-005: Input Validation & Abuse Resistance
    # =========================================================================

    def test_url_versus_domain_confusion_rejected(self):
        """SEC-005: URLs with schemes, paths, or query parameters submitted as domains MUST be rejected."""
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
        """SEC-005: Oversized evidence payload (>1MB) MUST be rejected with 422 or 400."""
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

    # =========================================================================
    # REL-001: Rate Limiter Architecture & Pruning
    # =========================================================================

    def test_in_memory_rate_limiter_stale_key_pruning(self):
        """REL-001: In-memory backend MUST purge empty/stale history to prevent unbounded growth."""
        limiter = InMemoryRateLimiterBackend()
        # Add entry with past timestamp
        limiter._ip_history["old-ip"] = [100.0]
        limiter._domain_history["old-domain.test"] = [100.0]
        limiter._last_submissions[("old-ip", "old-domain.test", "phishing")] = 100.0

        # Run check_and_record for a new IP (now is current time >> 100.0)
        limiter.check_and_record(
            client_ip="current-ip",
            normalized_domain="current-domain.test",
            claim_type="phishing",
            ip_limit_per_minute=10,
            domain_limit_per_minute=5,
            replay_burst_seconds=5,
        )

        # Stale keys should have been purged from memory
        self.assertNotIn("old-ip", limiter._ip_history)
        self.assertNotIn("old-domain.test", limiter._domain_history)
        self.assertNotIn(("old-ip", "old-domain.test", "phishing"), limiter._last_submissions)

    def test_redis_rate_limiter_failure_raises_backend_error_in_production(self):
        """REL-001: Redis backend failures MUST raise RateLimiterBackendError rather than silently disabling protection."""
        backend = RedisRateLimiterBackend.__new__(RedisRateLimiterBackend)
        mock_client = MagicMock()
        mock_client.set.side_effect = Exception("Redis connection refused")
        backend.client = mock_client
        backend.redis_url = "redis://invalid:6379"

        with self.assertRaises(RateLimiterBackendError) as ctx:
            backend.check_and_record("127.0.0.1", "test.test", "phishing", 10, 5, 5)
        self.assertIn("Redis rate limiting failure", str(ctx.exception))

    # =========================================================================
    # REL-002: Concurrent Corroboration & Deduplication Integrity
    # =========================================================================

    def test_concurrent_independent_source_corroboration_consistency(self):
        """REL-002: Concurrent submissions from independent sources MUST calculate consistent corroboration count."""
        domain = "concurrency-test.test"
        collector_headers = {"Authorization": "Bearer collector-secret-token-key-2026"}

        # 3 independent sources submitted concurrently with distinct claim categories to avoid replay burst collisions
        source_claims = [
            ("openphish", "phishing"),
            ("virustotal", "impersonation"),
            ("urlhaus", "malware_delivery"),
        ]
        errors = []

        def submit_source(sf, claim):
            try:
                client = TestClient(app)
                res = client.post(
                    "/api/v1/community/reports",
                    json={
                        "normalized_domain": domain,
                        "claim_type": claim,
                        "source_family": sf,
                    },
                    headers=collector_headers,
                )
                if res.status_code != 201:
                    errors.append(f"Status {res.status_code}: {res.text}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=submit_source, args=(sf, claim)) for sf, claim in source_claims]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])

        # Verify in database: all reports for this domain MUST agree on the final independent source count (3)
        with self.test_db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), 3)
            counts = {r.independent_source_count for r in reports}
            self.assertEqual(counts, {3}, "All sibling reports must have identical corroboration count of 3")

    # =========================================================================
    # REL-003: Database Migrations
    # =========================================================================

    def test_alembic_clean_database_upgrade_and_downgrade(self):
        """REL-003: Alembic migration MUST upgrade a clean database to HEAD and downgrade to base cleanly."""
        from alembic.config import Config
        from alembic import command
        from sqlalchemy import inspect

        with tempfile.TemporaryDirectory() as tmp_dir:
            test_db_path = os.path.join(tmp_dir, "mig_test.db")
            db_url = f"sqlite:///{test_db_path}"

            alembic_cfg = Config("alembic.ini")
            alembic_cfg.set_main_option("sqlalchemy.url", db_url)

            # 1. Run upgrade to head
            command.upgrade(alembic_cfg, "head")

            # Verify tables and composite index
            engine = DatabaseManager(db_url).engine
            inspector = inspect(engine)
            tables = set(inspector.get_table_names())
            expected_tables = {
                "scans",
                "evidence_records",
                "findings",
                "finding_evidence_links",
                "community_reports",
                "community_report_evidence_links",
                "community_report_audit_events",
            }
            self.assertTrue(expected_tables.issubset(tables), f"Missing tables in {tables}")

            # Verify composite unique index on evidence_records
            ev_indexes = inspector.get_indexes("evidence_records")
            uq_idx = [idx for idx in ev_indexes if idx["name"] == "uq_evidence_scan_fingerprint"]
            self.assertEqual(len(uq_idx), 1)
            self.assertTrue(uq_idx[0]["unique"])
            self.assertEqual(uq_idx[0]["column_names"], ["scan_id", "fingerprint"])

            # 2. Run downgrade to base
            command.downgrade(alembic_cfg, "base")
            downgraded_tables = set(inspect(engine).get_table_names())
            self.assertFalse(expected_tables.intersection(downgraded_tables))

            # Dispose engine connection pool to release SQLite file lock on Windows
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
