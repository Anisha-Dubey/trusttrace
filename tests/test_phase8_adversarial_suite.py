"""Comprehensive Phase 8 Adversarial Regression Test Suite for TRUSTTRACE Worker 02.

Covers all 14 required adversarial and concurrency test specifications:
1. Production startup with missing secrets.
2. Production startup with insecure secrets.
3. Production startup without Redis.
4. Redis connection failure.
5. Concurrent Redis submissions at the rate limit boundary.
6. Replay and rate limit atomicity.
7. Collector attempting another provider's identity.
8. Public user attempting provider impersonation.
9. Concurrent submissions from the same source family.
10. Concurrent submissions from independent source families.
11. Concurrent first submissions for one domain.
12. Migration from clean database.
13. ORM/migration schema consistency.
14. Worker 01 contract regression.
"""

import os
import sys
import json
import time
import uuid
import unittest
import threading
import ast
from pathlib import Path
from typing import Dict, Any, List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from jsonschema import Draft202012Validator, FormatChecker

import fakeredis
from trusttrace.api.app import create_app
from trusttrace.api.auth import validate_token_configuration, DEV_TEST_TOKENS
from trusttrace.evidence.community.rate_limiter import (
    RedisRateLimiterBackend,
    RateLimiterBackendError,
    RateLimitExceededError,
    ReplaySubmissionError,
    CommunityRateLimiter,
)
from trusttrace.evidence.persistence.database import DatabaseManager, Base
from trusttrace.evidence.persistence.repository import EvidenceRepository
from trusttrace.evidence.community.service import CommunityIntelligenceService
from trusttrace.evidence.community.moderation import ModerationService
from trusttrace.evidence.services.evidence_service import EvidenceService
from trusttrace.evidence.domain.models import EvidenceModel
from trusttrace.evidence.domain.enums import EvidenceStatus, Reliability, VerificationState, ClaimType
from trusttrace.intake.boundary import IntakeBoundary


class TestPhase8AdversarialRegressionSuite(unittest.TestCase):
    """Phase 8 Adversarial and Concurrency Verification Suite."""

    def setUp(self):
        self.clean_db_path = ROOT / f"test_adv_{uuid.uuid4().hex[:8]}.db"
        self.db = DatabaseManager(f"sqlite:///{self.clean_db_path}")
        self.db.init_db()
        self.repo = EvidenceRepository(db_manager=self.db)
        self.service = CommunityIntelligenceService(db_manager=self.db, repository=self.repo)

    def tearDown(self):
        self.db.engine.dispose()
        if self.clean_db_path.exists():
            try:
                self.clean_db_path.unlink()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 1. Production startup with missing secrets
    # -------------------------------------------------------------------------
    def test_01_production_startup_missing_secrets(self):
        """SEC-ADV-01: Production mode with missing required secrets fails startup."""
        saved_env = os.environ.copy()
        try:
            os.environ["TRUSTTRACE_ENV"] = "production"
            for k in [
                "TRUSTTRACE_MODERATOR_TOKEN",
                "TRUSTTRACE_ADMIN_TOKEN",
                "TRUSTTRACE_COLLECTOR_TOKEN",
                "TRUSTTRACE_VIEWER_TOKEN",
            ]:
                os.environ.pop(k, None)

            with self.assertRaises(RuntimeError) as ctx:
                validate_token_configuration()
            self.assertIn("Missing required authentication token", str(ctx.exception))
        finally:
            os.environ.clear()
            os.environ.update(saved_env)

    # -------------------------------------------------------------------------
    # 2. Production startup with insecure secrets
    # -------------------------------------------------------------------------
    def test_02_production_startup_insecure_secrets(self):
        """SEC-ADV-02: Production mode with weak or default secrets fails startup."""
        saved_env = os.environ.copy()
        try:
            os.environ["TRUSTTRACE_ENV"] = "production"
            # Set default/insecure token
            os.environ["TRUSTTRACE_MODERATOR_TOKEN"] = "mod-secret-token-key-2026"
            os.environ["TRUSTTRACE_ADMIN_TOKEN"] = "admin-" + "x" * 32
            os.environ["TRUSTTRACE_COLLECTOR_TOKEN"] = "collector-" + "y" * 32
            os.environ["TRUSTTRACE_VIEWER_TOKEN"] = "viewer-" + "z" * 32

            with self.assertRaises(RuntimeError) as ctx:
                validate_token_configuration()
            self.assertIn("Insecure or weak token detected", str(ctx.exception))
        finally:
            os.environ.clear()
            os.environ.update(saved_env)

    # -------------------------------------------------------------------------
    # 3. Production startup without Redis
    # -------------------------------------------------------------------------
    def test_03_production_startup_without_redis(self):
        """SEC-ADV-03: Production mode without Redis fails closed."""
        saved_env = os.environ.copy()
        try:
            os.environ["TRUSTTRACE_ENV"] = "production"
            os.environ.pop("TRUSTTRACE_REDIS_URL", None)
            os.environ.pop("REDIS_URL", None)

            from trusttrace.evidence.community.rate_limiter import get_default_backend

            with self.assertRaises(RateLimiterBackendError) as ctx:
                get_default_backend()
            self.assertIn("Redis is strictly required in production mode", str(ctx.exception))
        finally:
            os.environ.clear()
            os.environ.update(saved_env)

    # -------------------------------------------------------------------------
    # 4. Redis connection failure
    # -------------------------------------------------------------------------
    def test_04_redis_connection_failure(self):
        """SEC-ADV-04: Redis connection failure raises RateLimiterBackendError (fails closed)."""
        backend = RedisRateLimiterBackend(redis_url="redis://127.0.0.1:59999/0")
        with self.assertRaises(RateLimiterBackendError) as ctx:
            backend.ping()
        self.assertIn("Redis ping failure", str(ctx.exception))

        with self.assertRaises(RateLimiterBackendError):
            backend.check_and_record(
                client_ip="1.2.3.4",
                normalized_domain="example.com",
                claim_type="phishing",
                ip_limit_per_minute=10,
                domain_limit_per_minute=5,
                replay_burst_seconds=5,
            )

    # -------------------------------------------------------------------------
    # 5. Concurrent Redis submissions at the rate limit boundary
    # -------------------------------------------------------------------------
    def test_05_concurrent_redis_submissions_at_rate_boundary(self):
        """SEC-ADV-05: Concurrent requests at boundary are metered atomically without race condition."""
        fake_server = fakeredis.FakeServer()
        fake_client = fakeredis.FakeRedis(server=fake_server, decode_responses=True)

        backend = RedisRateLimiterBackend.__new__(RedisRateLimiterBackend)
        backend.redis_url = "mock://redis"
        backend.client = fake_client
        from trusttrace.evidence.community.rate_limiter import ATOMIC_RATE_LIMIT_LUA
        backend._script = fake_client.register_script(ATOMIC_RATE_LIMIT_LUA)

        ip_limit = 5
        domain_limit = 10
        burst_sec = 1
        client_ip = "192.168.1.50"

        success_count = 0
        limit_count = 0
        lock = threading.Lock()

        def submit_attempt(idx: int):
            nonlocal success_count, limit_count
            try:
                backend.check_and_record(
                    client_ip=client_ip,
                    normalized_domain=f"domain-{idx}.test",
                    claim_type="phishing",
                    ip_limit_per_minute=ip_limit,
                    domain_limit_per_minute=domain_limit,
                    replay_burst_seconds=burst_sec,
                )
                with lock:
                    success_count += 1
            except RateLimitExceededError:
                with lock:
                    limit_count += 1
            except Exception as e:
                pass

        threads = [threading.Thread(target=submit_attempt, args=(i,)) for i in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(success_count, ip_limit, f"Exactly {ip_limit} requests should pass boundary")
        self.assertEqual(limit_count, 12 - ip_limit, f"Remaining {12 - ip_limit} requests should be throttled")

    # -------------------------------------------------------------------------
    # 6. Replay and rate limit atomicity
    # -------------------------------------------------------------------------
    def test_06_replay_and_rate_limit_atomicity(self):
        """SEC-ADV-06: Rejected requests must NOT contaminate rate count or set replay key."""
        fake_server = fakeredis.FakeServer()
        fake_client = fakeredis.FakeRedis(server=fake_server, decode_responses=True)

        backend = RedisRateLimiterBackend.__new__(RedisRateLimiterBackend)
        backend.redis_url = "mock://redis"
        backend.client = fake_client
        from trusttrace.evidence.community.rate_limiter import ATOMIC_RATE_LIMIT_LUA
        backend._script = fake_client.register_script(ATOMIC_RATE_LIMIT_LUA)

        # 1. Exhaust domain limit with domain_limit=1
        backend.check_and_record(
            client_ip="10.0.0.1",
            normalized_domain="atomic-test.test",
            claim_type="malicious",
            ip_limit_per_minute=10,
            domain_limit_per_minute=1,
            replay_burst_seconds=5,
        )

        # 2. Second request from a different IP should be rejected by domain limit
        with self.assertRaises(RateLimitExceededError):
            backend.check_and_record(
                client_ip="10.0.0.2",
                normalized_domain="atomic-test.test",
                claim_type="phishing",
                ip_limit_per_minute=10,
                domain_limit_per_minute=1,
                replay_burst_seconds=5,
            )

        # 3. Verify that 10.0.0.2 was NOT added to IP key and replay key was NOT set
        self.assertEqual(fake_client.zcard("rate:ip:10.0.0.2"), 0)
        self.assertIsNone(fake_client.get("rate:replay:10.0.0.2:atomic-test.test:phishing"))

    # -------------------------------------------------------------------------
    # 7. Collector attempting another provider's identity
    # -------------------------------------------------------------------------
    def test_07_collector_attempting_another_provider_identity(self):
        """SEC-ADV-07: Principal authorized for phishtank CANNOT impersonate openphish."""
        app = create_app()
        client = TestClient(app)

        # phishtank provider token is authorized for phishtank ONLY
        headers = {"Authorization": "Bearer phishtank-secret-token-key-2026"}
        res = client.post(
            "/api/v1/community/reports",
            json={
                "normalized_domain": "provider-cross.test",
                "claim_type": "phishing",
                "source_family": "openphish",  # Cross-provider impersonation attempt!
            },
            headers=headers,
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn("not authorized to submit reports on behalf of source family 'openphish'", res.json()["detail"])

    # -------------------------------------------------------------------------
    # 8. Public user attempting provider impersonation
    # -------------------------------------------------------------------------
    def test_08_public_user_attempting_provider_impersonation(self):
        """SEC-ADV-08: Public unauthenticated submissions claiming provider families are rejected."""
        app = create_app()
        client = TestClient(app)

        for provider in ["phishtank", "openphish", "urlhaus", "virustotal", "cert_feed"]:
            clean_dom_prefix = provider.replace("_", "-")
            res = client.post(
                "/api/v1/community/reports",
                json={
                    "normalized_domain": f"public-spoof-{clean_dom_prefix}.test",
                    "claim_type": "phishing",
                    "source_family": provider,
                },
            )
            self.assertEqual(res.status_code, 400, f"Public claim of '{provider}' should return 400")
            self.assertIn("Unauthorized source family claim", res.json()["detail"])

    # -------------------------------------------------------------------------
    # 9. Concurrent submissions from the same source family
    # -------------------------------------------------------------------------
    def test_09_concurrent_submissions_same_source_family(self):
        """SEC-ADV-09: Concurrent submissions from identical source family never inflate count beyond 1."""
        domain = "concurr-same-fam.test"
        errors = []

        def worker(w_id: int):
            try:
                self.service.submit_report(
                    normalized_domain=domain,
                    claim_type="phishing",
                    note=f"Report from worker {w_id}",
                    raw_reporter_identifier=f"worker-ip-{w_id}",
                    source_family="phishtank",
                    is_authenticated_provider=True,
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Workers encountered errors: {errors}")

        # Authoritative independent count MUST strictly be 1
        reports = self.service.list_reports_for_domain(domain)
        self.assertGreater(len(reports), 0)
        for r in reports:
            self.assertEqual(r.independent_source_count, 1, "Same source family must not increment count beyond 1")

    # -------------------------------------------------------------------------
    # 10. Concurrent submissions from independent source families
    # -------------------------------------------------------------------------
    def test_10_concurrent_submissions_independent_source_families(self):
        """SEC-ADV-10: Concurrent submissions from independent source families count correctly."""
        domain = "concurr-indep-fam.test"
        families = ["phishtank", "urlhaus", "openphish"]
        errors = []

        def worker(fam: str, idx: int):
            try:
                self.service.submit_report(
                    normalized_domain=domain,
                    claim_type="phishing",
                    note=f"Report from family {fam}",
                    raw_reporter_identifier=f"indep-ip-{idx}",
                    source_family=fam,
                    is_authenticated_provider=True,
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f, i)) for i, f in enumerate(families)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Workers encountered errors: {errors}")

        reports = self.service.list_reports_for_domain(domain)
        self.assertEqual(len(reports), 3)
        for r in reports:
            self.assertEqual(r.independent_source_count, 3, "Distinct source families must increment count to 3")

    # -------------------------------------------------------------------------
    # 11. Concurrent first submissions for one domain
    # -------------------------------------------------------------------------
    def test_11_concurrent_first_submissions_for_one_domain(self):
        """SEC-ADV-11: Concurrent initial submissions for brand-new domain execute without collision."""
        domain = f"fresh-brand-new-{uuid.uuid4().hex[:6]}.test"
        errors = []

        def submit_first(w_id: int):
            try:
                self.service.submit_report(
                    normalized_domain=domain,
                    claim_type="phishing",
                    note=f"First race report {w_id}",
                    raw_reporter_identifier=f"fresh-rep-{w_id}",
                    source_family="community_user",
                    is_authenticated_provider=False,
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=submit_first, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors on concurrent first submission: {errors}")
        reports = self.service.list_reports_for_domain(domain)
        self.assertGreater(len(reports), 0)

    # -------------------------------------------------------------------------
    # 12. Migration from clean database
    # -------------------------------------------------------------------------
    def test_12_migration_from_clean_database(self):
        """SEC-ADV-12: Alembic migration executes upgrade and downgrade on clean database."""
        test_db_file = ROOT / f"clean_alembic_test_{uuid.uuid4().hex[:6]}.db"
        saved_env = os.environ.copy()
        try:
            os.environ["TRUSTTRACE_DB_URL"] = f"sqlite:///{test_db_file}"
            import subprocess

            # Upgrade to head
            res = subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                timeout=30,
            )
            self.assertEqual(res.returncode, 0, f"Alembic upgrade head failed: {res.stderr}")

            # Verify head revision
            res_curr = subprocess.run(
                [sys.executable, "-m", "alembic", "current"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                timeout=30,
            )
            self.assertIn("9b3f11e2a05d", res_curr.stdout)

            # Downgrade 1 revision
            res_down = subprocess.run(
                [sys.executable, "-m", "alembic", "downgrade", "-1"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                timeout=30,
            )
            self.assertEqual(res_down.returncode, 0, f"Alembic downgrade -1 failed: {res_down.stderr}")

            # Re-upgrade to head
            res_up = subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                timeout=30,
            )
            self.assertEqual(res_up.returncode, 0, f"Alembic re-upgrade failed: {res_up.stderr}")
        finally:
            os.environ.clear()
            os.environ.update(saved_env)
            if test_db_file.exists():
                try:
                    test_db_file.unlink()
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # 13. ORM/migration schema consistency
    # -------------------------------------------------------------------------
    def test_13_orm_migration_schema_consistency(self):
        """SEC-ADV-13: Verifies all tables and unique constraints in ORM models exist in migrated schema."""
        test_db_file = ROOT / f"schema_check_{uuid.uuid4().hex[:6]}.db"
        saved_env = os.environ.copy()
        try:
            os.environ["TRUSTTRACE_DB_URL"] = f"sqlite:///{test_db_file}"
            import subprocess
            subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                capture_output=True,
                check=True,
                cwd=str(ROOT),
                timeout=30,
            )

            engine = create_engine(f"sqlite:///{test_db_file}")
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
                "community_domain_source_families",
                "community_domain_coordination",
            }
            self.assertTrue(expected_tables.issubset(tables), f"Missing tables: {expected_tables - tables}")

            # Verify unique constraint / index on evidence fingerprint
            ev_indexes = inspector.get_indexes("evidence_records")
            fp_indexes = [ix for ix in ev_indexes if "fingerprint" in ix["column_names"]]
            self.assertTrue(any(ix.get("unique") for ix in fp_indexes), "Evidence fingerprint index must be UNIQUE")

            engine.dispose()
        finally:
            os.environ.clear()
            os.environ.update(saved_env)
            if test_db_file.exists():
                try:
                    test_db_file.unlink()
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # 14. Worker 01 contract regression
    # -------------------------------------------------------------------------
    def test_14_worker_01_contract_regression(self):
        """SEC-ADV-14: Intake boundary regression and schema validity check."""
        boundary = IntakeBoundary()
        schemas_dir = ROOT / ".brain/.work/contracts/v1"
        report_schema = json.loads((schemas_dir / "scan_report.schema.json").read_text(encoding="utf-8"))
        validator = Draft202012Validator(report_schema, format_checker=FormatChecker())

        test_cases = [
            ("http://127.0.0.1:8080/admin", "loopback_target"),
            ("https://user:password@malicious-site.com/login", "credentials_in_url"),
            ("file:///etc/passwd", "unsupported_scheme"),
            ("http://169.254.169.254/latest/meta-data/", "cloud_metadata_target"),
        ]

        for url, reason in test_cases:
            eval_res = boundary.evaluate_target(url)
            self.assertFalse(eval_res.is_safe, f"{url} must be rejected")
            report = boundary.build_rejected_report(scan_id=f"adv-{reason}", evaluation=eval_res)
            errors = list(validator.iter_errors(report))
            self.assertEqual(len(errors), 0, f"Rejected report failed contract schema validation: {errors}")

    # -------------------------------------------------------------------------
    # 15. Concurrent duplicate evidence ingestion
    # -------------------------------------------------------------------------
    def test_15_concurrent_duplicate_evidence_ingestion(self):
        """SEC-ADV-15: Concurrent duplicate evidence ingestion creates exactly 1 record without crashing."""
        from trusttrace.evidence.adapters.base import EvidenceBatch
        ev_service = EvidenceService(db_manager=self.db, repository=self.repo)
        scan_id = f"scan-concurrent-{uuid.uuid4().hex[:6]}"
        ev_id = f"ev-{uuid.uuid4().hex[:8]}"
        now = "2026-11-10T00:00:00Z"

        evidence = EvidenceModel(
            evidence_id=ev_id,
            scan_id=scan_id,
            kind="dns_lookup",
            value={"resolved_ip": "1.2.3.4"},
            source="worker01_dns",
            source_type="internal_collector",
            observed_at=now,
            status=EvidenceStatus.OBSERVED,
            reliability=Reliability.DIRECT_OBSERVATION,
            limitations=[],
            schema_version="1.0",
        )
        batch = EvidenceBatch(scan_id=scan_id, items=[evidence])

        results = []
        errors = []

        def worker():
            try:
                res = ev_service.ingest_batch(batch)
                results.append(res)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent ingestion encountered errors: {errors}")
        with self.db.session_scope() as session:
            records = self.repo.get_evidence_by_scan(session, scan_id=scan_id)
            self.assertEqual(len(records), 1, "Exactly one evidence record should exist after concurrent duplicate ingestion")

    # -------------------------------------------------------------------------
    # 16. Concurrent moderation state changes
    # -------------------------------------------------------------------------
    def test_16_concurrent_moderation_state_transitions(self):
        """SEC-ADV-16: Concurrent moderation reviews on a report maintain consistent terminal state and audit trail."""
        comm_service = CommunityIntelligenceService(db_manager=self.db, repository=self.repo)
        mod_service = ModerationService(community_service=comm_service, db_manager=self.db)
        domain = f"mod-target-{uuid.uuid4().hex[:6]}.com"
        report, _ = comm_service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            note="Initial report",
            raw_reporter_identifier="192.168.1.1",
        )

        outcomes = []

        def mod_worker(idx):
            try:
                updated = mod_service.review_report(
                    report_id=report.report_id,
                    target_state=VerificationState.REVIEWED,
                    reason=f"Concurrent review by moderator {idx}",
                    moderator_ref=f"moderator_{idx}",
                )
                outcomes.append(("ok", updated))
            except Exception as e:
                outcomes.append(("err", e))

        threads = [threading.Thread(target=mod_worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [o for o in outcomes if o[0] == "ok"]
        self.assertGreaterEqual(len(successes), 1)
        final_report = comm_service.get_report(report.report_id)
        self.assertIsNotNone(final_report)
        self.assertEqual(final_report.verification_state, VerificationState.REVIEWED)

        audit_trail = mod_service.get_audit_trail(report.report_id)
        self.assertGreaterEqual(len(audit_trail), 2)  # Initial submission + at least 1 moderation action

    # -------------------------------------------------------------------------
    # 17. Client cannot fabricate independent corroboration count
    # -------------------------------------------------------------------------
    def test_17_client_cannot_fabricate_independent_count(self):
        """SEC-ADV-17: Client-supplied independent count overrides or fake counts in API requests are strictly ignored."""
        client = TestClient(create_app())
        domain = f"spoofed-count-{uuid.uuid4().hex[:6]}.com"

        resp = client.post(
            "/api/v1/community/reports",
            json={
                "normalized_domain": domain,
                "claim_type": "phishing",
                "note": "Malicious site",
                "independent_source_count": 999,
                "independent_count_override": 500,
            },
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()["data"]["report"]
        self.assertEqual(data["independent_source_count"], 1, "Server must compute count, ignoring client payload overrides")

    # -------------------------------------------------------------------------
    # 18. Worker 02 isolation — no Worker 01 networking or raw socket imports
    # -------------------------------------------------------------------------
    def test_18_worker02_isolation_no_worker01_network_imports(self):
        """SEC-ADV-18: Worker 02 modules never import Worker 01 networking or raw socket/request libraries."""
        prohibited_modules = {
            "socket",
            "urllib",
            "urllib.request",
            "requests",
            "httpx",
            "aiohttp",
            "trusttrace.intake.dns_resolver",
            "trusttrace.intake.ip_classifier",
            "trusttrace.intake.redirect_policy",
        }

        evidence_dir = ROOT / "src" / "trusttrace" / "evidence"
        for py_file in evidence_dir.rglob("*.py"):
            code = py_file.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for prohibited in prohibited_modules:
                            self.assertFalse(
                                alias.name == prohibited or alias.name.startswith(prohibited + "."),
                                f"Worker 02 file {py_file.name} violates isolation by importing {alias.name}",
                            )
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    for prohibited in prohibited_modules:
                        self.assertFalse(
                            mod == prohibited or mod.startswith(prohibited + "."),
                            f"Worker 02 file {py_file.name} violates isolation by importing from {mod}",
                        )


if __name__ == "__main__":
    unittest.main()
