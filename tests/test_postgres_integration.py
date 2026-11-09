"""PostgreSQL Integration, Concurrency, and Migration Verification Suite.

Executes directly against a live PostgreSQL 15 instance to verify:
1. Migration upgrade/downgrade/re-upgrade lifecycle.
2. PostgreSQL schema, foreign keys, unique indexes, and constraints.
3. Multi-thread and multi-process domain coordination concurrency.
4. Evidence uniqueness and transactional rollback behavior.
5. Concurrent moderation state changes and audit logging.
"""

import os
import sys
import json
import uuid
import unittest
import threading
import subprocess
from pathlib import Path
from typing import Dict, Any, List
from concurrent.futures import ProcessPoolExecutor

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from sqlalchemy import inspect, text, select
from trusttrace.evidence.persistence.database import DatabaseManager, sanitize_db_url
from trusttrace.evidence.persistence.repository import EvidenceRepository
from trusttrace.evidence.persistence.models import (
    CommunityReportEntity,
    CommunityDomainSourceFamilyEntity,
    CommunityDomainCoordinationEntity,
    EvidenceEntity,
    ReportAuditEntity,
)
from trusttrace.evidence.community.service import CommunityIntelligenceService
from trusttrace.evidence.community.moderation import ModerationService
from trusttrace.evidence.services.evidence_service import EvidenceService
from trusttrace.evidence.domain.models import EvidenceModel
from trusttrace.evidence.domain.enums import EvidenceStatus, Reliability, VerificationState, ClaimType
from trusttrace.evidence.adapters.base import EvidenceBatch


def _multiprocess_submit_worker(pg_url: str, domain: str, family: str, reporter_id: str) -> Dict[str, Any]:
    """Independent worker executed in a separate OS process."""
    db = DatabaseManager(pg_url, fail_fast=True)
    repo = EvidenceRepository(db)
    service = CommunityIntelligenceService(db_manager=db, repository=repo)
    is_prov = family != "community_user"
    perm_families = {family} if is_prov else None

    report, dedup = service.submit_report(
        normalized_domain=domain,
        claim_type="phishing",
        note="Multiprocess test",
        raw_reporter_identifier=reporter_id,
        source_family=family,
        is_authenticated_provider=is_prov,
        permitted_families=perm_families,
    )
    return {
        "report_id": report.report_id,
        "independent_source_count": report.independent_source_count,
        "category": dedup.category.value,
    }


class TestPostgresIntegration(unittest.TestCase):
    """Real PostgreSQL 15 integration and concurrency verification suite."""

    pg_url: str = ""
    db: DatabaseManager = None  # type: ignore

    @classmethod
    def setUpClass(cls):
        pg_url = os.environ.get("TRUSTTRACE_PG_URL") or os.environ.get("TRUSTTRACE_DB_URL")
        if not pg_url or "postgres" not in pg_url:
            raise unittest.SkipTest(
                "TRUSTTRACE_PG_URL not configured. "
                "Real PostgreSQL integration tests require a live PostgreSQL 15 database service."
            )
        cls.pg_url = pg_url
        cls.db = DatabaseManager(pg_url, fail_fast=True)
        dialect = cls.db.get_dialect_name()
        if dialect != "postgresql":
            raise AssertionError(f"PostgreSQL integration tests must use PostgreSQL, got dialect: {dialect}")
        print(f"\n[PostgreSQL Integration] Connected to {cls.db.get_sanitized_url()} (Dialect: {dialect})")

    def setUp(self):
        self.repo = EvidenceRepository(self.db)
        self.comm_service = CommunityIntelligenceService(db_manager=self.db, repository=self.repo)
        self.ev_service = EvidenceService(db_manager=self.db, repository=self.repo)
        self.mod_service = ModerationService(community_service=self.comm_service, db_manager=self.db)

    # =========================================================================
    # PART 1: Migration Verification on PostgreSQL
    # =========================================================================

    def test_01_postgres_empty_db_to_alembic_head(self):
        """PG-MIG-01: Empty PostgreSQL database migrates cleanly to Alembic HEAD."""
        env = os.environ.copy()
        env["TRUSTTRACE_DB_URL"] = self.pg_url
        env["TRUSTTRACE_PG_URL"] = self.pg_url

        # Upgrade to head
        res = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res.returncode, 0, f"Alembic upgrade head failed on PostgreSQL:\n{res.stderr}")

        # Verify current revision
        res_cur = subprocess.run(
            [sys.executable, "-m", "alembic", "current"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res_cur.returncode, 0)
        self.assertIn("head", res_cur.stdout.lower())

    def test_02_postgres_migration_downgrade_to_base_and_reupgrade(self):
        """PG-MIG-02: PostgreSQL schema cleanly downgrades to base and re-upgrades to head."""
        env = os.environ.copy()
        env["TRUSTTRACE_DB_URL"] = self.pg_url
        env["TRUSTTRACE_PG_URL"] = self.pg_url

        # Downgrade to base
        res_down = subprocess.run(
            [sys.executable, "-m", "alembic", "downgrade", "base"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res_down.returncode, 0, f"Alembic downgrade base failed:\n{res_down.stderr}")

        # Re-upgrade to head
        res_up = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res_up.returncode, 0, f"Alembic re-upgrade to head failed:\n{res_up.stderr}")

    def test_03_postgres_schema_and_constraints_verification(self):
        """PG-MIG-03: PostgreSQL schema contains all tables, indexes, and unique constraints."""
        inspector = inspect(self.db.engine)
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
        self.assertTrue(expected_tables.issubset(tables), f"Missing tables in PostgreSQL: {expected_tables - tables}")

        # Unique index on evidence_records.fingerprint
        indexes = inspector.get_indexes("evidence_records")
        fp_indexes = [ix for ix in indexes if "fingerprint" in ix.get("column_names", [])]
        self.assertTrue(any(ix.get("unique") for ix in fp_indexes), "Evidence fingerprint index must be UNIQUE in Postgres")

        # Unique constraint on community_domain_source_families (normalized_domain, source_family)
        uqs = inspector.get_unique_constraints("community_domain_source_families")
        has_uq = any(set(uq.get("column_names", [])) == {"normalized_domain", "source_family"} for uq in uqs)
        self.assertTrue(has_uq, "community_domain_source_families must have UniqueConstraint('normalized_domain', 'source_family')")

        # Foreign keys exist on audit events and links
        fks = inspector.get_foreign_keys("community_report_audit_events")
        self.assertTrue(any(fk.get("referred_table") == "community_reports" for fk in fks))

    # =========================================================================
    # PART 2: Domain Coordination Concurrency on PostgreSQL
    # =========================================================================

    def test_04_postgres_concurrent_first_submissions_new_domain(self):
        """PG-CONC-01: Concurrent first submissions for unseen domain maintain atomic count 1."""
        domain = f"pg-first-{uuid.uuid4().hex[:8]}.com"
        concurrency = 8
        barrier = threading.Barrier(concurrency)
        results = []
        errors = []

        def worker(idx):
            try:
                # Each worker uses an independent session and repository
                repo = EvidenceRepository(self.db)
                service = CommunityIntelligenceService(db_manager=self.db, repository=repo)
                barrier.wait(timeout=10)
                rep, dedup = service.submit_report(
                    normalized_domain=domain,
                    claim_type="phishing",
                    note=f"First probe {idx}",
                    raw_reporter_identifier=f"user_{idx}",
                )
                results.append((rep, dedup))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Encountered concurrency errors in Postgres: {errors}")
        self.assertEqual(len(results), concurrency)

        # Assert final database state in PostgreSQL
        with self.db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), concurrency)
            # All reports must authoritatively have independent_source_count == 1
            for r in reports:
                self.assertEqual(r.independent_source_count, 1)

            # Exactly 1 record in domain source families junction
            families = session.execute(
                select(CommunityDomainSourceFamilyEntity).where(
                    CommunityDomainSourceFamilyEntity.normalized_domain == domain
                )
            ).scalars().all()
            self.assertEqual(len(families), 1)
            self.assertEqual(families[0].source_family, "community_user")

            # Coordination record exists and is not disputed
            coord = session.get(CommunityDomainCoordinationEntity, domain)
            self.assertIsNotNone(coord)
            self.assertFalse(coord.is_disputed)

    def test_05_postgres_concurrent_same_source_family(self):
        """PG-CONC-02: Concurrent submissions from same source family never inflate count beyond 1."""
        domain = f"pg-same-family-{uuid.uuid4().hex[:8]}.com"
        concurrency = 6
        barrier = threading.Barrier(concurrency)
        errors = []

        def worker(idx):
            try:
                repo = EvidenceRepository(self.db)
                service = CommunityIntelligenceService(db_manager=self.db, repository=repo)
                barrier.wait(timeout=10)
                service.submit_report(
                    normalized_domain=domain,
                    claim_type="phishing",
                    note=f"Feed feed probe {idx}",
                    raw_reporter_identifier=f"collector_{idx}",
                    source_family="phishtank",
                    is_authenticated_provider=True,
                    permitted_families={"phishtank"},
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Encountered errors: {errors}")

        with self.db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), concurrency)
            for r in reports:
                self.assertEqual(r.independent_source_count, 1)

            family_records = session.execute(
                select(CommunityDomainSourceFamilyEntity).where(
                    CommunityDomainSourceFamilyEntity.normalized_domain == domain
                )
            ).scalars().all()
            self.assertEqual(len(family_records), 1)
            self.assertEqual(family_records[0].source_family, "phishtank")

    def test_06_postgres_concurrent_independent_source_families(self):
        """PG-CONC-03: Concurrent submissions from distinct source families count correctly to 4."""
        domain = f"pg-distinct-families-{uuid.uuid4().hex[:8]}.com"
        families = ["phishtank", "urlhaus", "openphish", "cert_feed"]
        barrier = threading.Barrier(len(families))
        errors = []

        def worker(family_name):
            try:
                repo = EvidenceRepository(self.db)
                service = CommunityIntelligenceService(db_manager=self.db, repository=repo)
                barrier.wait(timeout=10)
                service.submit_report(
                    normalized_domain=domain,
                    claim_type="phishing",
                    note=f"Report from {family_name}",
                    raw_reporter_identifier=f"agent_{family_name}",
                    source_family=family_name,
                    is_authenticated_provider=True,
                    permitted_families={family_name},
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f,)) for f in families]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Encountered errors: {errors}")

        # Assert final database state: all 4 families registered and count is 4
        with self.db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), 4)
            for r in reports:
                self.assertEqual(r.independent_source_count, 4)

            family_records = session.execute(
                select(CommunityDomainSourceFamilyEntity).where(
                    CommunityDomainSourceFamilyEntity.normalized_domain == domain
                )
            ).scalars().all()
            self.assertEqual(len(family_records), 4)
            registered = {f.source_family for f in family_records}
            self.assertEqual(registered, set(families))

    def test_07_postgres_conflicting_claims_disputed_consistency(self):
        """PG-CONC-04: Concurrent conflicting claims consistently transition domain to disputed."""
        domain = f"pg-dispute-{uuid.uuid4().hex[:8]}.com"
        barrier = threading.Barrier(2)
        errors = []

        def worker(claim_str, user_id):
            try:
                repo = EvidenceRepository(self.db)
                service = CommunityIntelligenceService(db_manager=self.db, repository=repo)
                barrier.wait(timeout=10)
                service.submit_report(
                    normalized_domain=domain,
                    claim_type=claim_str,
                    note=f"Claim {claim_str}",
                    raw_reporter_identifier=user_id,
                )
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker, args=("phishing", "reporter_a"))
        t2 = threading.Thread(target=worker, args=("other", "reporter_b"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(errors), 0, f"Dispute concurrency errors: {errors}")

        with self.db.session_scope() as session:
            coord = session.get(CommunityDomainCoordinationEntity, domain)
            self.assertIsNotNone(coord)
            self.assertTrue(coord.is_disputed, "Domain coordination must be marked disputed")

            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), 2)
            for r in reports:
                self.assertEqual(r.verification_state, VerificationState.DISPUTED)

    # =========================================================================
    # PART 3: Evidence Persistence on PostgreSQL
    # =========================================================================

    def test_08_postgres_concurrent_duplicate_evidence_uniqueness(self):
        """PG-EVID-01: Concurrent duplicate evidence creates exactly 1 row; unique index enforced."""
        scan_id = f"pg-scan-{uuid.uuid4().hex[:8]}"
        ev_id = f"ev-pg-{uuid.uuid4().hex[:8]}"
        now = "2026-11-10T02:00:00Z"

        evidence = EvidenceModel(
            evidence_id=ev_id,
            scan_id=scan_id,
            kind="tls_hostname_validation",
            value={"hostname_matches": True, "issuer": "DigiCert"},
            source="worker01_tls",
            source_type="internal_collector",
            observed_at=now,
            status=EvidenceStatus.OBSERVED,
            reliability=Reliability.DIRECT_OBSERVATION,
            limitations=[],
            schema_version="1.0",
        )
        batch = EvidenceBatch(scan_id=scan_id, items=[evidence])

        concurrency = 8
        barrier = threading.Barrier(concurrency)
        errors = []

        def worker():
            try:
                ev_svc = EvidenceService(db_manager=self.db)
                barrier.wait(timeout=10)
                ev_svc.ingest_batch(batch)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Evidence concurrency errors: {errors}")

        with self.db.session_scope() as session:
            records = self.repo.get_evidence_by_scan(session, scan_id=scan_id)
            self.assertEqual(len(records), 1, "Exactly one evidence row must exist in PostgreSQL")

    def test_09_postgres_transaction_rollback_behavior(self):
        """PG-EVID-02: Failed transactions in PostgreSQL roll back cleanly without partial persistence."""
        scan_id = f"pg-rollback-{uuid.uuid4().hex[:8]}"
        ev_id = f"ev-rollback-{uuid.uuid4().hex[:8]}"

        evidence = EvidenceModel(
            evidence_id=ev_id,
            scan_id=scan_id,
            kind="dns_lookup",
            value={"ip": "8.8.8.8"},
            source="dns",
            observed_at="2026-11-10T02:00:00Z",
            status=EvidenceStatus.OBSERVED,
        )

        with self.assertRaises(RuntimeError):
            with self.db.session_scope() as session:
                self.repo.save_evidence(session, scan_id, evidence)
                # Deliberate failure inside transaction scope
                raise RuntimeError("Simulated transaction failure")

        # Verify nothing persisted in PostgreSQL
        with self.db.session_scope() as session:
            rec = self.repo.get_evidence_by_id(session, ev_id)
            self.assertIsNone(rec, "Rolled-back evidence must not exist in PostgreSQL")

    # =========================================================================
    # PART 4: Moderation Concurrency on PostgreSQL
    # =========================================================================

    def test_10_postgres_concurrent_moderation_state_transitions(self):
        """PG-MOD-01: Concurrent moderation reviews on PostgreSQL maintain consistent state & audit log."""
        domain = f"pg-mod-{uuid.uuid4().hex[:8]}.com"
        report, _ = self.comm_service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            note="To be moderated",
            raw_reporter_identifier="127.0.0.1",
        )

        concurrency = 5
        barrier = threading.Barrier(concurrency)
        errors = []

        def mod_worker(idx):
            try:
                mod_svc = ModerationService(community_service=self.comm_service, db_manager=self.db)
                barrier.wait(timeout=10)
                mod_svc.review_report(
                    report_id=report.report_id,
                    target_state=VerificationState.REVIEWED,
                    reason=f"Concurrent signoff by mod {idx}",
                    moderator_ref=f"moderator_{idx}",
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=mod_worker, args=(i,)) for i in range(concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Moderation concurrency errors: {errors}")

        with self.db.session_scope() as session:
            updated = self.repo.get_community_report(session, report.report_id)
            self.assertIsNotNone(updated)
            self.assertEqual(updated.verification_state, VerificationState.REVIEWED)

            audit_events = self.repo.get_audit_events_for_report(session, report.report_id)
            self.assertGreaterEqual(len(audit_events), 2)  # Submission + at least 1 review

    # =========================================================================
    # PART 5: Multi-Process Independence on PostgreSQL
    # =========================================================================

    def test_11_postgres_multiprocess_corroboration_consistency(self):
        """PG-PROC-01: Independent OS processes coordinate corroboration directly via PostgreSQL."""
        domain = f"pg-multi-proc-{uuid.uuid4().hex[:8]}.com"
        tasks = [
            (self.pg_url, domain, "phishtank", "proc_user_1"),
            (self.pg_url, domain, "urlhaus", "proc_user_2"),
            (self.pg_url, domain, "openphish", "proc_user_3"),
            (self.pg_url, domain, "phishtank", "proc_user_4"),  # Duplicate family across process
        ]

        # Execute across 4 independent OS processes
        with ProcessPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(_multiprocess_submit_worker, *t) for t in tasks]
            results = [f.result(timeout=20) for f in futures]

        self.assertEqual(len(results), 4)

        # Assert final state in PostgreSQL:
        # Families submitted: phishtank, urlhaus, openphish, phishtank.
        # Distinct families: 3 (phishtank, urlhaus, openphish).
        with self.db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), 4)
            for r in reports:
                self.assertEqual(r.independent_source_count, 3, "Distinct source families across processes must be exactly 3")

            families = session.execute(
                select(CommunityDomainSourceFamilyEntity).where(
                    CommunityDomainSourceFamilyEntity.normalized_domain == domain
                )
            ).scalars().all()
            self.assertEqual(len(families), 3)
            registered = {f.source_family for f in families}
            self.assertEqual(registered, {"phishtank", "urlhaus", "openphish"})


if __name__ == "__main__":
    unittest.main()
