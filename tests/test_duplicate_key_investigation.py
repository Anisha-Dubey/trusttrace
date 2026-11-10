"""TRUSTTRACE — Duplicate-Key Investigation and Concurrency Verification Suite.

Tests scenarios A through H specified in Post-Merge Duplicate-Key Investigation:
- A. Same normalized domain inserted twice sequentially.
- B. Same normalized domain and source family inserted twice.
- C. Same domain reported by two different source families.
- D. Concurrent ingestion of the same normalized domain.
- E. Concurrent ingestion of the same domain and source family.
- F. Repeated ingestion of the same community report.
- G. Transaction behavior after a uniqueness conflict.
- H. Domain normalization variants (case, whitespace, trailing dot, URL rejection).
"""

import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.evidence.persistence.repository import EvidenceRepository
from trusttrace.evidence.persistence.models import (
    CommunityDomainCoordinationEntity,
    CommunityDomainSourceFamilyEntity,
    CommunityReportEntity,
)
from trusttrace.evidence.community.service import CommunityIntelligenceService
from trusttrace.evidence.community.deduplicator import DeduplicationCategory
from trusttrace.evidence.domain.enums import VerificationState
from trusttrace.api.schemas import validate_domain_name


class TestDuplicateKeyInvestigation(unittest.TestCase):
    """Reproduction and verification suite for duplicate-key and concurrency handling."""

    def setUp(self):
        self.db = DatabaseManager("sqlite:///:memory:")
        self.db.init_db()
        self.repo = EvidenceRepository(self.db)
        self.service = CommunityIntelligenceService(db_manager=self.db, repository=self.repo)

    # -------------------------------------------------------------------------
    # Scenario A: Same normalized domain inserted twice sequentially
    # -------------------------------------------------------------------------
    def test_scenario_a_same_domain_sequential_ingestion(self):
        """A. Sequential reports on the same domain update independent counts without duplicate coordination errors."""
        domain = "scenario-a-target.com"
        rep1, dedup1 = self.service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            note="Report 1",
            raw_reporter_identifier="analyst_1",
        )
        self.assertEqual(rep1.independent_source_count, 1)

        rep2, dedup2 = self.service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            note="Report 2",
            raw_reporter_identifier="analyst_2",
        )
        self.assertEqual(rep2.independent_source_count, 1)

        with self.db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), 2)
            for r in reports:
                self.assertEqual(r.independent_source_count, 1)

            # Exactly one coordination row
            coord = session.get(CommunityDomainCoordinationEntity, domain)
            self.assertIsNotNone(coord)
            self.assertFalse(coord.is_disputed)

    # -------------------------------------------------------------------------
    # Scenario B: Same normalized domain and source family inserted twice
    # -------------------------------------------------------------------------
    def test_scenario_b_same_domain_and_source_family_twice(self):
        """B. Two reports from the same source family absorb duplicate without inflating independent count."""
        domain = "scenario-b-target.com"
        family = "phishtank"

        rep1, dedup1 = self.service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            note="Feed probe 1",
            raw_reporter_identifier="collector_1",
            source_family=family,
            is_authenticated_provider=True,
            permitted_families={family},
        )
        self.assertEqual(rep1.independent_source_count, 1)

        rep2, dedup2 = self.service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            note="Feed probe 2",
            raw_reporter_identifier="collector_2",
            source_family=family,
            is_authenticated_provider=True,
            permitted_families={family},
        )
        self.assertEqual(dedup2.category, DeduplicationCategory.COPIED_SOURCE)
        self.assertEqual(rep2.independent_source_count, 1)

        with self.db.session_scope() as session:
            # Only 1 source family registered in junction table
            families = self.repo.get_registered_source_families_for_domain(session, domain)
            self.assertEqual(len(families), 1)
            self.assertEqual(families[0], family)

    # -------------------------------------------------------------------------
    # Scenario C: Same domain reported by two different source families
    # -------------------------------------------------------------------------
    def test_scenario_c_two_different_source_families(self):
        """C. Two distinct authenticated source families corroborate and safely increment count to 2."""
        domain = "scenario-c-target.com"

        rep1, _ = self.service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            source_family="phishtank",
            is_authenticated_provider=True,
            permitted_families={"phishtank"},
            raw_reporter_identifier="collector_1",
        )
        self.assertEqual(rep1.independent_source_count, 1)

        rep2, _ = self.service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            source_family="urlhaus",
            is_authenticated_provider=True,
            permitted_families={"urlhaus"},
            raw_reporter_identifier="collector_2",
        )
        self.assertEqual(rep2.independent_source_count, 2)

        with self.db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), 2)
            for r in reports:
                self.assertEqual(r.independent_source_count, 2)

            families = self.repo.get_registered_source_families_for_domain(session, domain)
            self.assertEqual(set(families), {"phishtank", "urlhaus"})

    # -------------------------------------------------------------------------
    # Scenario D: Concurrent ingestion of the same normalized domain
    # -------------------------------------------------------------------------
    def test_scenario_d_concurrent_same_normalized_domain(self):
        """D. Concurrent submissions for unseen domain maintain atomic coordination and count 1."""
        domain = "scenario-d-target.com"
        concurrency = 6
        barrier = threading.Barrier(concurrency)
        results = []
        errors = []

        def worker(idx):
            try:
                barrier.wait(timeout=5)
                rep, dedup = self.service.submit_report(
                    normalized_domain=domain,
                    claim_type="phishing",
                    note=f"Concurrent probe {idx}",
                    raw_reporter_identifier=f"user_{idx}",
                )
                results.append(rep)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent domain errors: {errors}")
        self.assertEqual(len(results), concurrency)

        with self.db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), concurrency)
            for r in reports:
                self.assertEqual(r.independent_source_count, 1)

            coord = session.get(CommunityDomainCoordinationEntity, domain)
            self.assertIsNotNone(coord)
            self.assertFalse(coord.is_disputed)

    # -------------------------------------------------------------------------
    # Scenario E: Concurrent ingestion of the same domain and source family
    # -------------------------------------------------------------------------
    def test_scenario_e_concurrent_same_domain_and_family(self):
        """E. Concurrent submissions for same domain and family absorb safely without count inflation."""
        domain = "scenario-e-target.com"
        concurrency = 6
        barrier = threading.Barrier(concurrency)
        results = []
        errors = []

        def worker(idx):
            try:
                barrier.wait(timeout=5)
                rep, dedup = self.service.submit_report(
                    normalized_domain=domain,
                    claim_type="phishing",
                    note=f"Family probe {idx}",
                    raw_reporter_identifier=f"collector_{idx}",
                    source_family="phishtank",
                    is_authenticated_provider=True,
                    permitted_families={"phishtank"},
                )
                results.append(rep)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent family errors: {errors}")
        self.assertEqual(len(results), concurrency)

        with self.db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), concurrency)
            for r in reports:
                self.assertEqual(r.independent_source_count, 1)

            families = self.repo.get_registered_source_families_for_domain(session, domain)
            self.assertEqual(len(families), 1)
            self.assertEqual(families[0], "phishtank")

    # -------------------------------------------------------------------------
    # Scenario F: Repeated ingestion of the exact same community report
    # -------------------------------------------------------------------------
    def test_scenario_f_repeated_exact_report_ingestion(self):
        """F. Re-submitting the exact same report returns existing model (EXACT_DUPLICATE) with same report_id."""
        domain = "scenario-f-target.com"
        raw_id = "analyst_alice"
        note = "Exact malicious login clone"

        rep1, dedup1 = self.service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            note=note,
            raw_reporter_identifier=raw_id,
        )
        self.assertEqual(dedup1.category, DeduplicationCategory.NEW_REPORT)

        rep2, dedup2 = self.service.submit_report(
            normalized_domain=domain,
            claim_type="phishing",
            note=note,
            raw_reporter_identifier=raw_id,
        )
        self.assertEqual(dedup2.category, DeduplicationCategory.EXACT_DUPLICATE)
        self.assertEqual(rep1.report_id, rep2.report_id)

        with self.db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain=domain)
            self.assertEqual(len(reports), 1)

    # -------------------------------------------------------------------------
    # Scenario G: Transaction behavior after uniqueness conflict
    # -------------------------------------------------------------------------
    def test_scenario_g_transaction_behavior_after_uniqueness_conflict(self):
        """G. Subtransaction savepoint rollback preserves session health after duplicate constraint violation."""
        domain = "scenario-g-target.com"
        family = "phishtank"

        # Create parent report
        with self.db.session_scope() as session:
            rep = CommunityReportEntity(
                report_id="rep-g-001",
                normalized_domain=domain,
                claim_type="phishing",
                submitted_at="2026-11-10T00:00:00Z",
                verification_state="unverified",
                independent_source_count=1,
                source_family=family,
                reporter_hash="hash_g_001",
            )
            session.add(rep)

        # In a single session, register same family twice
        with self.db.session_scope() as session:
            first_res = self.repo.register_domain_source_family(
                session, domain, family, "rep-g-001", "2026-11-10T00:00:00Z"
            )
            self.assertTrue(first_res, "First registration must succeed")

            # Duplicate insertion: hits UniqueConstraint('normalized_domain', 'source_family')
            second_res = self.repo.register_domain_source_family(
                session, domain, family, "rep-g-001", "2026-11-10T00:00:00Z"
            )
            self.assertFalse(second_res, "Second duplicate registration must return False")

            # Verify session was NOT corrupted and can continue executing queries
            distinct_count = self.repo.count_distinct_source_families_for_domain(session, domain)
            self.assertEqual(distinct_count, 1)

            # Session can execute further writes without PendingRollbackError
            coord = self.repo.acquire_domain_coordination(session, domain, "2026-11-10T00:00:00Z")
            self.assertIsNotNone(coord)
            self.assertEqual(coord.normalized_domain, domain)

    # -------------------------------------------------------------------------
    # Scenario H: Domain normalization variants
    # -------------------------------------------------------------------------
    def test_scenario_h1_case_insensitivity(self):
        """H1. Uppercase domains are normalized to lowercase identically."""
        rep1, _ = self.service.submit_report(
            normalized_domain="UPPERCASE-DOMAIN.COM",
            claim_type="phishing",
            raw_reporter_identifier="u1",
        )
        self.assertEqual(rep1.normalized_domain, "uppercase-domain.com")

        rep2, _ = self.service.submit_report(
            normalized_domain="uppercase-domain.com",
            claim_type="phishing",
            raw_reporter_identifier="u2",
        )
        self.assertEqual(rep2.normalized_domain, "uppercase-domain.com")

        with self.db.session_scope() as session:
            reports = self.repo.find_community_reports(session, normalized_domain="uppercase-domain.com")
            self.assertEqual(len(reports), 2)

    def test_scenario_h2_whitespace_stripping(self):
        """H2. Leading and trailing whitespace is stripped."""
        rep, _ = self.service.submit_report(
            normalized_domain="   whitespace-domain.com   \t",
            claim_type="phishing",
            raw_reporter_identifier="u1",
        )
        self.assertEqual(rep.normalized_domain, "whitespace-domain.com")

    def test_scenario_h3_trailing_dot_handling(self):
        """H3. Trailing dot is stripped cleanly in schema validation and service layer."""
        # API schema validator
        cleaned = validate_domain_name("trailing-dot.com.")
        self.assertEqual(cleaned, "trailing-dot.com")

        # Service layer
        rep, _ = self.service.submit_report(
            normalized_domain="trailing-dot.com.",
            claim_type="phishing",
            raw_reporter_identifier="u1",
        )
        # Verify stored cleanly without trailing dot
        self.assertEqual(rep.normalized_domain, "trailing-dot.com")

    def test_scenario_h4_url_input_rejected_by_schema(self):
        """H4. URLs with protocol schemes or path/queries are rejected at schema boundary."""
        invalid_inputs = [
            "https://example.com/login",
            "http://phish.target.org",
            "example.com/path?foo=bar",
            "https://evil.com#anchor",
        ]
        for url in invalid_inputs:
            with self.assertRaises(ValueError):
                validate_domain_name(url)


if __name__ == "__main__":
    unittest.main()
