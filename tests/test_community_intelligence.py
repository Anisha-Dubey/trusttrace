"""Tests for Community Intelligence, Deduplication, Moderation, and Audit History."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import unittest

from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.evidence.community.service import CommunityIntelligenceService
from trusttrace.evidence.community.moderation import ModerationService
from trusttrace.evidence.community.state_machine import InvalidStateTransitionError
from trusttrace.evidence.community.deduplicator import DeduplicationCategory
from trusttrace.evidence.domain.enums import VerificationState, ClaimType


class TestCommunityIntelligence(unittest.TestCase):
    """Test suite for Phase 02 community intelligence lifecycle."""

    def setUp(self):
        self.db = DatabaseManager("sqlite:///:memory:")
        self.service = CommunityIntelligenceService(db_manager=self.db)
        self.moderation = ModerationService(community_service=self.service, db_manager=self.db)

    def test_new_report_defaults_to_unverified(self):
        """COMM: New community reports must strictly default to unverified state."""
        report, res = self.service.submit_report(
            normalized_domain="phish-bank.test",
            claim_type="phishing",
            note="User reported credential harvesting",
            raw_reporter_identifier="user-session-12345",
        )
        self.assertEqual(report.verification_state, VerificationState.UNVERIFIED)
        self.assertEqual(report.independent_source_count, 1)
        self.assertEqual(res.category, DeduplicationCategory.NEW_REPORT)

    def test_text_sanitization_xss_protection_comm_004(self):
        """COMM-004: HTML/script tags in free text must be stripped, preventing stored XSS."""
        malicious_note = "<script>alert('pwned')</script><iframe src='evil.com'></iframe>Suspect login form"
        report, _ = self.service.submit_report(
            normalized_domain="target-xss.test",
            claim_type="phishing",
            note=malicious_note,
            raw_reporter_identifier="attacker-ip",
        )
        self.assertNotIn("<script>", report.note_redacted)
        self.assertNotIn("alert", report.note_redacted)
        self.assertNotIn("<iframe", report.note_redacted)
        self.assertIn("Suspect login form", report.note_redacted)

    def test_reporter_pseudonymization_data_002(self):
        """DATA-002: Private reporter identity must never appear in database or public output."""
        raw_ip = "198.51.100.42"
        report, _ = self.service.submit_report(
            normalized_domain="privacy.test",
            claim_type="impersonation",
            note="Impersonating HR portal",
            raw_reporter_identifier=raw_ip,
        )
        # Public contract dict must not contain reporter IP or hash
        contract_dict = report.to_v1_contract_dict()
        self.assertNotIn(raw_ip, str(contract_dict))
        self.assertNotIn("reporter_hash", contract_dict)

        # In DB entity, raw IP is never stored
        with self.db.session_scope() as session:
            entity = self.service.repo.get_scan(session, report.report_id)
            # Scan table won't have it, and report entity has only HMAC hash
            rep_entity = self.service.repo.find_community_reports(session, normalized_domain="privacy.test")[0]
            self.assertNotEqual(rep_entity.reporter_hash, raw_ip)
            self.assertNotIn(raw_ip, rep_entity.reporter_hash)

    def test_exact_duplicate_detection_comm_001(self):
        """COMM-001: Repeated reports by same reporter do NOT inflate independent count."""
        # Initial submission
        rep1, res1 = self.service.submit_report(
            normalized_domain="repeat-phish.test",
            claim_type="phishing",
            raw_reporter_identifier="reporter-alpha",
        )
        self.assertEqual(res1.category, DeduplicationCategory.NEW_REPORT)
        self.assertEqual(rep1.independent_source_count, 1)

        # Exact duplicate
        rep2, res2 = self.service.submit_report(
            normalized_domain="repeat-phish.test",
            claim_type="phishing",
            raw_reporter_identifier="reporter-alpha",
        )
        self.assertEqual(res2.category, DeduplicationCategory.EXACT_DUPLICATE)
        self.assertEqual(rep2.report_id, rep1.report_id)
        self.assertEqual(rep2.independent_source_count, 1)

    def test_copied_source_detection_comm_002(self):
        """COMM-002: Copied or shared threat feeds (same source family) do NOT inflate independent count."""
        # Reporter 1 submits from PhishTank API (authenticated feed provider)
        rep1, res1 = self.service.submit_report(
            normalized_domain="syndicated-threat.test",
            claim_type="phishing",
            raw_reporter_identifier="reporter-01",
            source_family="phishtank_api",
            is_authenticated_provider=True,
        )
        self.assertEqual(rep1.independent_source_count, 1)

        # Reporter 2 submits from PhishTank mirror
        rep2, res2 = self.service.submit_report(
            normalized_domain="syndicated-threat.test",
            claim_type="phishing",
            raw_reporter_identifier="reporter-02",
            source_family="phishtank_community",
            is_authenticated_provider=True,
        )
        self.assertEqual(res2.category, DeduplicationCategory.COPIED_SOURCE)
        self.assertEqual(rep2.independent_source_count, 1)  # Stays at 1!

    def test_independent_source_corroboration(self):
        """Independent sources from distinct source families safely increment count."""
        # Source 1: PhishTank (authenticated provider)
        rep1, _ = self.service.submit_report(
            normalized_domain="corroborated-phish.test",
            claim_type="phishing",
            raw_reporter_identifier="rep-1",
            source_family="phishtank",
            is_authenticated_provider=True,
        )
        self.assertEqual(rep1.independent_source_count, 1)

        # Source 2: OpenPhish (independent authenticated provider family)
        rep2, res2 = self.service.submit_report(
            normalized_domain="corroborated-phish.test",
            claim_type="phishing",
            raw_reporter_identifier="rep-2",
            source_family="openphish",
            is_authenticated_provider=True,
        )
        self.assertEqual(res2.category, DeduplicationCategory.INDEPENDENT_SOURCE)
        self.assertEqual(rep2.independent_source_count, 2)

        # Rep1 count should also reflect 2
        updated_rep1 = self.service.get_report(rep1.report_id)
        self.assertEqual(updated_rep1.independent_source_count, 2)

    def test_conflicting_report_handling_comm_003(self):
        """COMM-003: Contradictory reports transition domain state to disputed, preserving both reports."""
        # Report 1: Phishing claim
        rep1, _ = self.service.submit_report(
            normalized_domain="disputed-domain.test",
            claim_type="phishing",
            raw_reporter_identifier="user-victim",
        )
        self.assertEqual(rep1.verification_state, VerificationState.UNVERIFIED)

        # Report 2: Contradictory non-malicious claim
        rep2, res2 = self.service.submit_report(
            normalized_domain="disputed-domain.test",
            claim_type="other",
            note="Legitimate corporate portal, false positive",
            raw_reporter_identifier="domain-admin",
        )
        self.assertEqual(res2.category, DeduplicationCategory.CONFLICTING_REPORT)
        self.assertTrue(res2.is_conflict)
        self.assertEqual(rep2.verification_state, VerificationState.DISPUTED)

        # Verify Report 1 is also marked disputed
        updated_rep1 = self.service.get_report(rep1.report_id)
        self.assertEqual(updated_rep1.verification_state, VerificationState.DISPUTED)

        # Both reports must remain visible
        domain_reports = self.service.list_reports_for_domain("disputed-domain.test")
        self.assertEqual(len(domain_reports), 2)

    def test_allowed_state_transitions(self):
        """Verify all valid lifecycle transitions."""
        # 1. unverified -> corroborated
        r1, _ = self.service.submit_report("t1.test", "phishing")
        u1 = self.service.transition_report_state(
            r1.report_id, VerificationState.CORROBORATED, "Corroborated by telemetry", "mod-1"
        )
        self.assertEqual(u1.verification_state, VerificationState.CORROBORATED)

        # 2. unverified -> disputed
        r2, _ = self.service.submit_report("t2.test", "phishing")
        u2 = self.service.transition_report_state(
            r2.report_id, VerificationState.DISPUTED, "Claim contested", "mod-1"
        )
        self.assertEqual(u2.verification_state, VerificationState.DISPUTED)

        # 3. unverified -> reviewed
        r3, _ = self.service.submit_report("t3.test", "phishing")
        u3 = self.service.transition_report_state(
            r3.report_id, VerificationState.REVIEWED, "Reviewed by analyst", "mod-1"
        )
        self.assertEqual(u3.verification_state, VerificationState.REVIEWED)

        # 4. corroborated -> disputed
        u4 = self.service.transition_report_state(
            r1.report_id, VerificationState.DISPUTED, "Counter-evidence surfaced", "mod-2"
        )
        self.assertEqual(u4.verification_state, VerificationState.DISPUTED)

        # 5. disputed -> reviewed
        u5 = self.service.transition_report_state(
            r2.report_id, VerificationState.REVIEWED, "Dispute arbitrated", "mod-3"
        )
        self.assertEqual(u5.verification_state, VerificationState.REVIEWED)

    def test_prohibited_state_transitions(self):
        """Verify illegal transitions are strictly rejected by the state machine."""
        rep, _ = self.service.submit_report("illegal-test.test", "phishing")
        # Move to reviewed
        self.service.transition_report_state(
            rep.report_id, VerificationState.REVIEWED, "Analyst review", "mod-1"
        )

        # Attempt reviewed -> unverified (forbidden)
        with self.assertRaises(InvalidStateTransitionError):
            self.service.transition_report_state(
                rep.report_id, VerificationState.UNVERIFIED, "Illegal reset", "attacker"
            )

        # Attempt reviewed -> corroborated (forbidden)
        with self.assertRaises(InvalidStateTransitionError):
            self.service.transition_report_state(
                rep.report_id, VerificationState.CORROBORATED, "Illegal jump", "attacker"
            )

    def test_moderation_review_and_audit_history(self):
        """Verify moderation actions generate chronological, queryable audit events."""
        rep, _ = self.service.submit_report("audit-test.test", "phishing")

        # Formal moderation review
        reviewed = self.moderation.review_report(
            report_id=rep.report_id,
            target_state=VerificationState.REVIEWED,
            reason="Verified against internal CERT feed",
            moderator_ref="mod-chief-01",
        )
        self.assertEqual(reviewed.verification_state, VerificationState.REVIEWED)

        # Query report audit trail
        trail = self.moderation.get_audit_trail(rep.report_id)
        self.assertEqual(len(trail), 2)
        self.assertEqual(trail[0].action, "submitted")
        self.assertEqual(trail[1].action, "transition_to_reviewed")
        self.assertIn("CERT feed", trail[1].reason)
        self.assertEqual(trail[1].actor_ref, "moderator:mod-chief-01")

        # Query domain audit history
        domain_history = self.moderation.get_domain_audit_history("audit-test.test")
        self.assertEqual(len(domain_history), 2)


if __name__ == "__main__":
    unittest.main()
