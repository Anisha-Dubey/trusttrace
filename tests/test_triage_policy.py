"""Tests for Worker 03 — Explainable triage policy and controlled evaluation.

Test matrix coverage:
- EVID-002: No reputation match → never safe
- EVID-003: Stale evidence → staleness flagged
- EVID-004: Conflicting signals → inconclusive, both retained
- TLS-001 (via policy): Valid TLS → identity=unverified, not supported
- TLS-002 (via policy): Expired TLS → not sole proof of phishing
- CLAIM-001: Pitch claim audit flags unsupported claims

Golden cases from phase_01.md:
1. Valid TLS / unverified identity
2. Weak signal only
3. Corroborated match
4. No match
5. Missing/conflicting checks
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from trusttrace.policy.signal_taxonomy import (
    SignalKind,
    SignalRecord,
    SignalDimension,
    DimensionAssessment,
    SIGNAL_DIMENSION_MAP,
)
from trusttrace.policy.triage_engine import TriageEngine, TriageResult, POLICY_VERSION
from trusttrace.policy.decision_log import DecisionLog, DecisionLogEntry
from trusttrace.policy.evaluation import (
    ControlledEvaluationSet,
    EvaluationFixture,
    FixtureLabel,
    ClaimAuditor,
    ClaimVerdict,
    ClaimCategory,
)
from trusttrace.policy import (
    AbstentionNotice,
    AuditIssue,
    AuditRuleId,
    AuditSeverity,
    CommunityReportItem,
    ConfidenceBand,
    CoverageSummary,
    DEFAULT_FRESHNESS_WINDOWS,
    DecisionAuditRecord,
    DiagnosticCode,
    DiagnosticCollector,
    DiagnosticRecord,
    DiagnosticSeverity,
    EvidenceItem,
    EvidenceSignalExtractor,
    EvidenceValidator,
    FIXTURES_V1,
    FIXTURES_V2,
    FreshnessPolicy,
    ParseIssue,
    PolicyInput,
    PolicyInputParseError,
    PolicyRegressionRunner,
    RegressionDiffReport,
    ReportAuditResult,
    ReportIntegrityAuditor,
    SignalConfidence,
    SignalExtractionResult,
    UncertaintyAssessment,
    UncertaintyEngine,
    UncertaintyRecord,
    UncertaintyType,
    ValidationIssue,
    ValidationResult,
    build_eval_v1_set,
    build_eval_v2_set,
    generate_deterministic_finding_id,
    normalize_signal_confidence,
)
import json
from datetime import datetime, timezone, timedelta
from dataclasses import FrozenInstanceError



class TestSignalTaxonomy(unittest.TestCase):
    """Tests for signal classification and dimension mapping."""

    def test_all_signals_have_dimension_mapping(self):
        """Every SignalKind must map to exactly one dimension."""
        for kind in SignalKind:
            self.assertIn(
                kind,
                SIGNAL_DIMENSION_MAP,
                f"SignalKind.{kind.name} has no dimension mapping.",
            )

    def test_signal_record_dimension_property(self):
        """SignalRecord.dimension returns the correct dimension."""
        sig = SignalRecord(
            kind=SignalKind.TLS_VALID,
            evidence_ids=["ev-1"],
            source="tls_collector",
        )
        self.assertEqual(sig.dimension, SignalDimension.CERTIFICATE)

    def test_identity_signals_map_to_identity(self):
        """Identity-related signals map to IDENTITY dimension."""
        identity_kinds = [
            SignalKind.TLS_HOSTNAME_MATCH,
            SignalKind.AUTHORIZATION_EVIDENCE,
            SignalKind.IDN_LOOKALIKE,
        ]
        for kind in identity_kinds:
            self.assertEqual(
                SIGNAL_DIMENSION_MAP[kind],
                SignalDimension.IDENTITY,
                f"{kind} should map to IDENTITY.",
            )


class TestTriageEngine(unittest.TestCase):
    """Tests for the conservative deterministic triage engine."""

    def setUp(self):
        self.engine = TriageEngine()

    # ── Golden Case 1: Valid TLS / unverified identity (TLS-001) ──

    def test_valid_tls_identity_unverified(self):
        """TLS-001: Valid TLS alone → identity=unverified, never supported."""
        signals = [
            SignalRecord(
                kind=SignalKind.TLS_VALID,
                evidence_ids=["ev-tls-1"],
                source="tls_collector",
            ),
            SignalRecord(
                kind=SignalKind.TLS_HOSTNAME_MATCH,
                evidence_ids=["ev-tls-1"],
                source="tls_collector",
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-tls-1", "ev-dns-1"],
                source="orchestrator",
            ),
            SignalRecord(
                kind=SignalKind.NO_THREAT_MATCH,
                evidence_ids=["ev-dns-1"],
                source="dns_collector",
            ),
        ]
        result = self.engine.evaluate(signals)

        self.assertEqual(result.dimensions["identity"], "unverified")
        self.assertNotEqual(result.dimensions["identity"], "supported")
        self.assertEqual(result.dimensions["certificate"], "valid_for_hostname")
        self.assertEqual(result.policy_version, POLICY_VERSION)
        # Must have rule trace showing which rules fired.
        self.assertGreater(len(result.rule_trace), 0)

    # ── Golden Case 2: Weak signal only ──

    def test_weak_signal_stale_evidence(self):
        """EVID-003: Stale evidence → weak quality, inconclusive decision."""
        signals = [
            SignalRecord(
                kind=SignalKind.STALE_EVIDENCE,
                evidence_ids=["ev-stale-1"],
                source="evidence_service",
                limitations=["Evidence is 30 days old."],
            ),
        ]
        result = self.engine.evaluate(signals)

        self.assertEqual(result.dimensions["evidence_quality"], "weak")
        self.assertEqual(result.decision, "inconclusive")
        self.assertTrue(
            any("stale" in lim.lower() for lim in result.limitations),
            "Should mention staleness in limitations.",
        )

    # ── Golden Case 3: Corroborated match ──

    def test_corroborated_community_report(self):
        """Corroborated community report → caution, behavior=suspicious."""
        signals = [
            SignalRecord(
                kind=SignalKind.COMMUNITY_REPORT_CORROBORATED,
                evidence_ids=["ev-comm-1", "ev-comm-2"],
                source="community_service",
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-dns-1", "ev-tls-1"],
                source="orchestrator",
            ),
        ]
        result = self.engine.evaluate(signals)

        self.assertEqual(result.decision, "caution")
        self.assertEqual(result.dimensions["behavior"], "suspicious")
        # Should generate a community report finding.
        comm_findings = [
            f for f in result.findings if "community" in f.get("kind", "").lower()
        ]
        self.assertGreater(len(comm_findings), 0)

    # ── Golden Case 4: No match (EVID-002) ──

    def test_no_threat_match_never_safe(self):
        """EVID-002: No reputation match → never 'safe'; at most no_threat_observed."""
        signals = [
            SignalRecord(
                kind=SignalKind.NO_THREAT_MATCH,
                evidence_ids=["ev-dns-1"],
                source="threat_feed",
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-dns-1", "ev-tls-1", "ev-http-1"],
                source="orchestrator",
            ),
            SignalRecord(
                kind=SignalKind.TLS_VALID,
                evidence_ids=["ev-tls-1"],
                source="tls_collector",
            ),
        ]
        result = self.engine.evaluate(signals)

        # Decision must never be "safe" — that value doesn't even exist in schema.
        self.assertIn(
            result.decision,
            ["no_threat_observed", "inconclusive", "caution"],
        )
        self.assertNotEqual(result.decision, "safe")
        # Must have limitation about scope.
        self.assertTrue(
            any("safe" in lim.lower() or "scope" in lim.lower() or "absence" in lim.lower()
                for lim in result.limitations),
            f"Should mention limited scope in limitations: {result.limitations}",
        )

    # ── Golden Case 5: Missing/conflicting checks (EVID-004) ──

    def test_conflicting_signals_inconclusive(self):
        """EVID-004: Conflicting signals → inconclusive, both retained."""
        signals = [
            SignalRecord(
                kind=SignalKind.THREAT_FEED_MATCH,
                evidence_ids=["ev-feed-1"],
                source="threat_feed_A",
            ),
            SignalRecord(
                kind=SignalKind.NO_THREAT_MATCH,
                evidence_ids=["ev-feed-2"],
                source="threat_feed_B",
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-feed-1", "ev-feed-2"],
                source="orchestrator",
            ),
        ]
        result = self.engine.evaluate(signals)

        self.assertEqual(result.decision, "inconclusive")
        # Both evidence trails must be in findings or rule trace.
        all_ev_ids = set()
        for finding in result.findings:
            all_ev_ids.update(finding.get("evidence_ids", []))
        self.assertIn("ev-feed-1", all_ev_ids)
        # Limitations should mention conflict.
        self.assertTrue(
            any("conflict" in lim.lower() for lim in result.limitations),
            f"Should mention conflict in limitations: {result.limitations}",
        )

    # ── TLS-002: Expired TLS not proof of phishing ──

    def test_expired_tls_not_phishing_proof(self):
        """TLS-002: Expired TLS alone → caution at most, not high_risk."""
        signals = [
            SignalRecord(
                kind=SignalKind.TLS_EXPIRED,
                evidence_ids=["ev-tls-exp-1"],
                source="tls_collector",
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-tls-exp-1"],
                source="orchestrator",
            ),
        ]
        result = self.engine.evaluate(signals)

        self.assertEqual(result.dimensions["certificate"], "invalid_or_expired")
        # Decision should NOT be high_risk from certificate alone.
        self.assertNotEqual(result.decision, "high_risk")
        # Must have limitation about certificate not being proof.
        self.assertTrue(
            any("not" in lim.lower() and "proof" in lim.lower()
                or "insufficient" in lim.lower()
                for lim in result.limitations),
            f"Should flag cert invalidity limitation: {result.limitations}",
        )

    # ── Threat feed match → high_risk with evidence ──

    def test_threat_feed_match_high_risk(self):
        """Threat feed match with strong evidence → high_risk."""
        signals = [
            SignalRecord(
                kind=SignalKind.THREAT_FEED_MATCH,
                evidence_ids=["ev-feed-1"],
                source="threat_feed",
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-feed-1", "ev-dns-1"],
                source="orchestrator",
            ),
        ]
        result = self.engine.evaluate(signals)

        self.assertEqual(result.decision, "high_risk")
        self.assertEqual(result.dimensions["behavior"], "malicious_evidence")
        # Should have a threat finding.
        threat_findings = [
            f for f in result.findings if f.get("kind") == "threat_feed_match"
        ]
        self.assertGreater(len(threat_findings), 0)

    # ── IDN lookalike → unverified, caution at most ──

    def test_idn_lookalike_caution(self):
        """IDN/lookalike alone → identity=unverified, at most caution."""
        signals = [
            SignalRecord(
                kind=SignalKind.IDN_LOOKALIKE,
                evidence_ids=["ev-idn-1"],
                source="url_policy",
                limitations=["Candidate-generation signal; can produce false positives."],
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-idn-1"],
                source="orchestrator",
            ),
        ]
        result = self.engine.evaluate(signals)

        self.assertEqual(result.dimensions["identity"], "unverified")
        self.assertNotEqual(result.decision, "high_risk")
        self.assertTrue(
            any("idn" in lim.lower() or "lookalike" in lim.lower() or "impersonation" in lim.lower()
                for lim in result.limitations),
        )

    # ── All collectors failed → inconclusive (EVID-001) ──

    def test_all_collectors_failed_inconclusive(self):
        """EVID-001: All collectors failed → unavailable quality, inconclusive."""
        signals = [
            SignalRecord(
                kind=SignalKind.COLLECTOR_FAILURE,
                evidence_ids=["ev-fail-1"],
                source="orchestrator",
                limitations=["DNS collector timed out.", "TLS collector connection refused."],
            ),
        ]
        result = self.engine.evaluate(signals)

        self.assertEqual(result.dimensions["evidence_quality"], "unavailable")
        self.assertEqual(result.decision, "inconclusive")

    # ── Unverified community report → no auto-label ──

    def test_unverified_community_no_label(self):
        """COMM-001: Unverified community report stays unverified; no auto-label."""
        signals = [
            SignalRecord(
                kind=SignalKind.COMMUNITY_REPORT_UNVERIFIED,
                evidence_ids=["ev-comm-1"],
                source="community_service",
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-dns-1"],
                source="orchestrator",
            ),
        ]
        result = self.engine.evaluate(signals)

        # Should NOT escalate to high_risk from unverified report alone.
        self.assertNotEqual(result.decision, "high_risk")
        # Behavior should remain unknown, not malicious_evidence.
        self.assertNotEqual(result.dimensions["behavior"], "malicious_evidence")
        # Should have a community finding marked as unverified.
        comm_findings = [
            f for f in result.findings
            if f.get("kind") == "community_report"
        ]
        self.assertGreater(len(comm_findings), 0)
        self.assertTrue(
            any("unverified" in str(f.get("limitations", [])).lower()
                for f in comm_findings),
        )


class TestDecisionLog(unittest.TestCase):
    """Tests for the decision audit trail."""

    def test_record_and_retrieve(self):
        """Decision log records entries and retrieves by scan_id."""
        engine = TriageEngine()
        log = DecisionLog()

        signals = [
            SignalRecord(
                kind=SignalKind.TLS_VALID,
                evidence_ids=["ev-1"],
                source="tls",
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-1"],
                source="orchestrator",
            ),
        ]
        result = engine.evaluate(signals)
        entry = log.record("scan-123", result, ["tls_valid"], ["ev-1"])

        self.assertEqual(entry.scan_id, "scan-123")
        self.assertEqual(entry.policy_version, POLICY_VERSION)
        self.assertEqual(entry.decision, result.decision)
        self.assertGreater(len(entry.rule_ids_fired), 0)

        # Retrieve by scan_id.
        found = log.find_by_scan("scan-123")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].entry_id, entry.entry_id)

    def test_log_serialization(self):
        """Decision log entry serializes to dict with all fields."""
        entry = DecisionLogEntry(
            scan_id="scan-456",
            policy_version="test-v1",
            decision="caution",
            dimensions={"identity": "unknown"},
            rule_ids_fired=["RULE-BEH-001"],
            rationale_summary="Test rationale.",
        )
        d = entry.to_dict()
        self.assertEqual(d["scan_id"], "scan-456")
        self.assertEqual(d["decision"], "caution")
        self.assertIn("entry_id", d)
        self.assertIn("created_at", d)


class TestControlledEvaluation(unittest.TestCase):
    """Tests for controlled evaluation set and regression testing."""

    def _build_evaluation_set(self) -> ControlledEvaluationSet:
        """Build a set of golden fixtures covering all major scenarios."""
        eval_set = ControlledEvaluationSet()

        # Fixture 1: Valid TLS, no threats → no_threat_observed
        eval_set.add_fixture(EvaluationFixture(
            fixture_id="FIX-001",
            description="Valid TLS, all collectors pass, no threats",
            label=FixtureLabel.NO_THREAT_OBSERVED,
            signals_config=[
                {"kind": "tls_valid", "evidence_ids": ["ev-tls-1"]},
                {"kind": "tls_hostname_match", "evidence_ids": ["ev-tls-1"]},
                {"kind": "no_threat_match", "evidence_ids": ["ev-dns-1"]},
                {"kind": "collector_success", "evidence_ids": ["ev-tls-1", "ev-dns-1"]},
            ],
            expected_dimensions={
                "identity": "unverified",
                "certificate": "valid_for_hostname",
                "behavior": "no_threat_observed",
                "evidence_quality": "strong",
            },
            expected_decision="no_threat_observed",
        ))

        # Fixture 2: Threat feed match → high_risk
        eval_set.add_fixture(EvaluationFixture(
            fixture_id="FIX-002",
            description="Threat feed match with strong evidence",
            label=FixtureLabel.HIGH_RISK,
            signals_config=[
                {"kind": "threat_feed_match", "evidence_ids": ["ev-feed-1"]},
                {"kind": "collector_success", "evidence_ids": ["ev-feed-1"]},
            ],
            expected_dimensions={
                "behavior": "malicious_evidence",
                "evidence_quality": "strong",
            },
            expected_decision="high_risk",
        ))

        # Fixture 3: Expired TLS alone → inconclusive (not high_risk)
        eval_set.add_fixture(EvaluationFixture(
            fixture_id="FIX-003",
            description="Expired TLS certificate, no other signals",
            label=FixtureLabel.INCONCLUSIVE,
            signals_config=[
                {"kind": "tls_expired", "evidence_ids": ["ev-tls-exp-1"]},
                {"kind": "collector_success", "evidence_ids": ["ev-tls-exp-1"]},
            ],
            expected_dimensions={
                "certificate": "invalid_or_expired",
                "identity": "unknown",
                "evidence_quality": "strong",
            },
            expected_decision="inconclusive",
        ))

        # Fixture 4: All collectors failed → inconclusive
        eval_set.add_fixture(EvaluationFixture(
            fixture_id="FIX-004",
            description="All collectors failed",
            label=FixtureLabel.INCONCLUSIVE,
            signals_config=[
                {"kind": "collector_failure", "evidence_ids": ["ev-fail-1"]},
            ],
            expected_dimensions={
                "evidence_quality": "unavailable",
            },
            expected_decision="inconclusive",
        ))

        # Fixture 5: Conflicting signals → inconclusive
        eval_set.add_fixture(EvaluationFixture(
            fixture_id="FIX-005",
            description="Conflicting threat feed results",
            label=FixtureLabel.CONFLICTING,
            signals_config=[
                {"kind": "threat_feed_match", "evidence_ids": ["ev-f1"]},
                {"kind": "no_threat_match", "evidence_ids": ["ev-f2"]},
                {"kind": "collector_success", "evidence_ids": ["ev-f1", "ev-f2"]},
            ],
            expected_dimensions={
                "evidence_quality": "partial",
            },
            expected_decision="inconclusive",
        ))

        # Fixture 6: Corroborated community report → caution
        eval_set.add_fixture(EvaluationFixture(
            fixture_id="FIX-006",
            description="Corroborated community report",
            label=FixtureLabel.CAUTION,
            signals_config=[
                {"kind": "community_report_corroborated", "evidence_ids": ["ev-c1", "ev-c2"]},
                {"kind": "collector_success", "evidence_ids": ["ev-dns-1"]},
            ],
            expected_dimensions={
                "behavior": "suspicious",
                "evidence_quality": "strong",
            },
            expected_decision="caution",
        ))

        # Fixture 7: Stale evidence only → inconclusive
        eval_set.add_fixture(EvaluationFixture(
            fixture_id="FIX-007",
            description="Only stale evidence available",
            label=FixtureLabel.INCONCLUSIVE,
            signals_config=[
                {"kind": "stale_evidence", "evidence_ids": ["ev-stale-1"]},
            ],
            expected_dimensions={
                "evidence_quality": "weak",
            },
            expected_decision="inconclusive",
        ))

        return eval_set

    def test_evaluation_set_freeze(self):
        """Evaluation set can be frozen and no more fixtures added."""
        eval_set = self._build_evaluation_set()
        eval_set.freeze()
        self.assertTrue(eval_set.is_frozen)
        with self.assertRaises(RuntimeError):
            eval_set.add_fixture(EvaluationFixture(
                fixture_id="FIX-EXTRA",
                description="Should fail",
                label=FixtureLabel.INCONCLUSIVE,
                signals_config=[],
                expected_dimensions={},
                expected_decision="inconclusive",
            ))

    def test_class_prevalence(self):
        """Class prevalence is reported honestly."""
        eval_set = self._build_evaluation_set()
        prevalence = eval_set.get_class_prevalence()
        self.assertIn("inconclusive", prevalence)
        self.assertIn("high_risk", prevalence)
        # Total should match fixture count.
        self.assertEqual(sum(prevalence.values()), len(eval_set.fixtures))

    def test_run_evaluation_all_pass(self):
        """All golden fixtures should pass against the triage engine."""
        eval_set = self._build_evaluation_set()
        engine = TriageEngine()
        summary = eval_set.run_evaluation(engine)

        self.assertEqual(summary.total_fixtures, 7)
        self.assertTrue(summary.is_simulated)

        # Print any failures for debugging.
        for r in summary.results:
            if not r.passed:
                print(f"  FAIL: {r.fixture_id}: "
                      f"expected={r.expected_decision}, actual={r.actual_decision}, "
                      f"dim_mismatches={r.dimension_mismatches}")

        self.assertEqual(summary.passed, 7, f"Expected all 7 fixtures to pass, got {summary.passed}")
        self.assertEqual(summary.failed, 0)
        self.assertIsNotNone(summary.decision_accuracy)
        self.assertEqual(summary.decision_accuracy, 1.0)

        # Limitations should note simulated data.
        self.assertTrue(
            any("simulated" in lim.lower() for lim in summary.limitations),
        )

    def test_evaluation_summary_serialization(self):
        """Evaluation summary serializes to dict with all required fields."""
        eval_set = self._build_evaluation_set()
        engine = TriageEngine()
        summary = eval_set.run_evaluation(engine)
        d = summary.to_dict()

        self.assertIn("run_id", d)
        self.assertIn("total_fixtures", d)
        self.assertIn("passed", d)
        self.assertIn("decision_accuracy", d)
        self.assertIn("is_simulated", d)
        self.assertTrue(d["is_simulated"])


class TestClaimAuditor(unittest.TestCase):
    """Tests for pitch/demo claim audit — CLAIM-001."""

    def setUp(self):
        self.auditor = ClaimAuditor()

    def test_accuracy_claim_without_evidence(self):
        """Accuracy claim without evaluation → unsupported."""
        entry = self.auditor.audit_claim(
            "Our system achieves 99% accuracy in detecting phishing."
        )
        self.assertEqual(entry.verdict, ClaimVerdict.UNSUPPORTED)
        self.assertEqual(entry.category, ClaimCategory.ACCURACY)
        self.assertGreater(len(entry.issues), 0)

    def test_absolute_safety_claim(self):
        """'100% safe' or 'zero false positives' → always unsupported."""
        entry = self.auditor.audit_claim(
            "Our platform guarantees 100% safe browsing."
        )
        self.assertEqual(entry.verdict, ClaimVerdict.UNSUPPORTED)
        self.assertEqual(entry.category, ClaimCategory.SAFETY)

    def test_novelty_claim_unsupported(self):
        """Novelty claim without comparison → unsupported."""
        entry = self.auditor.audit_claim(
            "TrustTrace is the first and most novel approach to URL verification."
        )
        self.assertEqual(entry.verdict, ClaimVerdict.UNSUPPORTED)
        self.assertEqual(entry.category, ClaimCategory.NOVELTY)

    def test_probability_language_flagged(self):
        """Score/probability language without calibration → unsupported."""
        entry = self.auditor.audit_claim(
            "Each URL receives a threat score indicating the probability of being malicious."
        )
        self.assertEqual(entry.verdict, ClaimVerdict.UNSUPPORTED)
        self.assertGreater(len(entry.issues), 0)

    def test_benign_claim_not_flagged(self):
        """Normal descriptive claim → not_evaluated (no flags)."""
        entry = self.auditor.audit_claim(
            "TrustTrace shows DNS, TLS, and HTTP observations for submitted URLs."
        )
        self.assertEqual(entry.verdict, ClaimVerdict.NOT_EVALUATED)

    def test_batch_audit_detects_unsupported(self):
        """Batch audit flags at least one unsupported claim."""
        claims = [
            "We achieve 99% detection rate.",
            "TrustTrace displays evidence for each scan.",
            "Our system prevents all phishing attacks.",
        ]
        entries = self.auditor.audit_claims(claims)
        self.assertTrue(self.auditor.has_unsupported_claims(entries))

    def test_accuracy_with_simulated_eval(self):
        """Accuracy claim with simulated eval → partially_supported."""
        eval_set = ControlledEvaluationSet()
        eval_set.add_fixture(EvaluationFixture(
            fixture_id="FIX-TEST",
            description="Test",
            label=FixtureLabel.HIGH_RISK,
            signals_config=[
                {"kind": "threat_feed_match", "evidence_ids": ["ev-1"]},
                {"kind": "collector_success", "evidence_ids": ["ev-1"]},
            ],
            expected_dimensions={"behavior": "malicious_evidence"},
            expected_decision="high_risk",
        ))
        engine = TriageEngine()
        summary = eval_set.run_evaluation(engine)

        entry = self.auditor.audit_claim(
            "Our accuracy on test fixtures is strong.",
            evaluation_summary=summary,
        )
        self.assertEqual(entry.verdict, ClaimVerdict.PARTIALLY_SUPPORTED)


class TestSchemaCompliance(unittest.TestCase):
    """Verify triage output matches scan_report.schema.json structures."""

    def test_triage_result_fragment_has_required_fields(self):
        """TriageResult.to_report_fragment() has all schema-required fields."""
        engine = TriageEngine()
        signals = [
            SignalRecord(
                kind=SignalKind.TLS_VALID,
                evidence_ids=["ev-1"],
                source="tls",
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-1"],
                source="orchestrator",
            ),
        ]
        result = engine.evaluate(signals)
        fragment = result.to_report_fragment()

        self.assertIn("decision", fragment)
        self.assertIn("policy_version", fragment)
        self.assertIn("dimensions", fragment)
        self.assertIn("findings", fragment)
        self.assertIn("limitations", fragment)

        # Dimensions must have all four keys.
        dims = fragment["dimensions"]
        for key in ("identity", "certificate", "behavior", "evidence_quality"):
            self.assertIn(key, dims)

        # Decision must be a valid schema enum value.
        valid_decisions = {
            "high_risk", "caution", "no_threat_observed",
            "inconclusive", "rejected", "failed",
        }
        self.assertIn(fragment["decision"], valid_decisions)

    def test_dimension_values_match_schema_enums(self):
        """All dimension values must be valid schema enum values."""
        engine = TriageEngine()

        valid_values = {
            "identity": {"supported", "unverified", "contradicted", "unknown"},
            "certificate": {"valid_for_hostname", "invalid_or_expired", "unavailable", "not_checked"},
            "behavior": {"suspicious", "no_threat_observed", "malicious_evidence", "unknown"},
            "evidence_quality": {"strong", "partial", "weak", "unavailable"},
        }

        # Test across multiple scenarios.
        scenarios = [
            [SignalRecord(kind=SignalKind.TLS_VALID, evidence_ids=["e"], source="t"),
             SignalRecord(kind=SignalKind.COLLECTOR_SUCCESS, evidence_ids=["e"], source="o")],
            [SignalRecord(kind=SignalKind.COLLECTOR_FAILURE, evidence_ids=["e"], source="o")],
            [SignalRecord(kind=SignalKind.THREAT_FEED_MATCH, evidence_ids=["e"], source="f"),
             SignalRecord(kind=SignalKind.COLLECTOR_SUCCESS, evidence_ids=["e"], source="o")],
            [SignalRecord(kind=SignalKind.TLS_EXPIRED, evidence_ids=["e"], source="t"),
             SignalRecord(kind=SignalKind.COLLECTOR_SUCCESS, evidence_ids=["e"], source="o")],
        ]

        for i, signals in enumerate(scenarios):
            result = engine.evaluate(signals)
            for dim_key, allowed in valid_values.items():
                actual = result.dimensions[dim_key]
                self.assertIn(
                    actual, allowed,
                    f"Scenario {i}: {dim_key}={actual} not in {allowed}",
                )

    def test_findings_have_required_fields(self):
        """Generated findings must have all schema-required fields."""
        engine = TriageEngine()
        signals = [
            SignalRecord(
                kind=SignalKind.THREAT_FEED_MATCH,
                evidence_ids=["ev-feed-1"],
                source="feed",
            ),
            SignalRecord(
                kind=SignalKind.COLLECTOR_SUCCESS,
                evidence_ids=["ev-feed-1"],
                source="orchestrator",
            ),
        ]
        result = engine.evaluate(signals)

        required_fields = {
            "finding_id", "kind", "severity", "summary",
            "evidence_ids", "rule_id", "rule_version",
            "created_at", "limitations",
        }

        for finding in result.findings:
            for req_field in required_fields:
                self.assertIn(
                    req_field, finding,
                    f"Finding missing required field: {req_field}",
                )

            # Severity must be valid.
            valid_severities = {"info", "low", "medium", "high", "critical"}
            self.assertIn(finding["severity"], valid_severities)

            # evidence_ids must be non-empty.
            self.assertGreater(len(finding["evidence_ids"]), 0)


# =====================================================================
# Phase 03 Tests: DTOs, Validation, Signal Extraction, and Integration
# =====================================================================


class TestPolicyInputDTOs(unittest.TestCase):
    """Tests for PolicyInput and canonical evidence DTO parsing and immutability."""

    def setUp(self):
        with open(".brain/.testdata/v1/complete_report.json", "r") as f:
            self.complete_dict = json.load(f)

    def test_v1_complete_report_parsing_strict(self):
        """Official complete fixture parses cleanly with strict=True."""
        parsed = PolicyInput.from_v1_dict(self.complete_dict, strict=True)
        self.assertEqual(parsed.scan_id, "fixture-complete-001")
        self.assertEqual(parsed.target, "example.test")
        self.assertEqual(len(parsed.evidence), 1)
        self.assertIsNotNone(parsed.coverage)
        self.assertEqual(parsed.coverage.checks_total, 4)
        self.assertEqual(parsed.coverage.checks_observed, 3)
        self.assertFalse(parsed.coverage.is_aggregate_complete())
        self.assertTrue(parsed.is_valid)

    def test_immutability_guarantees(self):
        """All DTOs enforce dataclass and nested MappingProxyType immutability."""
        parsed = PolicyInput.from_v1_dict(self.complete_dict, strict=True)

        # Dataclass reassignment raises FrozenInstanceError
        with self.assertRaises(FrozenInstanceError):
            parsed.target = "tampered.test"

        ev = parsed.evidence[0]
        with self.assertRaises(FrozenInstanceError):
            ev.status = "tampered"

        # MappingProxyType prevents in-place dictionary mutations
        with self.assertRaises(TypeError):
            parsed.unparsed_fields["new_key"] = "tampered"

        with self.assertRaises(TypeError):
            ev.unparsed_fields["new_key"] = "tampered"

        with self.assertRaises(TypeError):
            ev.value["result"] = "tampered"

    def test_caller_dict_never_mutated(self):
        """Parsing must never mutate caller's input dictionary or nested objects."""
        import copy
        dict_copy = copy.deepcopy(self.complete_dict)
        _ = PolicyInput.from_v1_dict(self.complete_dict, strict=True)
        self.assertEqual(self.complete_dict, dict_copy)

    def test_malformed_evidence_rejected_strict(self):
        """Strict parsing rejects non-string evidence_id or missing fields."""
        import copy
        bad_dict = copy.deepcopy(self.complete_dict)
        bad_dict["evidence"][0]["evidence_id"] = 12345
        with self.assertRaises(PolicyInputParseError) as ctx:
            PolicyInput.from_v1_dict(bad_dict, strict=True)
        self.assertTrue(any("evidence_id" in str(i.path) for i in ctx.exception.issues))

    def test_non_strict_parsing_retains_parse_issues(self):
        """Non-strict mode omits invalid records and populates parse_issues."""
        import copy
        bad_dict = copy.deepcopy(self.complete_dict)
        bad_dict["evidence"][0]["evidence_id"] = 99999
        parsed = PolicyInput.from_v1_dict(bad_dict, strict=False)
        self.assertFalse(parsed.is_valid)
        self.assertGreater(len(parsed.parse_issues), 0)
        self.assertEqual(len(parsed.evidence), 0)

    def test_bare_string_limitations_rejected(self):
        """Bare string for limitations sequence must be rejected."""
        import copy
        bad_dict = copy.deepcopy(self.complete_dict)
        bad_dict["evidence"][0]["limitations"] = "bare string"
        with self.assertRaises(PolicyInputParseError):
            PolicyInput.from_v1_dict(bad_dict, strict=True)

    def test_bare_string_linked_evidence_rejected(self):
        """Bare string for linked_evidence_ids sequence must be rejected."""
        comm_dict = {
            "report_id": "rep-1",
            "normalized_domain": "example.test",
            "claim_type": "phishing",
            "verification_state": "verified",
            "independent_source_count": 2,
            "linked_evidence_ids": "bare_string_id",
        }
        with self.assertRaises(PolicyInputParseError):
            CommunityReportItem.from_dict(comm_dict, strict=True)

    def test_coverage_summary_arithmetic(self):
        """Coverage arithmetic invariant is enforced (total = observed + failed + not_run)."""
        # Arithmetic mismatch: 3 + 2 + 1 != 4
        bad_cov = {
            "checks_total": 4,
            "checks_observed": 3,
            "checks_failed": 2,
            "checks_not_run": 1,
        }
        with self.assertRaises(PolicyInputParseError):
            CoverageSummary.from_dict(bad_cov, strict=True)

    def test_coverage_aggregate_completeness(self):
        """is_aggregate_complete returns True only if observed == total > 0 and failed == not_run == 0."""
        complete_cov = CoverageSummary(checks_total=4, checks_observed=4, checks_failed=0, checks_not_run=0)
        self.assertTrue(complete_cov.is_aggregate_complete())

        partial_cov = CoverageSummary(checks_total=4, checks_observed=3, checks_failed=0, checks_not_run=1)
        self.assertFalse(partial_cov.is_aggregate_complete())

        failed_cov = CoverageSummary(checks_total=4, checks_observed=2, checks_failed=2, checks_not_run=0)
        self.assertFalse(failed_cov.is_aggregate_complete())

    def test_unknown_fields_preserved_isolated(self):
        """Unknown nested and top-level fields are safely isolated into unparsed_fields."""
        import copy
        extra_dict = copy.deepcopy(self.complete_dict)
        extra_dict["custom_flag"] = "top_level_flag"
        extra_dict["evidence"][0]["custom_metric"] = 123.45

        parsed = PolicyInput.from_v1_dict(extra_dict, strict=True)
        self.assertEqual(parsed.unparsed_fields.get("custom_flag"), "top_level_flag")
        self.assertEqual(parsed.evidence[0].unparsed_fields.get("custom_metric"), 123.45)

    def test_target_resolution_and_validation(self):
        """Resolves target from 'target' or 'normalized_host', rejecting blank targets."""
        with_target = {"scan_id": "s-1", "target": "domain.com"}
        p1 = PolicyInput.from_v1_dict(with_target, strict=True)
        self.assertEqual(p1.target, "domain.com")

        with_host = {"scan_id": "s-2", "normalized_host": "domain.com"}
        p2 = PolicyInput.from_v1_dict(with_host, strict=True)
        self.assertEqual(p2.target, "domain.com")

        with_blank = {"scan_id": "s-3", "target": "   "}
        with self.assertRaises(PolicyInputParseError):
            PolicyInput.from_v1_dict(with_blank, strict=True)


class TestInputValidation(unittest.TestCase):
    """Tests for EvidenceValidator rule enforcement and diagnostics generation."""

    def setUp(self):
        self.validator = EvidenceValidator()

    def test_valid_input_passes(self):
        """Well-formed PolicyInput passes validation with zero errors."""
        policy_input = PolicyInput(
            scan_id="scan-001",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-1",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={"is_valid": True, "hostname_match": True, "is_expired": False},
                ),
            ),
        )
        result = self.validator.validate(policy_input)
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.issues), 0)

    def test_duplicate_evidence_ids_flagged(self):
        """Duplicate evidence IDs in evidence batch produce ERROR issue."""
        policy_input = PolicyInput(
            scan_id="scan-002",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-dup",
                    kind="tls_certificate",
                    source="src1",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={},
                ),
                EvidenceItem(
                    evidence_id="ev-dup",
                    kind="dns_resolution",
                    source="src2",
                    observed_at="2026-11-10T08:01:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={},
                ),
            ),
        )
        result = self.validator.validate(policy_input)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(i.code == DiagnosticCode.DUPLICATE_EVIDENCE_ID for i in result.issues))

    def test_invalid_timestamps_flagged(self):
        """Non-ISO or non-UTC timestamps produce validation error."""
        policy_input = PolicyInput(
            scan_id="scan-003",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-time",
                    kind="tls_certificate",
                    source="src1",
                    observed_at="invalid-date-format",
                    status="observed",
                    reliability="direct_observation",
                    value={},
                ),
            ),
        )
        result = self.validator.validate(policy_input)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(i.code == DiagnosticCode.MALFORMED_PAYLOAD for i in result.issues))

    def test_target_scope_mismatch_flagged(self):
        """Payload explicit target mismatch with scan target produces scope warning."""
        policy_input = PolicyInput(
            scan_id="scan-004",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-scope",
                    kind="tls_certificate",
                    source="src1",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={"hostname": "another-different-domain.org"},
                ),
            ),
        )
        result = self.validator.validate(policy_input)
        self.assertTrue(any(d.code == DiagnosticCode.TARGET_SCOPE_MISMATCH for d in result.diagnostics))

    def test_community_report_target_mismatch(self):
        """Community report targeting a different domain produces scope mismatch diagnostic."""
        policy_input = PolicyInput(
            scan_id="scan-005",
            target="example.com",
            scan_profile="standard",
            community_reports=(
                CommunityReportItem(
                    report_id="rep-mismatch",
                    normalized_domain="phish-target.net",
                    claim_type="phishing",
                    verification_state="verified",
                    independent_source_count=2,
                ),
            ),
        )
        result = self.validator.validate(policy_input)
        self.assertTrue(any(d.code == DiagnosticCode.TARGET_SCOPE_MISMATCH for d in result.diagnostics))

    def test_unlinked_community_report_flagged(self):
        """Community report citing non-existent evidence IDs is flagged."""
        policy_input = PolicyInput(
            scan_id="scan-006",
            target="example.com",
            scan_profile="standard",
            community_reports=(
                CommunityReportItem(
                    report_id="rep-unlinked",
                    normalized_domain="example.com",
                    claim_type="phishing",
                    verification_state="verified",
                    independent_source_count=2,
                    linked_evidence_ids=("non_existent_ev_999",),
                ),
            ),
        )
        result = self.validator.validate(policy_input)
        self.assertTrue(any(d.code == DiagnosticCode.UNLINKED_COMMUNITY_REPORT for d in result.diagnostics))


class TestSignalConfidenceAndTaxonomy(unittest.TestCase):
    """Tests for SignalConfidence enum, normalization, and SignalRecord validation."""

    def test_signal_confidence_normalization(self):
        """Ordinal confidence normalizes strings, legacy reliabilities, and enums into the approved six-value design."""
        # Six-value design
        self.assertEqual(normalize_signal_confidence(SignalConfidence.HIGH_CONFIDENCE), SignalConfidence.HIGH_CONFIDENCE)
        self.assertEqual(normalize_signal_confidence(SignalConfidence.OBSERVED), SignalConfidence.OBSERVED)
        self.assertEqual(normalize_signal_confidence(SignalConfidence.CORROBORATED), SignalConfidence.CORROBORATED)
        self.assertEqual(normalize_signal_confidence(SignalConfidence.HEURISTIC), SignalConfidence.HEURISTIC)
        self.assertEqual(normalize_signal_confidence(SignalConfidence.UNVERIFIED), SignalConfidence.UNVERIFIED)
        self.assertEqual(normalize_signal_confidence(SignalConfidence.UNKNOWN), SignalConfidence.UNKNOWN)

        # Legacy normalization
        self.assertEqual(normalize_signal_confidence("direct_observation"), SignalConfidence.OBSERVED)
        self.assertEqual(normalize_signal_confidence("verified_source"), SignalConfidence.HIGH_CONFIDENCE)
        self.assertEqual(normalize_signal_confidence("corroborated"), SignalConfidence.CORROBORATED)
        self.assertEqual(normalize_signal_confidence("heuristic"), SignalConfidence.HEURISTIC)
        self.assertEqual(normalize_signal_confidence("unverified_third_party"), SignalConfidence.UNVERIFIED)
        self.assertEqual(normalize_signal_confidence("untrusted"), SignalConfidence.UNKNOWN)

        # Compatibility aliases
        self.assertEqual(normalize_signal_confidence("high"), SignalConfidence.HIGH)
        self.assertEqual(normalize_signal_confidence("medium"), SignalConfidence.MEDIUM)
        self.assertEqual(normalize_signal_confidence("low"), SignalConfidence.LOW)
        self.assertEqual(normalize_signal_confidence("inferred"), SignalConfidence.INFERRED)

    def test_legacy_confidence_string_compatibility(self):
        """SignalRecord accepts string or SignalConfidence and maintains equality with strings."""
        sig = SignalRecord(
            kind=SignalKind.TLS_VALID,
            evidence_ids=["ev-1"],
            source="test",
            confidence="direct_observation",
        )
        self.assertEqual(sig.confidence_level, SignalConfidence.OBSERVED)
        self.assertEqual(sig.confidence, "direct_observation")
        self.assertEqual(sig.confidence, "direct_observation")

    def test_bare_string_evidence_ids_rejected(self):
        """Passing a bare string instead of a sequence of evidence_ids raises TypeError."""
        with self.assertRaises(TypeError):
            SignalRecord(
                kind=SignalKind.TLS_VALID,
                evidence_ids="ev-1",  # type: ignore[arg-type]
                source="test",
            )

    def test_empty_evidence_id_rejected(self):
        """Empty or blank string within evidence_ids raises ValueError."""
        with self.assertRaises(ValueError):
            SignalRecord(
                kind=SignalKind.TLS_VALID,
                evidence_ids=["ev-1", "  "],
                source="test",
            )


class TestEvidenceSignalExtractor(unittest.TestCase):
    """Tests for deterministic evidence-to-signal extraction rules."""

    def setUp(self):
        self.extractor = EvidenceSignalExtractor()

    def test_tls_certificate_valid_semantics(self):
        """Full TLS certificate observed with valid, matched, and non-expired flags."""
        policy_input = PolicyInput(
            scan_id="s-tls-1",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-tls",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={"is_valid": True, "hostname_match": True, "is_expired": False},
                ),
            ),
        )
        res = self.extractor.extract_signals(policy_input)
        kinds = {s.kind for s in res.signals}
        self.assertIn(SignalKind.TLS_VALID, kinds)
        self.assertIn(SignalKind.TLS_HOSTNAME_MATCH, kinds)
        self.assertIn(SignalKind.COLLECTOR_SUCCESS, kinds)

    def test_tls_certificate_expired(self):
        """Expired TLS certificate emits TLS_EXPIRED."""
        policy_input = PolicyInput(
            scan_id="s-tls-2",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-tls-exp",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={"is_valid": False, "hostname_match": True, "is_expired": True},
                ),
            ),
        )
        res = self.extractor.extract_signals(policy_input)
        kinds = {s.kind for s in res.signals}
        self.assertIn(SignalKind.TLS_EXPIRED, kinds)
        self.assertNotIn(SignalKind.TLS_VALID, kinds)

    def test_tls_certificate_mismatch(self):
        """Hostname mismatched TLS certificate emits TLS_MISMATCH."""
        policy_input = PolicyInput(
            scan_id="s-tls-3",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-tls-mis",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={"is_valid": False, "hostname_match": False, "is_expired": False},
                ),
            ),
        )
        res = self.extractor.extract_signals(policy_input)
        kinds = {s.kind for s in res.signals}
        self.assertIn(SignalKind.TLS_MISMATCH, kinds)
        self.assertNotIn(SignalKind.TLS_HOSTNAME_MATCH, kinds)

    def test_tls_hostname_validation_fixture_semantics(self):
        """Fixture tls_hostname_validation with valid_for_hostname emits ONLY TLS_HOSTNAME_MATCH."""
        policy_input = PolicyInput(
            scan_id="s-tls-fix",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-fix",
                    kind="tls_hostname_validation",
                    source="fixture_adapter",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={"result": "valid_for_hostname"},
                ),
            ),
        )
        res = self.extractor.extract_signals(policy_input)
        kinds = {s.kind for s in res.signals}
        self.assertIn(SignalKind.TLS_HOSTNAME_MATCH, kinds)
        # Invariant: Fixture validation CANNOT independently establish certificate validity or expiry
        self.assertNotIn(SignalKind.TLS_VALID, kinds)
        self.assertNotIn(SignalKind.TLS_EXPIRED, kinds)

    def test_tls_failure_semantics(self):
        """Failed TLS handshake emits TLS_UNAVAILABLE and COLLECTOR_FAILURE."""
        policy_input = PolicyInput(
            scan_id="s-tls-fail",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-fail",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at="2026-11-10T08:00:00Z",
                    status="failed",
                    reliability="direct_observation",
                    value={"error": "handshake_timeout"},
                ),
            ),
        )
        res = self.extractor.extract_signals(policy_input)
        kinds = {s.kind for s in res.signals}
        self.assertIn(SignalKind.TLS_UNAVAILABLE, kinds)
        self.assertIn(SignalKind.COLLECTOR_FAILURE, kinds)

    def test_dns_resolution_observed_and_blocked(self):
        """Observed DNS emits COLLECTOR_SUCCESS; blocked DNS records BLOCKED_DESTINATION_POLICY."""
        policy_input = PolicyInput(
            scan_id="s-dns",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-dns-obs",
                    kind="dns_resolution",
                    source="dns_collector",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={"resolved_ips": ["93.184.216.34"]},
                ),
                EvidenceItem(
                    evidence_id="ev-dns-blk",
                    kind="dns_resolution",
                    source="dns_collector",
                    observed_at="2026-11-10T08:00:01Z",
                    status="blocked",
                    reliability="direct_observation",
                    value={"reason": "ssrf_loopback_blocked"},
                ),
            ),
        )
        res = self.extractor.extract_signals(policy_input)
        kinds = {s.kind for s in res.signals}
        self.assertIn(SignalKind.COLLECTOR_SUCCESS, kinds)
        # Blocked destination is NOT a collector failure!
        self.assertNotIn(SignalKind.COLLECTOR_FAILURE, kinds)
        self.assertTrue(any(d.code == DiagnosticCode.BLOCKED_DESTINATION_POLICY for d in res.diagnostics))

    def test_threat_feed_match_provenance_and_scope(self):
        """Threat intelligence emits THREAT_FEED_MATCH with verified provider, suppressed if untrusted."""
        trusted_input = PolicyInput(
            scan_id="s-threat-1",
            target="evil.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-threat",
                    kind="threat_intelligence",
                    source="phish_feed_alpha",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="verified_source",
                    value={"matched": True, "target": "evil.com"},
                ),
            ),
        )
        res1 = self.extractor.extract_signals(trusted_input)
        kinds1 = {s.kind for s in res1.signals}
        self.assertIn(SignalKind.THREAT_FEED_MATCH, kinds1)

        untrusted_input = PolicyInput(
            scan_id="s-threat-2",
            target="evil.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-threat-untrusted",
                    kind="threat_intelligence",
                    source="random_forum",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="untrusted",
                    value={"matched": True, "target": "evil.com"},
                ),
            ),
        )
        res2 = self.extractor.extract_signals(untrusted_input)
        kinds2 = {s.kind for s in res2.signals}
        self.assertNotIn(SignalKind.THREAT_FEED_MATCH, kinds2)
        self.assertTrue(any(d.code == DiagnosticCode.UNVERIFIED_THREAT_PROVENANCE for d in res2.diagnostics))

    def test_no_threat_match_discipline(self):
        """NO_THREAT_MATCH emitted ONLY on successful negative match, NEVER on failure."""
        negative_input = PolicyInput(
            scan_id="s-neg",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-neg",
                    kind="threat_intelligence",
                    source="reputable_feed",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="reputable_third_party",
                    value={"matched": False, "target": "example.com"},
                ),
            ),
        )
        res1 = self.extractor.extract_signals(negative_input)
        self.assertIn(SignalKind.NO_THREAT_MATCH, {s.kind for s in res1.signals})

        failed_feed_input = PolicyInput(
            scan_id="s-fail-feed",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-fail-feed",
                    kind="threat_intelligence",
                    source="reputable_feed",
                    observed_at="2026-11-10T08:00:00Z",
                    status="failed",
                    reliability="reputable_third_party",
                    value={"error": "api_timeout"},
                ),
            ),
        )
        res2 = self.extractor.extract_signals(failed_feed_input)
        self.assertNotIn(SignalKind.NO_THREAT_MATCH, {s.kind for s in res2.signals})
        self.assertIn(SignalKind.COLLECTOR_FAILURE, {s.kind for s in res2.signals})

    def test_community_report_corroboration(self):
        """Community report requires >= 2 independent source families AND valid linked evidence IDs to corroborate."""
        corroborated_input = PolicyInput(
            scan_id="s-comm-1",
            target="example.com",
            scan_profile="standard",
            community_reports=(
                CommunityReportItem(
                    report_id="rep-corr",
                    normalized_domain="example.com",
                    claim_type="phishing",
                    verification_state="verified",
                    independent_source_count=3,
                    linked_evidence_ids=("ev-linked-1",),
                ),
            ),
        )
        res1 = self.extractor.extract_signals(corroborated_input)
        self.assertIn(SignalKind.COMMUNITY_REPORT_CORROBORATED, {s.kind for s in res1.signals})

        # Strict requirement: >= 2 sources but NO linked evidence IDs must NOT corroborate!
        missing_linked_input = PolicyInput(
            scan_id="s-comm-1b",
            target="example.com",
            scan_profile="standard",
            community_reports=(
                CommunityReportItem(
                    report_id="rep-corr-nolink",
                    normalized_domain="example.com",
                    claim_type="phishing",
                    verification_state="verified",
                    independent_source_count=3,
                    linked_evidence_ids=(),
                ),
            ),
        )
        res1b = self.extractor.extract_signals(missing_linked_input)
        self.assertNotIn(SignalKind.COMMUNITY_REPORT_CORROBORATED, {s.kind for s in res1b.signals})
        self.assertIn(SignalKind.COMMUNITY_REPORT_UNVERIFIED, {s.kind for s in res1b.signals})

        unverified_input = PolicyInput(
            scan_id="s-comm-2",
            target="example.com",
            scan_profile="standard",
            community_reports=(
                CommunityReportItem(
                    report_id="rep-unver",
                    normalized_domain="example.com",
                    claim_type="phishing",
                    verification_state="unverified",
                    independent_source_count=1,
                ),
            ),
        )
        res2 = self.extractor.extract_signals(unverified_input)
        self.assertIn(SignalKind.COMMUNITY_REPORT_UNVERIFIED, {s.kind for s in res2.signals})

    def test_unsupported_evidence_kind_diagnostic(self):
        """Unsupported evidence kinds emit diagnostic without fabricating signals."""
        policy_input = PolicyInput(
            scan_id="s-unsup",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-unknown",
                    kind="unsupported_exotic_collector",
                    source="experimental",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={"custom_payload": 123},
                ),
            ),
        )
        res = self.extractor.extract_signals(policy_input)
        self.assertEqual(len(res.signals), 0)
        self.assertTrue(any(d.code == DiagnosticCode.UNSUPPORTED_EVIDENCE_KIND for d in res.diagnostics))


class TestDeterministicFindingIDs(unittest.TestCase):
    """Tests for canonical JSON SHA-256 deterministic finding ID generation."""

    def test_permutation_invariance(self):
        """Evidence IDs in differing orders produce identical finding IDs."""
        id1 = generate_deterministic_finding_id(
            scan_id="scan-001",
            rule_id="RULE-BEH-001",
            evidence_ids=["ev-a", "ev-b", "ev-c"],
        )
        id2 = generate_deterministic_finding_id(
            scan_id="scan-001",
            rule_id="RULE-BEH-001",
            evidence_ids=["ev-c", "ev-a", "ev-b"],
        )
        self.assertEqual(id1, id2)

    def test_cross_scan_separation(self):
        """Identical rules and evidence on different scans produce different IDs."""
        id_scan1 = generate_deterministic_finding_id(
            scan_id="scan-001",
            rule_id="RULE-CERT-001",
            evidence_ids=["ev-1"],
        )
        id_scan2 = generate_deterministic_finding_id(
            scan_id="scan-002",
            rule_id="RULE-CERT-001",
            evidence_ids=["ev-1"],
        )
        self.assertNotEqual(id_scan1, id_scan2)

    def test_full_sha256_format(self):
        """Finding IDs use 'finding-' prefix followed by 64 hex characters."""
        fid = generate_deterministic_finding_id(
            scan_id="scan-demo",
            rule_id="RULE-01",
            evidence_ids=["ev-1"],
        )
        self.assertTrue(fid.startswith("finding-"))
        hex_digest = fid.split("-", 1)[1]
        self.assertEqual(len(hex_digest), 64)
        int(hex_digest, 16)  # Validates hex string


class TestTriageEvidenceIntegration(unittest.TestCase):
    """End-to-end tests for TriageEngine.evaluate_evidence()."""

    def setUp(self):
        self.engine = TriageEngine()
        with open(".brain/.testdata/v1/complete_report.json", "r") as f:
            self.fixture = json.load(f)

    def test_evaluate_evidence_complete_fixture(self):
        """Complete official fixture evaluates through the end-to-end evidence bridge."""
        policy_input = PolicyInput.from_v1_dict(self.fixture, strict=True)
        res = self.engine.evaluate_evidence(policy_input)
        self.assertIsInstance(res, TriageResult)
        self.assertIn(res.decision, ("caution", "inconclusive", "no_threat_observed"))
        # Invariant: tls_hostname_validation emits TLS_HOSTNAME_MATCH (identity=unverified).
        # It does NOT establish certificate validity, so certificate dimension remains 'not_checked'.
        self.assertEqual(res.dimensions["certificate"], "not_checked")
        self.assertEqual(res.dimensions["identity"], "unverified")

    def test_evaluate_evidence_orphan_finding_suppressed(self):
        """Findings referencing non-existent evidence IDs are suppressed with audit diagnostics."""
        # Signal cites unknown evidence ID 'ghost-ev-999' not present in policy_input.evidence
        policy_input = PolicyInput(
            scan_id="scan-orphan-test",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="real-ev-1",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={"is_valid": False, "is_expired": True, "hostname_match": True},
                ),
            ),
        )
        # Directly inject an orphan signal to test suppression logic
        orphan_sig = SignalRecord(
            kind=SignalKind.THREAT_FEED_MATCH,
            evidence_ids=["ghost-ev-999"],
            source="spoofed_source",
        )
        # Verify that if a rule generated a finding with ghost-ev-999, evaluate_evidence suppresses it
        class SpoofedEngine(TriageEngine):
            def evaluate(self, signals, scan_id=None):
                base = super().evaluate(signals, scan_id=scan_id)
                # Inject an orphan finding
                base.findings.append({
                    "finding_id": "finding-orphan",
                    "kind": "threat_feed_match",
                    "severity": "high",
                    "summary": "Ghost finding",
                    "evidence_ids": ["ghost-ev-999"],
                    "rule_id": "RULE-BEH-001",
                    "rule_version": "1.0",
                })
                return base

        spoofed_engine = SpoofedEngine()
        res = spoofed_engine.evaluate_evidence(policy_input)
        self.assertEqual(len(res.findings), 1)  # Only the certificate issue from real-ev-1
        self.assertEqual(res.findings[0]["kind"], "certificate_issue")
        self.assertTrue(any(d.code == DiagnosticCode.ORPHAN_FINDING_SUPPRESSED for d in res.diagnostics))

    def test_evaluate_evidence_invalid_input_quarantined(self):
        """Input with unresolved parse issues is safely quarantined without execution."""
        bad_dict = {"scan_id": "", "target": ""}
        bad_input = PolicyInput.from_v1_dict(bad_dict, strict=False)
        self.assertFalse(bad_input.is_valid)

        res = self.engine.evaluate_evidence(bad_input)
        self.assertEqual(res.decision, "inconclusive")
        self.assertEqual(res.dimensions["evidence_quality"], "unavailable")
        self.assertEqual(len(res.findings), 0)

    def test_evaluate_evidence_positive_threat_non_erasure(self):
        """Valid positive threat evidence is NOT erased by an unrelated collector failure."""
        threat_with_dns_failure = PolicyInput(
            scan_id="scan-non-erasure",
            target="malicious.test",
            scan_profile="standard",
            evidence=(
                # Positive threat feed match
                EvidenceItem(
                    evidence_id="ev-threat-pos",
                    kind="threat_intelligence",
                    source="verified_threat_feed",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="verified_source",
                    value={"matched": True, "target": "malicious.test"},
                ),
                # Unrelated DNS collector failure
                EvidenceItem(
                    evidence_id="ev-dns-fail",
                    kind="dns_resolution",
                    source="dns_collector",
                    observed_at="2026-11-10T08:00:01Z",
                    status="failed",
                    reliability="direct_observation",
                    value={"error": "timeout"},
                ),
            ),
        )
        res = self.engine.evaluate_evidence(threat_with_dns_failure)
        # Decision must remain high_risk; positive threat is not erased!
        self.assertEqual(res.decision, "high_risk")
        self.assertEqual(res.dimensions["behavior"], "malicious_evidence")
        self.assertTrue(any(f["kind"] == "threat_feed_match" for f in res.findings))

    def test_evaluate_evidence_partial_coverage_limitation(self):
        """Partial coverage appends an explicit limitation to the triage result."""
        policy_input = PolicyInput(
            scan_id="scan-partial-cov",
            target="example.com",
            scan_profile="standard",
            coverage=CoverageSummary(checks_total=4, checks_observed=2, checks_failed=1, checks_not_run=1),
            evidence=(
                EvidenceItem(
                    evidence_id="ev-1",
                    kind="dns_resolution",
                    source="dns_collector",
                    observed_at="2026-11-10T08:00:00Z",
                    status="observed",
                    reliability="direct_observation",
                    value={"resolved_ips": ["1.2.3.4"]},
                ),
            ),
        )
        res = self.engine.evaluate_evidence(policy_input)
        self.assertTrue(any("Coverage is partial" in lim for lim in res.limitations))

    def test_evaluate_evidence_all_collectors_failed(self):
        """When all collectors fail, decision is inconclusive and quality unavailable."""
        all_failed_input = PolicyInput(
            scan_id="scan-all-fail",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-tls-f",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at="2026-11-10T08:00:00Z",
                    status="failed",
                    reliability="direct_observation",
                    value={"error": "timeout"},
                ),
                EvidenceItem(
                    evidence_id="ev-dns-f",
                    kind="dns_resolution",
                    source="dns_collector",
                    observed_at="2026-11-10T08:00:01Z",
                    status="failed",
                    reliability="direct_observation",
                    value={"error": "nxdomain"},
                ),
            ),
        )
        res = self.engine.evaluate_evidence(all_failed_input)
        self.assertEqual(res.decision, "inconclusive")
        self.assertEqual(res.dimensions["evidence_quality"], "unavailable")

    def test_evaluate_evidence_populates_uncertainty_assessment(self):
        """Phase 04: evaluate_evidence populates uncertainty assessment and ordinal band."""
        policy_input = PolicyInput.from_v1_dict(self.fixture, strict=True)
        res = self.engine.evaluate_evidence(policy_input)
        self.assertIsNotNone(res.uncertainty)
        self.assertIsInstance(res.uncertainty, UncertaintyAssessment)
        self.assertIn(res.uncertainty.confidence_band, tuple(ConfidenceBand))

    def test_evaluate_evidence_inconclusive_embeds_abstention_limitation(self):
        """Phase 04: Inconclusive triage result embeds explicit abstention notice in limitations."""
        all_failed_input = PolicyInput(
            scan_id="scan-all-fail-abstain",
            target="example.com",
            scan_profile="standard",
            evidence=(
                EvidenceItem(
                    evidence_id="ev-tls-f",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at="2026-11-10T08:00:00Z",
                    status="failed",
                    reliability="direct_observation",
                    value={"error": "timeout"},
                ),
            ),
        )
        res = self.engine.evaluate_evidence(all_failed_input)
        self.assertEqual(res.decision, "inconclusive")
        self.assertIsNotNone(res.uncertainty)
        self.assertIsNotNone(res.uncertainty.abstention_notice)
        self.assertEqual(res.uncertainty.abstention_notice.reason_code, "ABSTAIN_COLLECTION_FAILURE")
        # Notice must appear in user-facing limitations without schema breach
        self.assertTrue(any("abstained" in lim.lower() for lim in res.limitations))

    def test_audit_triage_result_pipeline(self):
        """Phase 04: TriageEngine.audit_triage_result validates clean result before report publication."""
        policy_input = PolicyInput.from_v1_dict(self.fixture, strict=True)
        res = self.engine.evaluate_evidence(policy_input)
        audit_res = self.engine.audit_triage_result(res, policy_input)
        self.assertTrue(audit_res.is_valid)
        self.assertEqual(audit_res.error_count, 0)

    def test_to_report_fragment_strict_v1_compatibility(self):
        """Phase 04: to_report_fragment maintains strict additionalProperties: false compatibility."""
        policy_input = PolicyInput.from_v1_dict(self.fixture, strict=True)
        res = self.engine.evaluate_evidence(policy_input)
        frag = res.to_report_fragment()
        # Exactly the 5 approved keys
        self.assertEqual(
            set(frag.keys()),
            {"decision", "policy_version", "dimensions", "findings", "limitations"},
        )
        # No unapproved internal uncertainty or diagnostic fields leaked into v1 fragment
        self.assertNotIn("uncertainty", frag)
        self.assertNotIn("diagnostics", frag)
        self.assertNotIn("rule_trace", frag)


class TestUncertaintyTaxonomy(unittest.TestCase):
    """Tests for Worker 03 Phase 04 Uncertainty quantification and abstention engine."""

    def setUp(self):
        self.engine = UncertaintyEngine()

    def test_uncertainty_types_and_confidence_bands(self):
        """Verify all 5 uncertainty types and 4 ordinal confidence bands exist."""
        self.assertEqual(len(UncertaintyType), 5)
        self.assertEqual(UncertaintyType.DATA_ABSENCE.value, "data_absence")
        self.assertEqual(UncertaintyType.COLLECTION_FAILURE.value, "collection_failure")
        self.assertEqual(UncertaintyType.UNCHECKED_COVERAGE.value, "unchecked_coverage")
        self.assertEqual(UncertaintyType.TEMPORAL_STALENESS.value, "temporal_staleness")
        self.assertEqual(UncertaintyType.EVIDENCE_CONFLICT.value, "evidence_conflict")

        self.assertEqual(len(ConfidenceBand), 4)
        self.assertEqual(ConfidenceBand.SUFFICIENT_FOR_SCOPED_OBSERVATION.value, "sufficient_for_scoped_observation")
        self.assertEqual(ConfidenceBand.LIMITED_OBSERVATION.value, "limited_observation")
        self.assertEqual(ConfidenceBand.INSUFFICIENT_EVIDENCE.value, "insufficient_evidence")
        self.assertEqual(ConfidenceBand.CONTRADICTORY_EVIDENCE.value, "contradictory_evidence")

    def test_freshness_policy_defaults_and_evaluation(self):
        """Source-specific freshness windows accurately classify fresh vs stale timestamps."""
        policy = FreshnessPolicy()
        # DNS default is 24h (86400s); TLS is 7 days (604800s); threat_intel is 12h (43200s)
        self.assertEqual(policy.get_window("dns_resolution"), 86400)
        self.assertEqual(policy.get_window("tls_certificate"), 604800)
        self.assertEqual(policy.get_window("threat_feed"), 43200)

        # 1-hour old DNS observation is fresh
        now = datetime.now(timezone.utc)
        fresh_ts = (now - timedelta(seconds=3600)).isoformat().replace("+00:00", "Z")
        is_stale, age, win = policy.evaluate_freshness("dns_resolution", fresh_ts, now_dt=now)
        self.assertFalse(is_stale)
        self.assertAlmostEqual(age, 3600, delta=10)

        # 48-hour old DNS observation is stale (window 24h)
        stale_ts = (now - timedelta(hours=48)).isoformat().replace("+00:00", "Z")
        is_stale, age, win = policy.evaluate_freshness("dns_resolution", stale_ts, now_dt=now)
        self.assertTrue(is_stale)
        self.assertGreater(age, 86400)

    def test_uncertainty_clean_observation(self):
        """Successful observation across checks yields SUFFICIENT_FOR_SCOPED_OBSERVATION."""
        policy_input = PolicyInput(
            scan_id="scan-clean",
            target="example.com",
            scan_profile="standard",
            coverage=CoverageSummary(checks_total=2, checks_observed=2, checks_failed=0, checks_not_run=0),
            evidence=(
                EvidenceItem(
                    evidence_id="ev-tls",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    status="observed",
                    reliability="direct_observation",
                    value={"is_valid": True, "hostname_match": True, "is_expired": False},
                ),
            ),
        )
        signals = [
            SignalRecord(kind=SignalKind.TLS_VALID, evidence_ids=["ev-tls"], source="tls_collector"),
            SignalRecord(kind=SignalKind.COLLECTOR_SUCCESS, evidence_ids=["ev-tls"], source="tls_collector"),
        ]
        dimensions = {"certificate": "valid_for_hostname", "identity": "unverified", "behavior": "no_threat_observed", "evidence_quality": "strong"}
        assessment = self.engine.assess_evidence(policy_input, signals, "no_threat_observed", dimensions)
        self.assertEqual(assessment.confidence_band, ConfidenceBand.SUFFICIENT_FOR_SCOPED_OBSERVATION)
        self.assertIsNone(assessment.abstention_notice)

    def test_uncertainty_collection_failure(self):
        """Failed collector emits COLLECTION_FAILURE and caps confidence band at LIMITED_OBSERVATION."""
        policy_input = PolicyInput(
            scan_id="scan-fail",
            target="example.com",
            scan_profile="standard",
            coverage=CoverageSummary(checks_total=2, checks_observed=1, checks_failed=1, checks_not_run=0),
            evidence=(
                EvidenceItem(
                    evidence_id="ev-tls-ok",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    status="observed",
                    reliability="direct_observation",
                    value={"is_valid": True},
                ),
                EvidenceItem(
                    evidence_id="ev-dns",
                    kind="dns_resolution",
                    source="dns_collector",
                    observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    status="failed",
                    reliability="direct_observation",
                    value={"error": "timeout"},
                ),
            ),
        )
        signals = [
            SignalRecord(kind=SignalKind.COLLECTOR_SUCCESS, evidence_ids=["ev-tls-ok"], source="tls_collector"),
            SignalRecord(kind=SignalKind.COLLECTOR_FAILURE, evidence_ids=["ev-dns"], source="dns_collector"),
        ]
        dimensions = {"certificate": "not_checked", "identity": "unknown", "behavior": "unknown", "evidence_quality": "partial"}
        assessment = self.engine.assess_evidence(policy_input, signals, "caution", dimensions)
        self.assertEqual(assessment.confidence_band, ConfidenceBand.LIMITED_OBSERVATION)
        self.assertTrue(any(u.uncertainty_type == UncertaintyType.COLLECTION_FAILURE for u in assessment.uncertainties))

    def test_uncertainty_unchecked_coverage(self):
        """Blocked or not run checks emit UNCHECKED_COVERAGE uncertainty."""
        policy_input = PolicyInput(
            scan_id="scan-block",
            target="private.corp",
            scan_profile="standard",
            coverage=CoverageSummary(checks_total=3, checks_observed=1, checks_failed=0, checks_not_run=2),
            evidence=(
                EvidenceItem(
                    evidence_id="ev-block",
                    kind="http_headers",
                    source="http_collector",
                    observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    status="blocked",
                    reliability="direct_observation",
                    value={"reason": "private_network"},
                ),
            ),
        )
        signals = [
            SignalRecord(kind=SignalKind.COLLECTOR_SUCCESS, evidence_ids=["ev-block"], source="http_collector"),
        ]
        dimensions = {"certificate": "not_checked", "identity": "unknown", "behavior": "unknown", "evidence_quality": "partial"}
        assessment = self.engine.assess_evidence(policy_input, signals, "inconclusive", dimensions)
        self.assertTrue(any(u.uncertainty_type == UncertaintyType.UNCHECKED_COVERAGE for u in assessment.uncertainties))
        self.assertEqual(assessment.confidence_band, ConfidenceBand.LIMITED_OBSERVATION)
        self.assertIsNotNone(assessment.abstention_notice)
        self.assertEqual(assessment.abstention_notice.reason_code, "ABSTAIN_UNCHECKED_COVERAGE")

    def test_uncertainty_evidence_conflict(self):
        """Opposing contemporaneous signals emit EVIDENCE_CONFLICT and CONTRADICTORY_EVIDENCE band."""
        signals = [
            SignalRecord(kind=SignalKind.THREAT_FEED_MATCH, evidence_ids=["ev-feed-1"], source="feed_alpha"),
            SignalRecord(kind=SignalKind.NO_THREAT_MATCH, evidence_ids=["ev-feed-2"], source="feed_beta"),
        ]
        dimensions = {"certificate": "not_checked", "identity": "unknown", "behavior": "unknown", "evidence_quality": "partial"}
        assessment = self.engine.assess_signals(signals, "inconclusive", dimensions, target_scope="disputed.site")
        self.assertEqual(assessment.confidence_band, ConfidenceBand.CONTRADICTORY_EVIDENCE)
        self.assertIsNotNone(assessment.abstention_notice)
        self.assertEqual(assessment.abstention_notice.reason_code, "ABSTAIN_EVIDENCE_CONFLICT")
        self.assertTrue(assessment.abstention_notice.is_rescan_recommended)
        self.assertIn("material evidence conflict", assessment.abstention_notice.explanation)

    def test_abstention_notice_serialization(self):
        """AbstentionNotice serializes to dict with all canonical fields."""
        notice = AbstentionNotice(
            reason_code="ABSTAIN_TEST",
            affected_dimensions=("identity", "behavior"),
            missing_or_failed_checks=("dns", "tls"),
            target_scope="example.com",
            is_rescan_recommended=True,
            explanation="Test explanation.",
        )
        d = notice.to_dict()
        self.assertEqual(d["reason_code"], "ABSTAIN_TEST")
        self.assertEqual(d["affected_dimensions"], ["identity", "behavior"])
        self.assertEqual(d["missing_or_failed_checks"], ["dns", "tls"])
        self.assertEqual(d["target_scope"], "example.com")
        self.assertTrue(d["is_rescan_recommended"])
        self.assertEqual(d["explanation"], "Test explanation.")


class TestReportIntegrityAuditor(unittest.TestCase):
    """Tests for Worker 03 Phase 04 ReportIntegrityAuditor core safety invariants."""

    def setUp(self):
        self.auditor = ReportIntegrityAuditor()

    def test_rule_1_tls_001_supported_identity_without_authorization_rejected(self):
        """INV-TLS-001: identity='supported' without explicit authorization evidence is rejected."""
        report = {
            "dimensions": {"identity": "supported", "certificate": "valid_for_hostname"},
            "evidence": [
                {"evidence_id": "ev-1", "kind": "tls_certificate", "status": "observed"}
            ],
            "findings": [],
        }
        res = self.auditor.audit_report(report)
        self.assertFalse(res.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.TLS_001.value for i in res.issues))

    def test_rule_1_tls_001_supported_identity_with_authorization_accepted(self):
        """INV-TLS-001: identity='supported' with valid authorization evidence passes."""
        report = {
            "dimensions": {"identity": "supported", "certificate": "valid_for_hostname"},
            "evidence": [
                {"evidence_id": "ev-auth", "kind": "brand_authorization", "status": "observed"}
            ],
            "findings": [
                {"finding_id": "f-1", "evidence_ids": ["ev-auth"]}
            ],
        }
        res = self.auditor.audit_report(report)
        self.assertTrue(res.is_valid)

    def test_rule_2_evid_002_affirmative_global_safety_claim_rejected(self):
        """INV-EVID-002: Affirmative global safety assertion fails audit."""
        # Test prohibited decision value
        bad_decision = {"decision": "safe", "findings": [], "limitations": []}
        res1 = self.auditor.audit_report(bad_decision)
        self.assertFalse(res1.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.EVID_002.value for i in res1.issues))

        # Test affirmative claim in finding summary
        bad_finding = {
            "decision": "no_threat_observed",
            "findings": [{"finding_id": "f-1", "summary": "This site is safe and clean.", "evidence_ids": ["ev-1"]}],
            "evidence": [{"evidence_id": "ev-1", "kind": "dns", "status": "observed"}],
        }
        res2 = self.auditor.audit_report(bad_finding)
        self.assertFalse(res2.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.EVID_002.value for i in res2.issues))

    def test_rule_2_evid_002_negated_disclaimer_accepted(self):
        """INV-EVID-002: Negated educational text and disclaimers are accepted."""
        clean_report = {
            "decision": "no_threat_observed",
            "findings": [
                {
                    "finding_id": "f-1",
                    "summary": "Absence of threat feed match is not proof of safety (EVID-002).",
                    "evidence_ids": ["ev-1"],
                }
            ],
            "limitations": [
                "No reputation match -> never 'safe'; at most no_threat_observed.",
                "Does not establish that the site is safe.",
            ],
            "evidence": [{"evidence_id": "ev-1", "kind": "threat_intel", "status": "observed"}],
        }
        res = self.auditor.audit_report(clean_report)
        self.assertTrue(res.is_valid)

    def test_rule_3_coverage_unqualified_no_threat_rejected(self):
        """INV-COV-001: no_threat_observed under partial coverage without disclosure is rejected."""
        report = {
            "decision": "no_threat_observed",
            "dimensions": {"evidence_quality": "strong"},
            "coverage": {"checks_total": 4, "checks_observed": 2, "checks_failed": 2, "checks_not_run": 0},
            "limitations": [],  # Missing required partial coverage disclosure!
            "findings": [],
        }
        res = self.auditor.audit_report(report)
        self.assertFalse(res.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.COV_001.value for i in res.issues))

    def test_rule_3_coverage_qualified_no_threat_accepted(self):
        """INV-COV-001: no_threat_observed with explicit partial coverage disclosure passes."""
        report = {
            "decision": "no_threat_observed",
            "dimensions": {"evidence_quality": "partial"},
            "coverage": {"checks_total": 4, "checks_observed": 2, "checks_failed": 2, "checks_not_run": 0},
            "limitations": ["Coverage is partial: 2 checks failed out of 4 total."],
            "findings": [],
        }
        res = self.auditor.audit_report(report)
        self.assertTrue(res.is_valid)

    def test_rule_4_anti_marketing_absolute_claims_rejected(self):
        """INV-CLAIM-001: Unsupported absolute marketing assertions ('100% secure', 'bulletproof') are rejected."""
        report = {
            "decision": "caution",
            "findings": [
                {
                    "finding_id": "f-1",
                    "summary": "This domain features 100% secure infrastructure with zero false positives.",
                    "evidence_ids": ["ev-1"],
                }
            ],
            "evidence": [{"evidence_id": "ev-1", "kind": "dns", "status": "observed"}],
        }
        res = self.auditor.audit_report(report)
        self.assertFalse(res.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.CLAIM_001.value for i in res.issues))

    def test_rule_4_anti_marketing_negated_claim_accepted(self):
        """INV-CLAIM-001: Negated marketing assertions are permitted."""
        report = {
            "decision": "caution",
            "findings": [
                {
                    "finding_id": "f-1",
                    "summary": "Heuristic detection cannot guarantee 100% security or zero false positives.",
                    "evidence_ids": ["ev-1"],
                }
            ],
            "evidence": [{"evidence_id": "ev-1", "kind": "dns", "status": "observed"}],
        }
        res = self.auditor.audit_report(report)
        self.assertTrue(res.is_valid)

    def test_rule_5_finding_integrity_empty_evidence_ids_rejected(self):
        """INV-FINDING-001: Finding with empty evidence_ids is rejected."""
        report = {
            "decision": "caution",
            "findings": [{"finding_id": "f-empty", "summary": "Empty finding", "evidence_ids": []}],
        }
        res = self.auditor.audit_report(report)
        self.assertFalse(res.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.FINDING_001.value for i in res.issues))

    def test_rule_5_finding_integrity_orphan_evidence_id_rejected(self):
        """INV-FINDING-001: Finding referencing undeclared evidence ID is rejected."""
        report = {
            "decision": "caution",
            "evidence": [{"evidence_id": "ev-real", "kind": "dns", "status": "observed"}],
            "findings": [{"finding_id": "f-orphan", "summary": "Orphan finding", "evidence_ids": ["ev-ghost"]}],
        }
        res = self.auditor.audit_report(report)
        self.assertFalse(res.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.FINDING_001.value for i in res.issues))

    def test_rule_5_finding_integrity_valid_references_accepted(self):
        """INV-FINDING-001: Finding referencing declared evidence IDs is accepted."""
        report = {
            "decision": "caution",
            "evidence": [{"evidence_id": "ev-real", "kind": "dns", "status": "observed"}],
            "findings": [{"finding_id": "f-valid", "summary": "Valid finding", "evidence_ids": ["ev-real"]}],
        }
        res = self.auditor.audit_report(report)
        self.assertTrue(res.is_valid)

    def test_rule_6_coverage_arithmetic_mismatch_rejected(self):
        """INV-COV-002: Coverage arithmetic mismatch is rejected."""
        report = {
            "decision": "caution",
            "coverage": {"checks_total": 10, "checks_observed": 5, "checks_failed": 2, "checks_not_run": 1},  # Sum = 8 != 10
            "findings": [],
        }
        res = self.auditor.audit_report(report)
        self.assertFalse(res.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.COV_002.value for i in res.issues))

    def test_rule_6_coverage_arithmetic_valid_accepted(self):
        """INV-COV-002: Valid coverage arithmetic passes."""
        report = {
            "decision": "caution",
            "coverage": {"checks_total": 10, "checks_observed": 7, "checks_failed": 2, "checks_not_run": 1},  # Sum = 10 == 10
            "findings": [],
        }
        res = self.auditor.audit_report(report)
        self.assertTrue(res.is_valid)

    def test_audit_complete_official_fixture(self):
        """Full official fixture passes ReportIntegrityAuditor cleanly."""
        with open(".brain/.testdata/v1/complete_report.json", "r") as f:
            fixture = json.load(f)
        res = self.auditor.audit_report(fixture)
        self.assertTrue(res.is_valid, f"Official fixture failed integrity audit: {res.issues}")

    def test_audit_report_non_dict_rejected(self):
        """ReportIntegrityAuditor safely rejects non-dict inputs without raising uncaught exceptions."""
        res = self.auditor.audit_report("not-a-dict")  # type: ignore[arg-type]
        self.assertFalse(res.is_valid)
        self.assertEqual(res.error_count, 1)
        self.assertEqual(res.issues[0].rule_id, "MALFORMED_REPORT")

    def test_audit_report_none_values_resilient(self):
        """ReportIntegrityAuditor safely handles None values within report keys."""
        report = {
            "dimensions": None,
            "findings": None,
            "limitations": None,
            "coverage": None,
            "evidence": None,
        }
        res = self.auditor.audit_report(report)
        self.assertTrue(res.is_valid)

    def test_audit_report_malformed_findings_list_handled(self):
        """ReportIntegrityAuditor flags non-dict findings gracefully without crashing."""
        report = {
            "findings": ["invalid-finding-string", None],
            "limitations": [123, None],
        }
        res = self.auditor.audit_report(report)
        self.assertFalse(res.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.FINDING_001.value for i in res.issues))


class Worker03IntegrationRemediationTests(unittest.TestCase):
    """Regression tests for Worker 03 integration interfaces and cross-worker interop."""

    def test_signal_record_clear_error_message_on_bare_string_evidence_id(self):
        """SignalRecord raises TypeError with clear guidance when evidence_ids is a bare string."""
        with self.assertRaises(TypeError) as ctx:
            SignalRecord(SignalKind.TLS_VALID, "tls_collector", "Valid DV Cert by Let's Encrypt")  # type: ignore[arg-type]
        self.assertIn("bare string", str(ctx.exception))
        self.assertIn("order is (kind, evidence_ids, source, ...)", str(ctx.exception))

    def test_signal_record_create_factory(self):
        """SignalRecord.create provides a safe named-parameter constructor."""
        sig1 = SignalRecord.create(
            kind=SignalKind.TLS_VALID,
            source="tls_collector",
            evidence_ids="ev-tls-001",
            value="Valid Let's Encrypt cert",
        )
        self.assertEqual(sig1.evidence_ids, ["ev-tls-001"])
        self.assertEqual(sig1.source, "tls_collector")
        self.assertEqual(sig1.kind, SignalKind.TLS_VALID)

        sig2 = SignalRecord.create(
            kind=SignalKind.TLS_HOSTNAME_MATCH,
            source="tls_collector",
            evidence_ids=["ev-tls-001", "ev-dns-001"],
        )
        self.assertEqual(sig2.evidence_ids, ["ev-tls-001", "ev-dns-001"])

    def test_policy_input_accepts_worker_02_evidence_and_coverage_models(self):
        """PolicyInput seamlessly accepts Worker 02 EvidenceModel and CoverageModel instances."""
        from trusttrace.evidence.domain.models import EvidenceModel, CoverageModel
        from trusttrace.evidence.domain.enums import EvidenceStatus, Reliability

        ev = EvidenceModel(
            evidence_id="ev-w02-test-01",
            scan_id="scan-rem-001",
            kind="tls_certificate",
            value={"is_valid": True, "hostname_match": True},
            source="tls_collector",
            observed_at="2026-11-10T00:00:00Z",
            status=EvidenceStatus.OBSERVED,
            reliability=Reliability.DIRECT_OBSERVATION,
            limitations=["Technical hygiene only"],
        )
        cov = CoverageModel(
            checks_total=4,
            checks_observed=4,
            checks_failed=0,
            checks_not_run=0,
        )

        # 1. Via from_components
        inp = PolicyInput.from_components(
            scan_id="scan-rem-001",
            target="example.com",
            evidence=[ev],
            coverage=cov,
        )
        self.assertTrue(inp.is_valid)
        self.assertEqual(len(inp.evidence), 1)
        self.assertEqual(inp.evidence[0].evidence_id, "ev-w02-test-01")
        self.assertIsNotNone(inp.coverage)
        self.assertEqual(inp.coverage.checks_total, 4)
        self.assertTrue(inp.coverage.is_aggregate_complete())

        # 2. Via from_v1_dict with nested models
        inp2 = PolicyInput.from_v1_dict(
            {
                "scan_id": "scan-rem-002",
                "target": "example.com",
                "evidence": [ev],
                "coverage": cov,
            }
        )
        self.assertTrue(inp2.is_valid)
        self.assertEqual(inp2.evidence[0].source, "tls_collector")

    def test_triage_engine_evaluate_evidence_accepts_dict_and_models(self):
        """TriageEngine.evaluate_evidence accepts PolicyInput, canonical dicts, or components."""
        from trusttrace.evidence.domain.models import EvidenceModel, CoverageModel
        from trusttrace.evidence.domain.enums import EvidenceStatus, Reliability

        ev = EvidenceModel(
            evidence_id="ev-rem-tls-01",
            kind="tls_certificate",
            value={"is_valid": True, "hostname_match": True},
            source="tls_collector",
            observed_at="2026-11-10T00:00:00Z",
            status=EvidenceStatus.OBSERVED,
            reliability=Reliability.DIRECT_OBSERVATION,
        )
        cov = CoverageModel(
            checks_total=4,
            checks_observed=1,
            checks_failed=0,
            checks_not_run=3,
        )

        engine = TriageEngine()

        # Evaluate directly from dict containing models
        res = engine.evaluate_evidence({
            "scan_id": "scan-e2e-001",
            "target": "safe-test.corp",
            "evidence": [ev],
            "coverage": cov,
        })

        self.assertIsInstance(res, TriageResult)
        self.assertEqual(res.dimensions["certificate"], "valid_for_hostname")
        self.assertEqual(res.dimensions["identity"], "unverified")  # TLS-001 preserved
        self.assertEqual(res.decision, "inconclusive")
        self.assertIsNotNone(res.uncertainty)
        self.assertIsNotNone(res.uncertainty.abstention_notice)

    def test_full_worker_02_worker_03_pipeline_with_integrity_audit(self):
        """Verify complete pipeline execution from Worker 02 models through triage and audit."""
        from trusttrace.evidence.domain.models import EvidenceModel, CoverageModel
        from trusttrace.evidence.domain.enums import EvidenceStatus, Reliability

        ev1 = EvidenceModel(
            evidence_id="ev-pipe-tls-01",
            kind="tls_certificate",
            value={"is_valid": True, "hostname_match": True},
            source="tls_collector",
            observed_at="2026-11-10T00:00:00Z",
            status=EvidenceStatus.OBSERVED,
            reliability=Reliability.DIRECT_OBSERVATION,
        )
        cov = CoverageModel(
            checks_total=4,
            checks_observed=4,
            checks_failed=0,
            checks_not_run=0,
        )

        policy_input = PolicyInput.from_components(
            scan_id="scan-full-001",
            target="audited-target.com",
            evidence=[ev1],
            coverage=cov,
        )

        engine = TriageEngine()
        triage_result = engine.evaluate_evidence(policy_input)

        # Audit candidate report via auditor
        audit_res = engine.audit_triage_result(triage_result, policy_input=policy_input)
        self.assertTrue(audit_res.is_valid)
        self.assertEqual(audit_res.error_count, 0)

    def test_malformed_and_missing_evidence_resilience(self):
        """Malformed evidence items in non-strict mode are quarantined without uncaught exception."""
        malformed_raw = {
            "scan_id": "scan-malformed-001",
            "target": "example.org",
            "evidence": [
                {"evidence_id": 12345, "kind": "broken_id"},  # non-string evidence_id
                "not-even-a-dict",  # non-dict item
            ],
        }
        inp = PolicyInput.from_v1_dict(malformed_raw, strict=False)
        self.assertFalse(inp.is_valid)
        self.assertGreater(len(inp.parse_issues), 0)

        # evaluate_evidence quarantines invalid input gracefully
        engine = TriageEngine()
        res = engine.evaluate_evidence(inp)
        self.assertEqual(res.decision, "inconclusive")
        self.assertTrue(any("parse issues" in lim for lim in res.limitations))

    def test_collector_failures_and_partial_coverage_abstention(self):
        """Failed collectors and partial coverage trigger explicit abstention notice and limitations."""
        failed_raw = {
            "scan_id": "scan-fail-001",
            "target": "failed-test.net",
            "evidence": [
                {
                    "evidence_id": "ev-dns-fail-01",
                    "kind": "dns_resolution",
                    "source": "dns_collector",
                    "observed_at": "2026-11-10T00:00:00Z",
                    "status": "failed",
                    "reliability": "direct_observation",
                    "value": None,
                    "limitations": ["DNS server timed out"],
                }
            ],
            "coverage": {
                "checks_total": 4,
                "checks_observed": 0,
                "checks_failed": 1,
                "checks_not_run": 3,
            },
        }
        engine = TriageEngine()
        res = engine.evaluate_evidence(failed_raw)

        # Invariant EVID-001: collector failure must never be clean or safe
        self.assertNotEqual(res.decision, "clean")
        self.assertNotEqual(res.decision, "safe")
        self.assertEqual(res.decision, "inconclusive")
        self.assertIsNotNone(res.uncertainty)
        self.assertIsNotNone(res.uncertainty.abstention_notice)
        self.assertTrue(any("Coverage is partial" in lim for lim in res.limitations))

    def test_conflicting_and_stale_evidence_handling(self):
        """Stale timestamps and conflicting signals generate uncertainty and cap confidence."""
        stale_observed_at = "2020-01-01T00:00:00Z"
        raw_input = {
            "scan_id": "scan-stale-001",
            "target": "stale-target.org",
            "evidence": [
                {
                    "evidence_id": "ev-stale-tls-01",
                    "kind": "tls_certificate",
                    "source": "tls_collector",
                    "observed_at": stale_observed_at,
                    "status": "observed",
                    "reliability": "direct_observation",
                    "value": {"is_valid": True, "hostname_match": True},
                },
                {
                    "evidence_id": "ev-threat-01",
                    "kind": "threat_intelligence",
                    "source": "virustotal",
                    "observed_at": "2026-11-10T00:00:00Z",
                    "status": "observed",
                    "reliability": "provider_assertion",
                    "value": {"match": True, "provider": "virustotal", "threat_type": "phishing", "confidence": "high"},
                },
            ],
            "coverage": {
                "checks_total": 2,
                "checks_observed": 2,
                "checks_failed": 0,
                "checks_not_run": 0,
            },
        }
        engine = TriageEngine()
        res = engine.evaluate_evidence(raw_input)

        # Stale evidence detected in uncertainty assessment
        unc_types = [u.uncertainty_type for u in res.uncertainty.uncertainties]
        self.assertIn(UncertaintyType.TEMPORAL_STALENESS, unc_types)

    def test_positive_threat_preservation_across_collector_failure(self):
        """Positive threat match is preserved even when an unrelated collector fails."""
        mixed_input = {
            "scan_id": "scan-mixed-001",
            "target": "phish-corp.xyz",
            "evidence": [
                {
                    "evidence_id": "ev-threat-pos-01",
                    "kind": "threat_intelligence",
                    "source": "openphish",
                    "observed_at": "2026-11-10T00:00:00Z",
                    "status": "observed",
                    "reliability": "provider_assertion",
                    "value": {"match": True, "provider": "openphish", "threat_type": "phishing", "confidence": "high"},
                },
                {
                    "evidence_id": "ev-http-fail-01",
                    "kind": "http_response",
                    "source": "http_collector",
                    "observed_at": "2026-11-10T00:00:00Z",
                    "status": "failed",
                    "reliability": "direct_observation",
                    "value": None,
                    "limitations": ["HTTP GET connection reset by peer"],
                },
            ],
            "coverage": {
                "checks_total": 2,
                "checks_observed": 1,
                "checks_failed": 1,
                "checks_not_run": 0,
            },
        }
        engine = TriageEngine()
        res = engine.evaluate_evidence(mixed_input)

        # Threat finding is preserved, high-risk verdict
        self.assertEqual(res.decision, "high_risk")
        self.assertGreater(len(res.findings), 0)
        self.assertEqual(res.findings[0]["severity"], "high")

    def test_report_integrity_auditor_all_invariants(self):
        """ReportIntegrityAuditor catches all major audit invariant violations."""
        auditor = ReportIntegrityAuditor()

        # Invariant 1: Missing top-level fields / illegal affirmative clean
        res1 = auditor.audit_report({"decision": "clean"})
        self.assertFalse(res1.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.EVID_002.value for i in res1.issues))

        # Invariant 2: Coverage sum arithmetic violation (checks_total == 4, but observed 2 + failed 1 + not_run 0 == 3)
        bad_cov_report = {
            "scan_id": "s1", "target": "t.com", "decision": "inconclusive", "status": "completed",
            "dimensions": {"identity": "unverified", "certificate": "valid_for_hostname", "behavior": "no_threat_observed", "evidence_quality": "sufficient"},
            "coverage": {"checks_total": 4, "checks_observed": 2, "checks_failed": 1, "checks_not_run": 0},  # sum is 3 != 4
            "evidence": [], "findings": [], "limitations": [],
        }
        res2 = auditor.audit_report(bad_cov_report)
        self.assertFalse(res2.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.COV_002.value for i in res2.issues))

        # Invariant 3: TLS-001 (Valid TLS claiming supported identity without auth credentials)
        tls001_violation = {
            "scan_id": "s2", "target": "t.com", "decision": "inconclusive", "status": "completed",
            "dimensions": {"identity": "supported", "certificate": "valid_for_hostname", "behavior": "no_threat_observed", "evidence_quality": "sufficient"},
            "coverage": {"checks_total": 1, "checks_observed": 1, "checks_failed": 0, "checks_not_run": 0},
            "evidence": [{"evidence_id": "e1", "kind": "tls_certificate", "source": "tls", "observed_at": "2026-11-10T00:00:00Z", "status": "observed"}],
            "findings": [], "limitations": [],
        }
        res3 = auditor.audit_report(tls001_violation)
        self.assertFalse(res3.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.TLS_001.value for i in res3.issues))

        # Invariant 4: EVID-002 (Affirmative safe claim is strictly forbidden)
        evid002_violation = {
            "scan_id": "s4", "target": "t.com", "decision": "safe", "status": "completed",
            "dimensions": {"identity": "unverified", "certificate": "valid_for_hostname", "behavior": "no_threat_observed", "evidence_quality": "sufficient"},
            "coverage": {"checks_total": 1, "checks_observed": 1, "checks_failed": 0, "checks_not_run": 0},
            "evidence": [], "findings": [], "limitations": [],
        }
        res4 = auditor.audit_report(evid002_violation)
        self.assertFalse(res4.is_valid)
        self.assertTrue(any(i.rule_id == AuditRuleId.EVID_002.value for i in res4.issues))


# ─── Worker 03 Phase 05: Evaluation, Regression, and Invariants ───────


class TestPolicyRegression(unittest.TestCase):
    """Deterministic policy regression comparison tests (Phase 05)."""

    def setUp(self):
        self.engine = TriageEngine()
        self.runner = PolicyRegressionRunner()

    def test_capture_baseline_snapshot(self):
        """Baseline snapshot captures deterministic semantic policy outcomes."""
        snapshot = self.runner.capture_baseline_snapshot(self.engine, FIXTURES_V1)
        self.assertEqual(len(snapshot), 7)
        self.assertIn("FIX-001", snapshot)

        f1 = snapshot["FIX-001"]
        self.assertEqual(f1["fixture_id"], "FIX-001")
        self.assertEqual(f1["decision"], "no_threat_observed")
        self.assertEqual(f1["dimensions"]["certificate"], "valid_for_hostname")
        self.assertIn("rules_triggered", f1)
        self.assertIn("limitations", f1)
        # Nondeterministic metadata should not be present
        self.assertNotIn("timestamp", f1)
        self.assertNotIn("scan_id", f1)

    def test_regression_runner_zero_false_regressions(self):
        """Running regression against baseline for unchanged engine reports zero regressions."""
        snapshot = self.runner.capture_baseline_snapshot(self.engine, FIXTURES_V2)
        diff = self.runner.run_regression_against_baseline(self.engine, snapshot, FIXTURES_V2)

        self.assertFalse(diff.has_regressions)
        self.assertEqual(len(diff.decision_shifts), 0)
        self.assertEqual(len(diff.dimension_shifts), 0)
        self.assertEqual(len(diff.rule_shifts), 0)
        self.assertEqual(diff.passed_fixtures, 15)
        self.assertEqual(diff.total_fixtures, 15)

    def test_regression_runner_detects_deliberate_verdict_shift(self):
        """Runner flags when candidate decision departs from baseline snapshot."""
        snapshot = self.runner.capture_baseline_snapshot(self.engine, FIXTURES_V1)
        # Deliberately modify baseline snapshot for FIX-001
        snapshot["FIX-001"]["decision"] = "caution"

        diff = self.runner.run_regression_against_baseline(self.engine, snapshot, FIXTURES_V1)
        self.assertTrue(diff.has_regressions)
        self.assertEqual(len(diff.decision_shifts), 1)
        shift = diff.decision_shifts[0]
        self.assertEqual(shift["fixture_id"], "FIX-001")
        self.assertEqual(shift["baseline"], "caution")
        self.assertEqual(shift["candidate"], "no_threat_observed")

    def test_regression_runner_detects_dimension_shift(self):
        """Runner flags when candidate dimensions depart from baseline snapshot."""
        snapshot = self.runner.capture_baseline_snapshot(self.engine, FIXTURES_V1)
        # Deliberately modify baseline dimension for FIX-002
        snapshot["FIX-002"]["dimensions"]["behavior"] = "suspicious"

        diff = self.runner.run_regression_against_baseline(self.engine, snapshot, FIXTURES_V1)
        self.assertTrue(diff.has_regressions)
        self.assertEqual(len(diff.dimension_shifts), 1)
        shift = diff.dimension_shifts[0]
        self.assertEqual(shift["fixture_id"], "FIX-002")
        self.assertEqual(shift["dimension"], "behavior")
        self.assertEqual(shift["baseline"], "suspicious")
        self.assertEqual(shift["candidate"], "malicious_evidence")

    def test_regression_diff_report_serialization(self):
        """RegressionDiffReport serializes cleanly to dict and JSON."""
        snapshot = self.runner.capture_baseline_snapshot(self.engine, FIXTURES_V1)
        snapshot["FIX-003"]["decision"] = "caution"
        diff = self.runner.run_regression_against_baseline(self.engine, snapshot, FIXTURES_V1)

        d = diff.to_dict()
        self.assertIsInstance(d, dict)
        self.assertTrue(d["has_regressions"])
        self.assertEqual(len(d["decision_shifts"]), 1)

        j = diff.to_json()
        parsed = json.loads(j)
        self.assertEqual(parsed["total_fixtures"], 7)
        self.assertTrue(parsed["has_regressions"])

    def test_decision_audit_record_semantic_dict(self):
        """DecisionAuditRecord provides deterministic semantic dict excluding transient keys."""
        record = DecisionAuditRecord(
            audit_id="audit-12345",
            scan_id="scan-abc",
            target="example.com",
            policy_version="1.0.0",
            timestamp="2026-11-10T12:00:00Z",
            decision="no_threat_observed",
            dimensions={"identity": "unverified", "certificate": "valid_for_hostname", "behavior": "no_threat_observed", "evidence_quality": "strong"},
            findings=[{"code": "NO_THREAT", "category": "behavior"}],
            limitations=["Simulated fixture context"],
            uncertainty={"band": "high"},
            rules_triggered=["RULE_CERT_VALID", "RULE_NO_THREAT"],
        )

        semantic = record.to_semantic_dict()
        self.assertEqual(semantic["target"], "example.com")
        self.assertEqual(semantic["decision"], "no_threat_observed")
        self.assertNotIn("scan_id", semantic)
        self.assertNotIn("audit_id", semantic)
        self.assertNotIn("timestamp", semantic)

        # JSON round-trip of full record
        full_json = record.to_json()
        restored = DecisionAuditRecord.from_json(full_json)
        self.assertEqual(restored.audit_id, "audit-12345")
        self.assertEqual(restored.decision, "no_threat_observed")

    def test_decision_log_record_audit_integration(self):
        """DecisionLog records and indexes DecisionAuditRecord without external DB."""
        log = DecisionLog()
        record = DecisionAuditRecord(
            audit_id="aud-1",
            scan_id="scan-99",
            target="trusted.org",
            policy_version="1.0.0",
            timestamp="2026-11-10T00:00:00Z",
            decision="inconclusive",
            dimensions={"evidence_quality": "unavailable"},
        )
        log.record_audit(record)
        self.assertEqual(len(log.audit_records), 1)

        found = log.find_audit_by_scan("scan-99")
        self.assertIsNotNone(found)
        self.assertEqual(found.target, "trusted.org")
        self.assertIsNone(log.find_audit_by_scan("non-existent"))


class TestExpandedFixtures(unittest.TestCase):
    """Controlled evaluation suites v1 (frozen) and v2 (expanded 15 fixtures)."""

    def setUp(self):
        self.engine = TriageEngine()

    def test_v1_fixtures_frozen_and_pass(self):
        """Canonical v1 suite contains exactly 7 fixtures and all pass."""
        eval_v1 = build_eval_v1_set()
        self.assertTrue(eval_v1.is_frozen)
        self.assertEqual(len(eval_v1.fixtures), 7)
        with self.assertRaises(RuntimeError):
            eval_v1.add_fixture(eval_v1.fixtures[0])

        summary = eval_v1.run_evaluation(self.engine)
        self.assertEqual(summary.total_fixtures, 7)
        self.assertEqual(summary.passed, 7)
        self.assertEqual(summary.failed, 0)
        self.assertTrue(summary.is_simulated)

    def test_v2_fixtures_expanded_and_pass(self):
        """Expanded v2 suite contains exactly 15 fixtures and all pass."""
        eval_v2 = build_eval_v2_set()
        self.assertTrue(eval_v2.is_frozen)
        self.assertEqual(len(eval_v2.fixtures), 15)
        with self.assertRaises(RuntimeError):
            eval_v2.add_fixture(eval_v2.fixtures[0])

        summary = eval_v2.run_evaluation(self.engine)
        self.assertEqual(summary.total_fixtures, 15)
        self.assertEqual(summary.passed, 15)
        self.assertEqual(summary.failed, 0)
        self.assertTrue(summary.is_simulated)

    def test_all_fixtures_marked_simulated(self):
        """Every fixture in v1 and v2 is explicitly marked is_simulated=True."""
        for f in FIXTURES_V1:
            self.assertTrue(f.is_simulated, f"{f.fixture_id} must have is_simulated=True")
        for f in FIXTURES_V2:
            self.assertTrue(f.is_simulated, f"{f.fixture_id} must have is_simulated=True")

    def test_summary_honest_limitations_and_class_prevalence(self):
        """EvaluationSummary reports honest limitations without claiming generalization."""
        eval_v2 = build_eval_v2_set()
        summary = eval_v2.run_evaluation(self.engine)

        self.assertTrue(any("simulated" in lim.lower() for lim in summary.limitations))
        prev = eval_v2.get_class_prevalence()
        self.assertIn("no_threat_observed", prev)
        self.assertIn("inconclusive", prev)
        self.assertIn("caution", prev)
        self.assertIn("high_risk", prev)

    def test_v2_specific_fixture_behaviors(self):
        """Specific behavioral verification for each of FIX-008 through FIX-015."""
        eval_v2 = build_eval_v2_set()
        res_map = {r.fixture_id: r for r in eval_v2.run_evaluation(self.engine).results}

        # FIX-008: Expired TLS alone does not trigger high_risk
        self.assertEqual(res_map["FIX-008"].actual_decision, "no_threat_observed")
        self.assertEqual(res_map["FIX-008"].actual_dimensions["certificate"], "invalid_or_expired")

        # FIX-009: IDN lookalike heuristic leaves identity unverified without asserting high_risk
        self.assertEqual(res_map["FIX-009"].actual_decision, "inconclusive")
        self.assertEqual(res_map["FIX-009"].actual_dimensions["identity"], "unverified")

        # FIX-010: Private IP blocked upstream yields inconclusive with unavailable quality
        self.assertEqual(res_map["FIX-010"].actual_decision, "inconclusive")
        self.assertEqual(res_map["FIX-010"].actual_dimensions["evidence_quality"], "unavailable")

        # FIX-011: Stale threat feed preserves positive threat evidence with partial quality
        self.assertEqual(res_map["FIX-011"].actual_decision, "high_risk")
        self.assertEqual(res_map["FIX-011"].actual_dimensions["evidence_quality"], "partial")

        # FIX-012: Rate-limited collector outcome maps to collector_failure and unavailable quality
        self.assertEqual(res_map["FIX-012"].actual_decision, "inconclusive")
        self.assertEqual(res_map["FIX-012"].actual_dimensions["evidence_quality"], "unavailable")

        # FIX-013: Corroborated community report elevates behavior to suspicious
        self.assertEqual(res_map["FIX-013"].actual_decision, "caution")
        self.assertEqual(res_map["FIX-013"].actual_dimensions["behavior"], "suspicious")

        # FIX-014: Complete network timeout yields unavailable evidence quality
        self.assertEqual(res_map["FIX-014"].actual_decision, "inconclusive")
        self.assertEqual(res_map["FIX-014"].actual_dimensions["evidence_quality"], "unavailable")

        # FIX-015: Conflicting provider observations retain evidence and cap at inconclusive
        self.assertEqual(res_map["FIX-015"].actual_decision, "inconclusive")
        self.assertEqual(res_map["FIX-015"].actual_dimensions["evidence_quality"], "partial")


class TestPolicyInvariantsAndFuzzing(unittest.TestCase):
    """Invariant preservation, permutation invariance, and fixed-seed property fuzzing."""

    def setUp(self):
        self.engine = TriageEngine()

    def test_permutation_invariance_deterministic(self):
        """Signal presentation order does not change semantic decision or dimensions."""
        test_scenarios = [
            # Scenario A: Clean site with valid TLS and collectors
            [
                SignalRecord(kind=SignalKind.TLS_VALID, evidence_ids=["e1"], source="tls"),
                SignalRecord(kind=SignalKind.TLS_HOSTNAME_MATCH, evidence_ids=["e1"], source="tls"),
                SignalRecord(kind=SignalKind.NO_THREAT_MATCH, evidence_ids=["e2"], source="dns"),
                SignalRecord(kind=SignalKind.COLLECTOR_SUCCESS, evidence_ids=["e1", "e2"], source="orch"),
            ],
            # Scenario B: High risk threat match
            [
                SignalRecord(kind=SignalKind.COLLECTOR_SUCCESS, evidence_ids=["e1"], source="orch"),
                SignalRecord(kind=SignalKind.THREAT_FEED_MATCH, evidence_ids=["e1"], source="feed"),
                SignalRecord(kind=SignalKind.TLS_MISMATCH, evidence_ids=["e2"], source="tls"),
            ],
            # Scenario C: Conflicting signals
            [
                SignalRecord(kind=SignalKind.NO_THREAT_MATCH, evidence_ids=["e1"], source="feed1"),
                SignalRecord(kind=SignalKind.COLLECTOR_SUCCESS, evidence_ids=["e1", "e2"], source="orch"),
                SignalRecord(kind=SignalKind.THREAT_FEED_MATCH, evidence_ids=["e2"], source="feed2"),
                SignalRecord(kind=SignalKind.CONFLICTING_SIGNALS, evidence_ids=["e1", "e2"], source="orch"),
            ],
            # Scenario D: Community caution
            [
                SignalRecord(kind=SignalKind.COLLECTOR_SUCCESS, evidence_ids=["e1"], source="orch"),
                SignalRecord(kind=SignalKind.COMMUNITY_REPORT_CORROBORATED, evidence_ids=["e2"], source="comm"),
                SignalRecord(kind=SignalKind.TLS_VALID, evidence_ids=["e3"], source="tls"),
            ],
        ]

        import random
        for scenario in test_scenarios:
            res_forward = self.engine.evaluate(scenario)
            res_reverse = self.engine.evaluate(list(reversed(scenario)))
            self.assertEqual(res_forward.decision, res_reverse.decision)
            self.assertEqual(res_forward.dimensions, res_reverse.dimensions)

            # Random permutations
            rng = random.Random(42)
            for _ in range(5):
                shuffled = list(scenario)
                rng.shuffle(shuffled)
                res_shuffled = self.engine.evaluate(shuffled)
                self.assertEqual(res_forward.decision, res_shuffled.decision)
                self.assertEqual(res_forward.dimensions, res_shuffled.dimensions)

    def test_fixed_seed_property_based_fuzzing(self):
        """150 randomized valid signal combinations uphold all policy invariants."""
        import random
        rng = random.Random(1337)
        all_kinds = list(SignalKind)
        valid_decisions = {"high_risk", "caution", "no_threat_observed", "inconclusive"}

        for i in range(150):
            sample_size = rng.randint(0, 12)
            kinds = [rng.choice(all_kinds) for _ in range(sample_size)]
            signals = [
                SignalRecord(
                    kind=kd,
                    evidence_ids=[f"ev-fuzz-{j}"],
                    source="fuzz_generator",
                    confidence="direct_observation",
                )
                for j, kd in enumerate(kinds)
            ]

            # Invariant 1: No unhandled exceptions
            res = self.engine.evaluate(signals)

            # Invariant 2: Decision is within legal non-affirmative set (EVID-002: never safe or clean)
            self.assertIn(res.decision, valid_decisions, f"Illegal decision at iteration {i}: {res.decision}")
            self.assertNotIn(res.decision, {"safe", "clean", "benign", "secure"})

            # Invariant 3: All 4 dimensions present and non-empty
            for dim_name in ("identity", "certificate", "behavior", "evidence_quality"):
                self.assertIn(dim_name, res.dimensions, f"Missing dimension {dim_name} at iteration {i}")
                self.assertTrue(len(res.dimensions[dim_name]) > 0)

            # Invariant 4: TLS-001 (Identity supported requires explicit authorization evidence)
            if res.dimensions.get("identity") == "supported":
                self.assertTrue(
                    any(s.kind == SignalKind.AUTHORIZATION_EVIDENCE for s in signals),
                    f"TLS-001 violated at iteration {i}: identity supported without authorization signal",
                )

            # Invariant 5: EVID-001 (Unavailable evidence quality cannot produce no_threat_observed)
            if res.dimensions.get("evidence_quality") == "unavailable":
                self.assertNotEqual(
                    res.decision,
                    "no_threat_observed",
                    f"EVID-001 violated at iteration {i}: unavailable quality produced no_threat_observed",
                )

    def test_malformed_input_isolation(self):
        """Passing non-SignalRecord elements raises appropriate error without engine corruption."""
        with self.assertRaises(AttributeError):
            self.engine.evaluate(["invalid_string_instead_of_signal"])  # type: ignore

        # Engine remains fully functional after error
        res = self.engine.evaluate([])
        self.assertEqual(res.decision, "inconclusive")


if __name__ == "__main__":
    unittest.main()
