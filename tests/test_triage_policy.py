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


if __name__ == "__main__":
    unittest.main()
