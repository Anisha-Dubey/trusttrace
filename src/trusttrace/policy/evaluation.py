"""Controlled evaluation and claim audit — Worker 03 Phase 02.

Provides:
1. ControlledEvaluationSet: Manages frozen fixture-based test cases with
   known expected outcomes for regression and baseline measurement.
2. ClaimAuditor: Reviews pitch/demo claims against available evidence,
   flagging unsupported accuracy, novelty, or safety assertions.

Design constraints (from .brain/.work/shared/decision_policy_table.md):
- No random-split-only generalization claims
- No dataset absence as benign
- No fabricated metrics
- Fixtures labeled as simulated
- Negative results accepted (inability to measure is honest, not a failure)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import uuid


class FixtureLabel(str, Enum):
    """Ground truth labels for controlled evaluation fixtures."""

    HIGH_RISK = "high_risk"
    CAUTION = "caution"
    NO_THREAT_OBSERVED = "no_threat_observed"
    INCONCLUSIVE = "inconclusive"
    CONFLICTING = "conflicting"
    PARTIAL = "partial"


class ClaimCategory(str, Enum):
    """Categories of claims that require audit evidence."""

    ACCURACY = "accuracy"
    SAFETY = "safety"
    NOVELTY = "novelty"
    PERFORMANCE = "performance"
    COVERAGE = "coverage"


class ClaimVerdict(str, Enum):
    """Audit verdict for a claim."""

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    PARTIALLY_SUPPORTED = "partially_supported"
    NOT_EVALUATED = "not_evaluated"


@dataclass
class EvaluationFixture:
    """A single controlled test case with known expected outcome.

    Attributes:
        fixture_id: Stable identifier for this fixture.
        description: Human-readable description of the test scenario.
        label: Expected ground-truth decision.
        signals_config: Signal configuration to feed into TriageEngine.
        expected_dimensions: Expected dimension values.
        expected_decision: Expected final decision.
        source: Origin of the fixture (e.g., "manual_construction", "team_review").
        is_simulated: Always True for hackathon fixtures; labeled visibly.
        notes: Additional context about this fixture case.
    """

    fixture_id: str
    description: str
    label: FixtureLabel
    signals_config: List[Dict[str, Any]]
    expected_dimensions: Dict[str, str]
    expected_decision: str
    source: str = "manual_construction"
    is_simulated: bool = True
    notes: str = ""


@dataclass
class EvaluationResult:
    """Result of running a single fixture through the triage engine."""

    fixture_id: str
    expected_decision: str
    actual_decision: str
    expected_dimensions: Dict[str, str]
    actual_dimensions: Dict[str, str]
    passed: bool
    dimension_mismatches: List[str] = field(default_factory=list)
    rationale: str = ""


@dataclass
class EvaluationSummary:
    """Aggregate summary of a controlled evaluation run.

    Reports honest metrics without fabrication; if sample size is
    insufficient for statistical claims, states that explicitly.
    """

    run_id: str = field(default_factory=lambda: f"eval-{uuid.uuid4().hex[:8]}")
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    total_fixtures: int = 0
    passed: int = 0
    failed: int = 0
    decision_accuracy: Optional[float] = None  # None if sample too small
    per_decision_counts: Dict[str, Dict[str, int]] = field(default_factory=dict)
    results: List[EvaluationResult] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    is_simulated: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for report export."""
        d: Dict[str, Any] = {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "total_fixtures": self.total_fixtures,
            "passed": self.passed,
            "failed": self.failed,
            "per_decision_counts": self.per_decision_counts,
            "is_simulated": self.is_simulated,
            "limitations": self.limitations,
        }
        if self.decision_accuracy is not None:
            d["decision_accuracy"] = round(self.decision_accuracy, 4)
        else:
            d["decision_accuracy"] = None
            d["decision_accuracy_note"] = (
                "Sample size insufficient for meaningful accuracy claim."
            )
        return d


class ControlledEvaluationSet:
    """Manages a frozen set of evaluation fixtures for regression testing.

    All fixtures are explicitly labeled as simulated. Metrics are reported
    honestly with sample size, class prevalence, and limitations.
    """

    def __init__(self) -> None:
        self._fixtures: List[EvaluationFixture] = []
        self._frozen: bool = False

    def add_fixture(self, fixture: EvaluationFixture) -> None:
        """Add a fixture to the evaluation set. Must not be frozen."""
        if self._frozen:
            raise RuntimeError(
                "Evaluation set is frozen. Create a new version to add fixtures."
            )
        self._fixtures.append(fixture)

    def freeze(self) -> None:
        """Freeze the evaluation set. No more additions allowed."""
        self._frozen = True

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    @property
    def fixtures(self) -> List[EvaluationFixture]:
        return list(self._fixtures)

    def get_class_prevalence(self) -> Dict[str, int]:
        """Report class prevalence across fixtures."""
        counts: Dict[str, int] = {}
        for f in self._fixtures:
            counts[f.expected_decision] = counts.get(f.expected_decision, 0) + 1
        return counts

    def run_evaluation(self, triage_engine: Any) -> EvaluationSummary:
        """Run all fixtures through the triage engine and report results.

        Args:
            triage_engine: A TriageEngine instance with an evaluate() method.

        Returns:
            EvaluationSummary with honest metrics and limitations.
        """
        from .signal_taxonomy import SignalKind, SignalRecord

        results: List[EvaluationResult] = []
        passed = 0
        failed = 0

        # Per-decision confusion tracking.
        per_decision: Dict[str, Dict[str, int]] = {}

        for fixture in self._fixtures:
            # Build signals from fixture config.
            signals = []
            for sig_config in fixture.signals_config:
                signals.append(
                    SignalRecord(
                        kind=SignalKind(sig_config["kind"]),
                        evidence_ids=sig_config.get("evidence_ids", ["fixture-ev"]),
                        source=sig_config.get("source", "fixture"),
                        confidence=sig_config.get("confidence", "direct_observation"),
                        limitations=sig_config.get("limitations", []),
                    )
                )

            triage_result = triage_engine.evaluate(signals)

            # Compare decision.
            decision_match = triage_result.decision == fixture.expected_decision

            # Compare dimensions.
            dim_mismatches = []
            for dim_key, expected_val in fixture.expected_dimensions.items():
                actual_val = triage_result.dimensions.get(dim_key)
                if actual_val != expected_val:
                    dim_mismatches.append(
                        f"{dim_key}: expected={expected_val}, actual={actual_val}"
                    )

            is_pass = decision_match and len(dim_mismatches) == 0

            result = EvaluationResult(
                fixture_id=fixture.fixture_id,
                expected_decision=fixture.expected_decision,
                actual_decision=triage_result.decision,
                expected_dimensions=fixture.expected_dimensions,
                actual_dimensions=dict(triage_result.dimensions),
                passed=is_pass,
                dimension_mismatches=dim_mismatches,
                rationale=triage_result.rationale_summary,
            )
            results.append(result)

            if is_pass:
                passed += 1
            else:
                failed += 1

            # Track per-decision counts.
            expected = fixture.expected_decision
            actual = triage_result.decision
            if expected not in per_decision:
                per_decision[expected] = {}
            per_decision[expected][actual] = (
                per_decision[expected].get(actual, 0) + 1
            )

        total = len(self._fixtures)

        # Compute accuracy only if sample size is meaningful.
        limitations = [
            "All fixtures are simulated/constructed; not real-world data.",
            "Sample size is limited to hackathon fixture set.",
        ]

        accuracy: Optional[float] = None
        if total >= 5:
            accuracy = passed / total if total > 0 else None
        else:
            limitations.append(
                f"Only {total} fixtures; sample too small for accuracy claims."
            )

        # Check class balance.
        prevalence = self.get_class_prevalence()
        if prevalence:
            max_class_pct = max(prevalence.values()) / total if total > 0 else 0
            if max_class_pct > 0.6:
                limitations.append(
                    f"Class imbalance: dominant class is {max_class_pct:.0%} of fixtures."
                )

        return EvaluationSummary(
            total_fixtures=total,
            passed=passed,
            failed=failed,
            decision_accuracy=accuracy,
            per_decision_counts=per_decision,
            results=results,
            limitations=limitations,
            is_simulated=True,
        )


# ─── Claim Auditor ────────────────────────────────────────────────────


@dataclass
class ClaimAuditEntry:
    """Audit record for a single claim in pitch/demo copy.

    Attributes:
        claim_id: Stable identifier.
        claim_text: The exact claim text being audited.
        category: What kind of claim this is.
        verdict: Whether the claim is supported by evidence.
        supporting_evidence: Evidence references that support the claim.
        issues: Specific problems found with the claim.
        recommendation: Suggested revision or action.
    """

    claim_id: str = field(default_factory=lambda: f"claim-{uuid.uuid4().hex[:6]}")
    claim_text: str = ""
    category: ClaimCategory = ClaimCategory.ACCURACY
    verdict: ClaimVerdict = ClaimVerdict.NOT_EVALUATED
    supporting_evidence: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_text": self.claim_text,
            "category": self.category.value,
            "verdict": self.verdict.value,
            "supporting_evidence": self.supporting_evidence,
            "issues": self.issues,
            "recommendation": self.recommendation,
        }


class ClaimAuditor:
    """Audits pitch and demo claims against available evidence.

    Flags:
    - Unsupported accuracy claims (no dataset, no metrics, no version)
    - Unsupported safety claims (controls not tested)
    - Unsupported novelty claims (no comparison baseline)
    - Arbitrary weighted scores presented as probabilities
    """

    # Keywords that trigger audit scrutiny.
    ACCURACY_KEYWORDS = [
        "accuracy", "precise", "precision", "recall", "f1",
        "detection rate", "false positive", "false negative",
        "auc", "roc", "% accurate", "percent accurate",
    ]
    SAFETY_KEYWORDS = [
        "safe", "secure", "protected", "prevents", "blocks all",
        "guaranteed", "100%", "zero false",
    ]
    NOVELTY_KEYWORDS = [
        "novel", "first", "unique", "breakthrough", "revolutionary",
        "state-of-the-art", "sota", "outperforms", "superior",
    ]
    PROBABILITY_KEYWORDS = [
        "probability", "likelihood", "% chance", "risk score",
        "threat score", "confidence score", "trust score",
    ]

    def audit_claim(
        self,
        claim_text: str,
        available_evidence: Optional[List[str]] = None,
        evaluation_summary: Optional[EvaluationSummary] = None,
    ) -> ClaimAuditEntry:
        """Audit a single claim text.

        Args:
            claim_text: The claim to audit.
            available_evidence: List of evidence references available.
            evaluation_summary: Optional evaluation results to check against.

        Returns:
            ClaimAuditEntry with verdict and issues.
        """
        claim_lower = claim_text.lower()
        issues: List[str] = []
        category = ClaimCategory.ACCURACY
        verdict = ClaimVerdict.NOT_EVALUATED
        recommendation = ""

        # Check for accuracy claims.
        if any(kw in claim_lower for kw in self.ACCURACY_KEYWORDS):
            category = ClaimCategory.ACCURACY
            if evaluation_summary is None:
                issues.append(
                    "Accuracy claim made without controlled evaluation results."
                )
                verdict = ClaimVerdict.UNSUPPORTED
                recommendation = (
                    "Remove accuracy claim or provide dataset, version, "
                    "sample size, class prevalence, and measured metrics."
                )
            elif evaluation_summary.is_simulated:
                issues.append(
                    "Evaluation uses simulated fixtures only; "
                    "claims about real-world accuracy are unsupported."
                )
                verdict = ClaimVerdict.PARTIALLY_SUPPORTED
                recommendation = (
                    "Qualify claim with 'on simulated fixtures' and report "
                    "sample size and class distribution."
                )
            elif evaluation_summary.decision_accuracy is None:
                issues.append(
                    "Sample size too small for meaningful accuracy claim."
                )
                verdict = ClaimVerdict.UNSUPPORTED
                recommendation = "Increase evaluation set or remove accuracy claim."

        # Check for safety claims.
        elif any(kw in claim_lower for kw in self.SAFETY_KEYWORDS):
            category = ClaimCategory.SAFETY
            if "100%" in claim_text or "zero false" in claim_lower:
                issues.append(
                    "Absolute safety claim ('100%', 'zero false') is never supportable."
                )
                verdict = ClaimVerdict.UNSUPPORTED
                recommendation = (
                    "Replace absolute claim with specific tested controls and "
                    "their verified scope."
                )
            elif available_evidence:
                verdict = ClaimVerdict.PARTIALLY_SUPPORTED
                recommendation = "Qualify with tested scope and known limitations."
            else:
                issues.append("Safety claim without evidence of tested controls.")
                verdict = ClaimVerdict.UNSUPPORTED
                recommendation = "Provide test evidence for specific safety controls."

        # Check for novelty claims.
        elif any(kw in claim_lower for kw in self.NOVELTY_KEYWORDS):
            category = ClaimCategory.NOVELTY
            issues.append(
                "Novelty/superiority claim requires comparison baseline and "
                "reproducible methodology."
            )
            verdict = ClaimVerdict.UNSUPPORTED
            recommendation = (
                "Remove novelty claim or provide specific comparison, "
                "methodology, and reproducible results."
            )

        # Check for probability/score claims.
        elif any(kw in claim_lower for kw in self.PROBABILITY_KEYWORDS):
            category = ClaimCategory.ACCURACY
            issues.append(
                "Weighted score or probability language detected. "
                "Do not label arbitrary weighted scores as probabilities "
                "without calibration evidence."
            )
            verdict = ClaimVerdict.UNSUPPORTED
            recommendation = (
                "Use 'disposition' or 'assessment' instead of 'probability'. "
                "Explain the score's derivation and limitations."
            )

        # If no flags triggered, mark as not evaluated.
        if not issues:
            verdict = ClaimVerdict.NOT_EVALUATED
            recommendation = "No audit flags triggered for this claim."

        return ClaimAuditEntry(
            claim_text=claim_text,
            category=category,
            verdict=verdict,
            supporting_evidence=available_evidence or [],
            issues=issues,
            recommendation=recommendation,
        )

    def audit_claims(
        self,
        claims: List[str],
        available_evidence: Optional[List[str]] = None,
        evaluation_summary: Optional[EvaluationSummary] = None,
    ) -> List[ClaimAuditEntry]:
        """Audit a list of claims.

        Returns:
            List of ClaimAuditEntry objects.
        """
        return [
            self.audit_claim(claim, available_evidence, evaluation_summary)
            for claim in claims
        ]

    def has_unsupported_claims(self, entries: List[ClaimAuditEntry]) -> bool:
        """Check if any audited claims are unsupported."""
        return any(e.verdict == ClaimVerdict.UNSUPPORTED for e in entries)


# ─── Canonical Controlled Evaluation Fixture Suites ────────────────────

FIXTURES_V1: Tuple[EvaluationFixture, ...] = (
    EvaluationFixture(
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
        is_simulated=True,
        notes="Baseline legitimate site with valid TLS and no threat feed matches.",
    ),
    EvaluationFixture(
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
        is_simulated=True,
        notes="Known malicious target flagged by authoritative feed.",
    ),
    EvaluationFixture(
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
        is_simulated=True,
        notes="Expired certificate alone is not evidence of active hostility.",
    ),
    EvaluationFixture(
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
        is_simulated=True,
        notes="Collector failure requires honest abstention, never assumed benign.",
    ),
    EvaluationFixture(
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
        is_simulated=True,
        notes="Direct contradiction between feeds yields inconclusive disposition.",
    ),
    EvaluationFixture(
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
        is_simulated=True,
        notes="Multiple corroborated user reports justify caution, not unilateral high_risk.",
    ),
    EvaluationFixture(
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
        is_simulated=True,
        notes="Stale data with no recent observations degrades evidence quality to weak.",
    ),
)

FIXTURES_V2: Tuple[EvaluationFixture, ...] = FIXTURES_V1 + (
    EvaluationFixture(
        fixture_id="FIX-008",
        description="Expired TLS certificate with matching hostname and no threats",
        label=FixtureLabel.NO_THREAT_OBSERVED,
        signals_config=[
            {"kind": "tls_expired", "evidence_ids": ["ev-tls-1"]},
            {"kind": "tls_hostname_match", "evidence_ids": ["ev-tls-1"]},
            {"kind": "no_threat_match", "evidence_ids": ["ev-dns-1"]},
            {"kind": "collector_success", "evidence_ids": ["ev-tls-1", "ev-dns-1"]},
        ],
        expected_dimensions={
            "certificate": "invalid_or_expired",
            "identity": "unverified",
            "behavior": "no_threat_observed",
            "evidence_quality": "strong",
        },
        expected_decision="no_threat_observed",
        is_simulated=True,
        notes="TLS-002 technical caution: expired TLS without threats does not fabricate phishing.",
    ),
    EvaluationFixture(
        fixture_id="FIX-009",
        description="Mixed-script/Punycode IDN lookalike candidate with valid TLS",
        label=FixtureLabel.INCONCLUSIVE,
        signals_config=[
            {"kind": "idn_lookalike", "evidence_ids": ["ev-dns-idn"], "limitations": ["idn_lookalike_candidate"]},
            {"kind": "tls_valid", "evidence_ids": ["ev-tls-1"]},
            {"kind": "tls_hostname_match", "evidence_ids": ["ev-tls-1"]},
            {"kind": "collector_success", "evidence_ids": ["ev-dns-idn", "ev-tls-1"]},
        ],
        expected_dimensions={
            "identity": "unverified",
            "certificate": "valid_for_hostname",
            "behavior": "unknown",
            "evidence_quality": "strong",
        },
        expected_decision="inconclusive",
        is_simulated=True,
        notes="IDN lookalike candidate leaves identity unverified without asserting definitive impersonation.",
    ),
    EvaluationFixture(
        fixture_id="FIX-010",
        description="Loopback or private IP target blocked upstream by safety policy",
        label=FixtureLabel.INCONCLUSIVE,
        signals_config=[
            {"kind": "collector_failure", "evidence_ids": ["ev-fail-blocked"], "limitations": ["blocked_private_target"]},
        ],
        expected_dimensions={
            "evidence_quality": "unavailable",
        },
        expected_decision="inconclusive",
        is_simulated=True,
        notes="Blocked target collection abstains honestly with unavailable evidence quality.",
    ),
    EvaluationFixture(
        fixture_id="FIX-011",
        description="Stale threat-feed observation with current collector execution",
        label=FixtureLabel.HIGH_RISK,
        signals_config=[
            {"kind": "stale_evidence", "evidence_ids": ["ev-stale-feed"], "limitations": ["feed_stale_120d"]},
            {"kind": "threat_feed_match", "evidence_ids": ["ev-stale-feed"]},
            {"kind": "collector_success", "evidence_ids": ["ev-coll-1"]},
        ],
        expected_dimensions={
            "behavior": "malicious_evidence",
            "evidence_quality": "partial",
        },
        expected_decision="high_risk",
        is_simulated=True,
        notes="Positive threat evidence is preserved under stale evidence with partial quality.",
    ),
    EvaluationFixture(
        fixture_id="FIX-012",
        description="Rate-limited collector outcome represented using valid v1 failure status",
        label=FixtureLabel.INCONCLUSIVE,
        signals_config=[
            {"kind": "collector_failure", "evidence_ids": ["ev-fail-rate"], "limitations": ["upstream_rate_limited"]},
        ],
        expected_dimensions={
            "evidence_quality": "unavailable",
        },
        expected_decision="inconclusive",
        is_simulated=True,
        notes="Upstream rate limiting does not invent unsupported status codes; marks quality unavailable.",
    ),
    EvaluationFixture(
        fixture_id="FIX-013",
        description="Multi-source corroborated community report verified by Worker 02",
        label=FixtureLabel.CAUTION,
        signals_config=[
            {"kind": "community_report_corroborated", "evidence_ids": ["ev-c1", "ev-c2"]},
            {"kind": "collector_success", "evidence_ids": ["ev-c1"]},
        ],
        expected_dimensions={
            "behavior": "suspicious",
            "evidence_quality": "strong",
        },
        expected_decision="caution",
        is_simulated=True,
        notes="Corroborated community reports elevate behavior to suspicious with caution disposition.",
    ),
    EvaluationFixture(
        fixture_id="FIX-014",
        description="Network timeout across all required collectors causing complete abstention",
        label=FixtureLabel.INCONCLUSIVE,
        signals_config=[
            {"kind": "collector_failure", "evidence_ids": ["ev-fail-timeout"], "limitations": ["network_timeout_all_collectors"]},
        ],
        expected_dimensions={
            "evidence_quality": "unavailable",
        },
        expected_decision="inconclusive",
        is_simulated=True,
        notes="All-collector timeout forces honest abstention with unavailable quality.",
    ),
    EvaluationFixture(
        fixture_id="FIX-015",
        description="Conflicting provider observations for same target within comparable window",
        label=FixtureLabel.CONFLICTING,
        signals_config=[
            {"kind": "threat_feed_match", "evidence_ids": ["ev-feed-pos"]},
            {"kind": "no_threat_match", "evidence_ids": ["ev-feed-neg"]},
            {"kind": "conflicting_signals", "evidence_ids": ["ev-feed-pos", "ev-feed-neg"]},
            {"kind": "collector_success", "evidence_ids": ["ev-feed-pos", "ev-feed-neg"]},
        ],
        expected_dimensions={
            "evidence_quality": "partial",
            "behavior": "malicious_evidence",
        },
        expected_decision="inconclusive",
        is_simulated=True,
        notes="Conflicting provider observations retain evidence and cap decision at inconclusive.",
    ),
)


def build_eval_v1_set() -> ControlledEvaluationSet:
    """Build and freeze the canonical immutable Phase 02 evaluation suite (w03-eval-v1)."""
    eval_set = ControlledEvaluationSet()
    for fixture in FIXTURES_V1:
        eval_set.add_fixture(fixture)
    eval_set.freeze()
    return eval_set


def build_eval_v2_set() -> ControlledEvaluationSet:
    """Build and freeze the expanded Phase 05 evaluation suite (w03-eval-v2)."""
    eval_set = ControlledEvaluationSet()
    for fixture in FIXTURES_V2:
        eval_set.add_fixture(fixture)
    eval_set.freeze()
    return eval_set

