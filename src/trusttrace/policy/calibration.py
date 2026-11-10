"""Asymmetric Cost Calibration & Minimax Decision Rules — Worker 03 Phase 08.

Implements cost-sensitive decision rules, empirical threshold analysis, and
minimax expected cost evaluation under asymmetric operational penalties.

Strict Architectural Discipline:
1. Probability Calibration Gated: Continuous statistical probability math is
   explicitly gated (statistical_calibration_available = False) until an
   authorized, validated dataset and calibrated ML model exist.
2. Decoupled Dimensions: Ordinal confidence (ConfidenceBand), evidence quality,
   modality availability (ModalityAvailabilityMask), and operational costs
   remain separate dimensions. Ordinal bands are NEVER mapped to probability intervals.
3. Cost Validation: Validates finite, non-negative real numbers, positive review cost,
   and strict error-dominance (C_FP > C_TP, C_FN > C_TN) to prevent zero denominators.
4. Scale-Invariant Comparison: Uses unified math.isclose(rel_tol=1e-9, abs_tol=1e-9)
   for both small and large cost magnitudes.
5. Deterministic Precedence: D_I (Inconclusive) > D_M (Threat) > D_B (Clean) on ties.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple


class CandidateAction(str, Enum):
    """Candidate triage actions evaluated under operational costs."""

    THREAT = "threat"              # D_M: confirmed_threat or suspicious_threat
    INCONCLUSIVE = "inconclusive"  # D_I: request human analyst review / abstain
    CLEAN = "clean"                # D_B: no_threat_observed


# Deterministic Safety-First Precedence Hierarchy:
# When worst-case costs are equal (within tolerance), this order deterministically selects:
# D_I (Inconclusive) > D_M (Threat) > D_B (Clean)
DETERMINISTIC_ACTION_PRECEDENCE: Tuple[CandidateAction, ...] = (
    CandidateAction.INCONCLUSIVE,
    CandidateAction.THREAT,
    CandidateAction.CLEAN,
)

# Comparison tolerance for near-optimal cost equivalence
COST_COMPARISON_TOLERANCE: float = 1e-9


def is_cost_close(a: float, b: float, tol: float = COST_COMPARISON_TOLERANCE) -> bool:
    """Unified scale-invariant cost comparison.

    Uses math.isclose with identical relative and absolute tolerance.
    |a - b| <= max(tol * max(|a|, |b|), tol).
    """
    return math.isclose(a, b, rel_tol=tol, abs_tol=tol)


@dataclass(frozen=True)
class AsymmetricCostConfig:
    """Operational cost matrix for triage decision actions and true states.

    Costs represent operational regret/penalties:
        C_FN: Cost of declaring Clean when truly Malicious (missed threat, breach).
        C_FP: Cost of declaring Threat when truly Benign (false alarm, disruption).
        C_A:  Cost of Abstaining / routing to human analyst review queue.
        C_TP: Cost of declaring Threat when truly Malicious (normalized to 0.0).
        C_TN: Cost of declaring Clean when truly Benign (normalized to 0.0).
    """

    profile_name: str
    cost_false_negative: float   # C_FN
    cost_false_positive: float   # C_FP
    cost_abstain: float          # C_A
    cost_true_positive: float = 0.0  # C_TP
    cost_true_negative: float = 0.0  # C_TN

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Validate cost rationality, non-negativity, finiteness, and denominator safety."""
        fields = [
            ("cost_false_negative", self.cost_false_negative),
            ("cost_false_positive", self.cost_false_positive),
            ("cost_abstain", self.cost_abstain),
            ("cost_true_positive", self.cost_true_positive),
            ("cost_true_negative", self.cost_true_negative),
        ]
        for name, val in fields:
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                raise TypeError(f"{name} must be a real float, got {type(val).__name__}")
            if not math.isfinite(val) or math.isnan(val):
                raise ValueError(f"{name} must be finite and not NaN, got {val}")
            if val < 0.0:
                raise ValueError(f"{name} must be non-negative, got {val}")

        if self.cost_abstain <= 0.0:
            raise ValueError(f"cost_abstain must be strictly positive (> 0.0), got {self.cost_abstain}")

        # Strict error penalty dominance: C_FP > C_TP and C_FN > C_TN
        # This mathematically guarantees non-zero, positive denominators in threshold formulas.
        if self.cost_false_positive <= self.cost_true_positive:
            raise ValueError(
                f"cost_false_positive ({self.cost_false_positive}) must strictly exceed "
                f"cost_true_positive ({self.cost_true_positive})"
            )
        if self.cost_false_negative <= self.cost_true_negative:
            raise ValueError(
                f"cost_false_negative ({self.cost_false_negative}) must strictly exceed "
                f"cost_true_negative ({self.cost_true_negative})"
            )

    @property
    def denominator_threat(self) -> float:
        """Denominator for threat threshold: C_FP - C_TP > 0."""
        return self.cost_false_positive - self.cost_true_positive

    @property
    def denominator_clean(self) -> float:
        """Denominator for clean threshold: C_FN - C_TN > 0."""
        return self.cost_false_negative - self.cost_true_negative

    @property
    def raw_theta_threat(self) -> float:
        """Raw unconstrained threat boundary threshold: (C_FP - C_A) / (C_FP - C_TP)."""
        return (self.cost_false_positive - self.cost_abstain) / self.denominator_threat

    @property
    def raw_theta_clean(self) -> float:
        """Raw unconstrained clean boundary threshold: (C_A - C_TN) / (C_FN - C_TN)."""
        return (self.cost_abstain - self.cost_true_negative) / self.denominator_clean

    @property
    def theta_threat_clamped(self) -> float:
        """Clamped threat threshold saturated in [0.0, 1.0] for diagnostic reporting."""
        return max(0.0, min(1.0, self.raw_theta_threat))

    @property
    def theta_clean_clamped(self) -> float:
        """Clamped clean threshold saturated in [0.0, 1.0] for diagnostic reporting."""
        return max(0.0, min(1.0, self.raw_theta_clean))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "cost_false_negative": self.cost_false_negative,
            "cost_false_positive": self.cost_false_positive,
            "cost_abstain": self.cost_abstain,
            "cost_true_positive": self.cost_true_positive,
            "cost_true_negative": self.cost_true_negative,
            "raw_theta_threat": self.raw_theta_threat,
            "raw_theta_clean": self.raw_theta_clean,
            "theta_threat_clamped": self.theta_threat_clamped,
            "theta_clean_clamped": self.theta_clean_clamped,
        }


# Standard Illustrative Deployment Profiles (Non-Mandatory Presets)
DEFAULT_COST_PROFILES: Mapping[str, AsymmetricCostConfig] = {
    "analyst_triage": AsymmetricCostConfig(
        profile_name="analyst_triage",
        cost_false_negative=50.0,
        cost_false_positive=10.0,
        cost_abstain=2.0,
        cost_true_positive=0.0,
        cost_true_negative=0.0,
    ),
    "user_warning": AsymmetricCostConfig(
        profile_name="user_warning",
        cost_false_negative=80.0,
        cost_false_positive=15.0,
        cost_abstain=5.0,
        cost_true_positive=0.0,
        cost_true_negative=0.0,
    ),
    "enterprise_blocking": AsymmetricCostConfig(
        profile_name="enterprise_blocking",
        cost_false_negative=100.0,
        cost_false_positive=40.0,
        cost_abstain=10.0,
        cost_true_positive=0.0,
        cost_true_negative=0.0,
    ),
}


@dataclass(frozen=True)
class MinimaxEvaluationResult:
    """Result of evaluating worst-case operational costs across candidate actions.

    Attributes:
        optimal_action: The selected CandidateAction under minimax decision rule.
        is_tied: True if multiple actions achieved equivalent worst-case cost within tolerance.
        tied_actions: Sequence of candidate actions achieving near-optimal cost.
        worst_case_costs: Mapping from CandidateAction to computed worst-case expected cost.
        minimum_cost: The scalar minimum worst-case cost r_min.
        theta_threat_clamped: Diagnostic clamped threat threshold in [0.0, 1.0].
        theta_clean_clamped: Diagnostic clamped clean threshold in [0.0, 1.0].
        statistical_calibration_active: Always False until an authorized statistical model is fitted.
        rationale: Explanatory text summarizing the cost evaluation.
    """

    optimal_action: CandidateAction
    is_tied: bool
    tied_actions: Tuple[CandidateAction, ...]
    worst_case_costs: Mapping[str, float]
    minimum_cost: float
    theta_threat_clamped: float
    theta_clean_clamped: float
    statistical_calibration_active: bool = False
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "optimal_action": self.optimal_action.value,
            "is_tied": self.is_tied,
            "tied_actions": [a.value for a in self.tied_actions],
            "worst_case_costs": dict(self.worst_case_costs),
            "minimum_cost": self.minimum_cost,
            "theta_threat_clamped": self.theta_threat_clamped,
            "theta_clean_clamped": self.theta_clean_clamped,
            "statistical_calibration_active": self.statistical_calibration_active,
            "rationale": self.rationale,
        }


class MinimaxDecisionEngine:
    """Evaluates minimax expected costs over uncertainty intervals [lower_p, upper_p].

    Strict Invariant:
    Does NOT invent probabilities. Rejects invalid non-finite intervals and ordinal objects.
    Decisions are determined strictly by raw worst-case expected costs:
        R_bar(D_M) = lower_p * C_TP + (1 - lower_p) * C_FP
        R_bar(D_B) = upper_p * C_FN + (1 - upper_p) * C_TN
        R_bar(D_I) = C_A
    """

    def __init__(self, cost_config: Optional[AsymmetricCostConfig] = None):
        self.cost_config = cost_config or DEFAULT_COST_PROFILES["analyst_triage"]
        self.cost_config.validate()

    def evaluate_interval(
        self,
        lower_p: float,
        upper_p: float,
        statistical_source_authorized: bool = False,
    ) -> MinimaxEvaluationResult:
        """Evaluate minimax decision over valid probability interval [lower_p, upper_p].

        Raises:
            TypeError: If endpoints are not real floats or if an ordinal object is provided.
            ValueError: If endpoints are non-finite, NaN, out of [0.0, 1.0], or lower_p > upper_p.
        """
        if not isinstance(lower_p, (int, float)) or isinstance(lower_p, bool):
            raise TypeError(
                f"lower_p must be a real float, got {type(lower_p).__name__}. "
                "Ordinal confidence cannot be converted to numerical probability."
            )
        if not isinstance(upper_p, (int, float)) or isinstance(upper_p, bool):
            raise TypeError(
                f"upper_p must be a real float, got {type(upper_p).__name__}. "
                "Ordinal confidence cannot be converted to numerical probability."
            )

        if not math.isfinite(lower_p) or math.isnan(lower_p):
            raise ValueError(f"lower_p must be finite and not NaN, got {lower_p}")
        if not math.isfinite(upper_p) or math.isnan(upper_p):
            raise ValueError(f"upper_p must be finite and not NaN, got {upper_p}")

        if lower_p < 0.0 or lower_p > 1.0:
            raise ValueError(f"lower_p must be within [0.0, 1.0], got {lower_p}")
        if upper_p < 0.0 or upper_p > 1.0:
            raise ValueError(f"upper_p must be within [0.0, 1.0], got {upper_p}")
        if lower_p > upper_p:
            raise ValueError(f"lower_p ({lower_p}) cannot exceed upper_p ({upper_p})")

        # Complete expected cost equations evaluated at worst-case endpoints
        cfg = self.cost_config
        r_m = lower_p * cfg.cost_true_positive + (1.0 - lower_p) * cfg.cost_false_positive
        r_b = upper_p * cfg.cost_false_negative + (1.0 - upper_p) * cfg.cost_true_negative
        r_i = cfg.cost_abstain

        costs: Dict[CandidateAction, float] = {
            CandidateAction.THREAT: r_m,
            CandidateAction.CLEAN: r_b,
            CandidateAction.INCONCLUSIVE: r_i,
        }

        r_min = min(r_m, r_b, r_i)

        # Scale-invariant tie detection using math.isclose across all 3 candidate actions
        tied_candidates = [
            action
            for action in (CandidateAction.THREAT, CandidateAction.INCONCLUSIVE, CandidateAction.CLEAN)
            if is_cost_close(costs[action], r_min)
        ]

        is_tied = len(tied_candidates) > 1

        # Apply deterministic safety-first precedence hierarchy: D_I > D_M > D_B
        selected_action: CandidateAction = CandidateAction.INCONCLUSIVE
        for pref in DETERMINISTIC_ACTION_PRECEDENCE:
            if pref in tied_candidates:
                selected_action = pref
                break

        rationale = (
            f"Evaluated worst-case costs: D_M={r_m:.6f}, D_I={r_i:.6f}, D_B={r_b:.6f} "
            f"(r_min={r_min:.6f}). Selected {selected_action.value}"
            + (f" via deterministic precedence among {len(tied_candidates)} tied actions." if is_tied else ".")
        )

        return MinimaxEvaluationResult(
            optimal_action=selected_action,
            is_tied=is_tied,
            tied_actions=tuple(tied_candidates),
            worst_case_costs={a.value: c for a, c in costs.items()},
            minimum_cost=r_min,
            theta_threat_clamped=cfg.theta_threat_clamped,
            theta_clean_clamped=cfg.theta_clean_clamped,
            statistical_calibration_active=statistical_source_authorized,
            rationale=rationale,
        )


@dataclass(frozen=True)
class CostSensitivePolicyAssessment:
    """Configurable cost-sensitive triage assessment using supported deterministic inputs.

    Strict Invariant:
    Operates without fabricating probabilities. Integrates Phase 07 availability masks,
    evidence quality, and rule disposition ceilings with the configured cost profile.
    """

    cost_profile_name: str
    action_recommendation: CandidateAction
    disposition_input: str
    availability_status_vector: Mapping[str, str]
    confidence_band: str
    review_urgency: str  # "high", "normal", "low"
    cost_rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cost_profile_name": self.cost_profile_name,
            "action_recommendation": self.action_recommendation.value,
            "disposition_input": self.disposition_input,
            "availability_status_vector": dict(self.availability_status_vector),
            "confidence_band": self.confidence_band,
            "review_urgency": self.review_urgency,
            "cost_rationale": self.cost_rationale,
        }


class CostSensitivePolicyEvaluator:
    """Evaluates triage results against configured cost profiles using deterministic inputs."""

    def __init__(self, cost_config: Optional[AsymmetricCostConfig] = None):
        self.cost_config = cost_config or DEFAULT_COST_PROFILES["analyst_triage"]
        self.cost_config.validate()

    def assess_triage(
        self,
        decision: str,
        confidence_band: str,
        modality_statuses: Mapping[str, str],
        has_positive_threat: bool,
    ) -> CostSensitivePolicyAssessment:
        """Map deterministic triage outputs into cost-aware operational recommendations.

        Preserves:
        - Rule 1 (Positive threat evidence -> THREAT action recommendation).
        - Rule 5 (Clean requires complete baseline; missing/partial modalities -> INCONCLUSIVE).
        """
        cfg = self.cost_config

        # 1. Positive threat match always recommends THREAT containment
        if has_positive_threat or decision in ("confirmed_threat", "suspicious_threat"):
            urgency = "high" if cfg.cost_false_negative > cfg.cost_false_positive else "normal"
            return CostSensitivePolicyAssessment(
                cost_profile_name=cfg.profile_name,
                action_recommendation=CandidateAction.THREAT,
                disposition_input=decision,
                availability_status_vector=dict(modality_statuses),
                confidence_band=confidence_band,
                review_urgency=urgency,
                cost_rationale=(
                    f"Profile '{cfg.profile_name}': Verified threat signal overrides missing modalities "
                    f"to prevent false-negative operational penalty C_FN={cfg.cost_false_negative}."
                ),
            )

        # 2. If decision is already inconclusive, recommend INCONCLUSIVE
        if decision == "inconclusive":
            return CostSensitivePolicyAssessment(
                cost_profile_name=cfg.profile_name,
                action_recommendation=CandidateAction.INCONCLUSIVE,
                disposition_input=decision,
                availability_status_vector=dict(modality_statuses),
                confidence_band=confidence_band,
                review_urgency="normal",
                cost_rationale=(
                    f"Profile '{cfg.profile_name}': Triage engine determined inconclusive disposition. "
                    f"Routing to review queue at cost C_A={cfg.cost_abstain}."
                ),
            )

        # 3. Clean candidate: check modality completeness
        # Missing or failed modalities strictly prevent Clean recommendation under cost sensitivity.
        # Mandatory modalities for clean baseline are DNS, Threat Intel, and TLS (when applicable).
        # Community corroboration is optional and does not prevent clean recommendation.
        mandatory_modalities = {"dns", "threat_intel"}
        tls_status = modality_statuses.get("tls")
        if tls_status is not None and tls_status != "not_applicable":
            mandatory_modalities.add("tls")

        incomplete_modalities = [
            mod for mod, status in modality_statuses.items()
            if mod in mandatory_modalities and status not in ("observed_complete", "not_applicable")
        ]

        if incomplete_modalities:
            return CostSensitivePolicyAssessment(
                cost_profile_name=cfg.profile_name,
                action_recommendation=CandidateAction.INCONCLUSIVE,
                disposition_input=decision,
                availability_status_vector=dict(modality_statuses),
                confidence_band=confidence_band,
                review_urgency="normal",
                cost_rationale=(
                    f"Profile '{cfg.profile_name}': Clean baseline unverified due to incomplete modalities "
                    f"({', '.join(incomplete_modalities)}). Abstaining to avoid unvetted clean cost."
                ),
            )

        # 4. Verified clean baseline with complete modalities
        return CostSensitivePolicyAssessment(
            cost_profile_name=cfg.profile_name,
            action_recommendation=CandidateAction.CLEAN,
            disposition_input=decision,
            availability_status_vector=dict(modality_statuses),
            confidence_band=confidence_band,
            review_urgency="low",
            cost_rationale=(
                f"Profile '{cfg.profile_name}': Complete modality baseline verified without threat indicators. "
                f"Safe throughput at true-negative cost C_TN={cfg.cost_true_negative}."
            ),
        )
