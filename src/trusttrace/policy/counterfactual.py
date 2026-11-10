"""Deterministic Counterfactual Explanations & Boundary Sensitivity — Worker 03 Phase 09.

Provides deterministic evidence-boundary sensitivity analysis answering:
"What is the minimal set of signal modifications required to alter the policy triage decision?"

Strict Architectural Discipline:
1. Mathematical Sensitivity Only: Counterfactuals represent mathematical decision-boundary
   sensitivity under fixed policy rules. They do NOT constitute an operational security
   guarantee, endorsement, or real-world remediation certificate. Mandatory disclaimer is enforced.
2. In-Memory Simulation Only: Hypothetical modality completion and signal perturbations execute
   strictly in memory on ephemeral SignalRecord clones. Zero simulated evidence is ever written
   to PolicyInput.evidence_items, database, or report audit logs.
3. Codebase-Grounded Allowlist: Every perturbation maps to existing SignalKind members from
   signal_taxonomy.py. REMOVED is an operation type (PerturbationAction.REMOVE_SIGNAL),
   never an invented SignalKind.
4. Coordinated Modality Completion: In signal_extractor.py, TLS failure emits both
   TLS_UNAVAILABLE and COLLECTOR_FAILURE. Simulated completion coordinatedly mutates both to
   TLS_VALID and COLLECTOR_SUCCESS.
5. Strict Immutability: SignalKind.IDN_LOOKALIKE, domain registration age, and ASN/hosting
   properties are classified as IMMUTABLE_INTRINSIC and are strictly barred from perturbation.
6. Full Policy Re-Evaluation: Every candidate perturbation passes through complete TriageEngine
   evaluation and Step 7 ModalityAvailabilityGate.
7. Deterministic Tie-Breaking: Ranked by:
   (1) Hamming distance (minimal number of perturbed signals),
   (2) Composite feasibility penalty (MUTABLE_CONFIG=1.0, REPUTATION_DEPENDENT=5.0),
   (3) Lexicographical ordering on sorted (dimension, signal_kind, target_value).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .fusion import ModalityAvailabilityGate, ModalityClassifier, ModalityKind, parse_and_validate_target
from .policy_input import PolicyInput
from .signal_taxonomy import SignalConfidence, SignalDimension, SignalKind, SignalRecord
from .triage_engine import TriageEngine, TriageResult

# Mandatory Legal & Operational Disclaimer
COUNTERFACTUAL_DISCLAIMER: str = (
    "Hypothetical scenario based strictly on mathematical decision-boundary sensitivity. "
    "This analysis illustrates policy mechanics and does NOT constitute an operational "
    "security guarantee, endorsement, or remediation certificate."
)


class SignalFeasibility(str, Enum):
    """Feasibility of modifying a signal in real operational contexts."""

    MUTABLE_CONFIG = "mutable_configuration"        # Operator-controlled technical setting (e.g. renew cert)
    REPUTATION_DEPENDENT = "reputation_dependent"  # External third-party assessment (e.g. threat feed delisting)
    IMMUTABLE_INTRINSIC = "immutable_intrinsic"    # Structural, historical or brand property (PROHIBITED)


class PerturbationAction(str, Enum):
    """Type of perturbation applied to the signal vector."""

    REPLACE_SIGNAL = "replace_signal"          # Replaces one SignalKind with another
    REMOVE_SIGNAL = "remove_signal"            # Eliminates an artifact signal
    COORDINATED_MUTATION = "coordinated_mut"   # Multi-signal coordinated swap (e.g. TLS modality completion)


@dataclass(frozen=True)
class PermittedMutationRule:
    """Specification of an authorized signal perturbation rule."""

    rule_name: str
    source_kinds: Tuple[SignalKind, ...]
    action: PerturbationAction
    destination_kinds: Tuple[SignalKind, ...]
    feasibility: SignalFeasibility
    cost_weight: float
    description: str


# Permitted Mutation Rules Grounded in signal_taxonomy.py and signal_extractor.py
PERMITTED_MUTATION_RULES: Tuple[PermittedMutationRule, ...] = (
    # 1. Coordinated Modality Completion (TLS Failure -> Valid & Success)
    PermittedMutationRule(
        rule_name="complete_tls_modality",
        source_kinds=(SignalKind.TLS_UNAVAILABLE, SignalKind.COLLECTOR_FAILURE),
        action=PerturbationAction.COORDINATED_MUTATION,
        destination_kinds=(SignalKind.TLS_VALID, SignalKind.COLLECTOR_SUCCESS),
        feasibility=SignalFeasibility.MUTABLE_CONFIG,
        cost_weight=1.0,
        description="Simulate complete TLS availability (replaces TLS_UNAVAILABLE and COLLECTOR_FAILURE with TLS_VALID and COLLECTOR_SUCCESS).",
    ),
    # 2. Renew Expired Certificate
    PermittedMutationRule(
        rule_name="renew_expired_tls",
        source_kinds=(SignalKind.TLS_EXPIRED,),
        action=PerturbationAction.REPLACE_SIGNAL,
        destination_kinds=(SignalKind.TLS_VALID,),
        feasibility=SignalFeasibility.MUTABLE_CONFIG,
        cost_weight=1.0,
        description="Simulate renewing an expired TLS certificate with valid hostname coverage.",
    ),
    # 3. Correct Certificate Hostname Mismatch
    PermittedMutationRule(
        rule_name="correct_tls_mismatch",
        source_kinds=(SignalKind.TLS_MISMATCH,),
        action=PerturbationAction.REPLACE_SIGNAL,
        destination_kinds=(SignalKind.TLS_VALID,),
        feasibility=SignalFeasibility.MUTABLE_CONFIG,
        cost_weight=1.0,
        description="Simulate reissuing certificate to include matching hostname in SAN list.",
    ),
    # 4. Eliminate HTTP Suspicious Redirect Artifact
    PermittedMutationRule(
        rule_name="eliminate_suspicious_redirect",
        source_kinds=(SignalKind.SUSPICIOUS_REDIRECT,),
        action=PerturbationAction.REMOVE_SIGNAL,
        destination_kinds=(),
        feasibility=SignalFeasibility.MUTABLE_CONFIG,
        cost_weight=1.0,
        description="Simulate clean HTTP redirect hops by removing suspicious redirect artifact.",
    ),
    # 5. Eliminate HTTP Suspicious Headers Artifact
    PermittedMutationRule(
        rule_name="eliminate_suspicious_headers",
        source_kinds=(SignalKind.SUSPICIOUS_HEADERS,),
        action=PerturbationAction.REMOVE_SIGNAL,
        destination_kinds=(),
        feasibility=SignalFeasibility.MUTABLE_CONFIG,
        cost_weight=1.0,
        description="Simulate clean HTTP response headers by removing suspicious headers artifact.",
    ),
    # 6. External Threat Intelligence Delisting (High Latency / Dispute)
    PermittedMutationRule(
        rule_name="threat_feed_delisting",
        source_kinds=(SignalKind.THREAT_FEED_MATCH,),
        action=PerturbationAction.REPLACE_SIGNAL,
        destination_kinds=(SignalKind.NO_THREAT_MATCH,),
        feasibility=SignalFeasibility.REPUTATION_DEPENDENT,
        cost_weight=5.0,
        description="Simulate external third-party delisting from blocklist (replaces THREAT_FEED_MATCH with NO_THREAT_MATCH).",
    ),
    # 7. Community Report Dispute Resolution
    PermittedMutationRule(
        rule_name="resolve_community_dispute",
        source_kinds=(SignalKind.COMMUNITY_REPORT_DISPUTED,),
        action=PerturbationAction.REPLACE_SIGNAL,
        destination_kinds=(SignalKind.COMMUNITY_REPORT_CORROBORATED,),
        feasibility=SignalFeasibility.REPUTATION_DEPENDENT,
        cost_weight=5.0,
        description="Simulate resolving community dispute into verified corroboration.",
    ),
    # 8. Community Unverified Report Removal
    PermittedMutationRule(
        rule_name="remove_unverified_community_report",
        source_kinds=(SignalKind.COMMUNITY_REPORT_UNVERIFIED,),
        action=PerturbationAction.REMOVE_SIGNAL,
        destination_kinds=(),
        feasibility=SignalFeasibility.REPUTATION_DEPENDENT,
        cost_weight=5.0,
        description="Simulate removing unsubstantiated community user report.",
    ),
)

# Strictly Prohibited Signals from Perturbation (Intrinsic / Historical)
STRICTLY_IMMUTABLE_SIGNALS: Set[SignalKind] = {
    SignalKind.IDN_LOOKALIKE,  # Lexical punycode/homograph structure of registered domain
}


@dataclass(frozen=True)
class CounterfactualPerturbation:
    """A single applied hypothetical perturbation."""

    rule_name: str
    action: PerturbationAction
    removed_signals: Tuple[str, ...]
    added_signals: Tuple[str, ...]
    feasibility: SignalFeasibility
    cost_weight: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "action": self.action.value,
            "removed_signals": list(self.removed_signals),
            "added_signals": list(self.added_signals),
            "feasibility": self.feasibility.value,
            "cost_weight": self.cost_weight,
            "description": self.description,
        }


@dataclass(frozen=True)
class CounterfactualResult:
    """Complete result of a counterfactual sensitivity search."""

    original_disposition: str
    target_disposition: str
    status: str  # "SUCCESS", "UNREACHABLE", "NO_PERTURBATION_NEEDED", "INVALID_TARGET"
    perturbations: Tuple[CounterfactualPerturbation, ...]
    hamming_distance: int
    feasibility_score: float
    resulting_disposition: str
    resulting_findings: Tuple[str, ...]
    explanation: str
    disclaimer: str = COUNTERFACTUAL_DISCLAIMER

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_disposition": self.original_disposition,
            "target_disposition": self.target_disposition,
            "status": self.status,
            "perturbations": [p.to_dict() for p in self.perturbations],
            "hamming_distance": self.hamming_distance,
            "feasibility_score": self.feasibility_score,
            "resulting_disposition": self.resulting_disposition,
            "resulting_findings": list(self.resulting_findings),
            "explanation": self.explanation,
            "disclaimer": self.disclaimer,
        }


class CounterfactualExplanationEngine:
    """Calculates minimal, deterministic decision-boundary sensitivity counterfactuals.

    Strict Invariants:
    1. Operates on in-memory ephemeral signal clones. Zero persistent state mutation.
    2. Enforces search limit (k <= max_depth, default 3).
    3. Deterministic tie-breaking: (Hamming, Feasibility Penalty, Lexicographical tuple).
    4. Prohibits mutating SignalKind.IDN_LOOKALIKE and intrinsic structural signals.
    """

    def __init__(
        self,
        triage_engine: Optional[TriageEngine] = None,
        max_search_depth: int = 3,
    ):
        self.triage_engine = triage_engine or TriageEngine()
        self.max_search_depth = max_search_depth

    def evaluate_sensitivity(
        self,
        signals: Sequence[SignalRecord],
        target_disposition: str,
        scan_id: str = "sim-scan-001",
        target: Optional[str] = None,
    ) -> CounterfactualResult:
        """Find the minimal set of signal modifications required to transition to target_disposition."""
        # 1. Baseline evaluation of original signals
        base_result = self.triage_engine.evaluate(
            signals=list(signals),
            scan_id=scan_id,
        )
        original_disp = base_result.decision

        if original_disp == target_disposition:
            return CounterfactualResult(
                original_disposition=original_disp,
                target_disposition=target_disposition,
                status="NO_PERTURBATION_NEEDED",
                perturbations=(),
                hamming_distance=0,
                feasibility_score=0.0,
                resulting_disposition=original_disp,
                resulting_findings=tuple(f["finding_id"] for f in base_result.findings),
                explanation=f"Current triage disposition is already '{target_disposition}'. No perturbation needed.",
            )

        # 2. Check for presence of immutable signals
        immutable_present = [s.kind for s in signals if s.kind in STRICTLY_IMMUTABLE_SIGNALS]

        # 3. Determine applicable perturbation rules for current signals
        applicable_rules: List[PermittedMutationRule] = []
        for rule in PERMITTED_MUTATION_RULES:
            if all(any(s.kind == src for s in signals) for src in rule.source_kinds):
                applicable_rules.append(rule)

        if not applicable_rules:
            explanation = (
                f"No applicable perturbation rules found for current signals. "
                f"Target disposition '{target_disposition}' is unreachable from baseline."
            )
            if immutable_present:
                explanation += f" Immutable signals present: {[k.value for k in immutable_present]}."
            return CounterfactualResult(
                original_disposition=original_disp,
                target_disposition=target_disposition,
                status="UNREACHABLE",
                perturbations=(),
                hamming_distance=0,
                feasibility_score=float("inf"),
                resulting_disposition=original_disp,
                resulting_findings=tuple(f["finding_id"] for f in base_result.findings),
                explanation=explanation,
            )

        # 4. Search minimal combinations up to max_search_depth (default 3)
        candidate_solutions: List[Tuple[int, float, Tuple[str, ...], Tuple[CounterfactualPerturbation, ...], TriageResult]] = []

        from itertools import combinations

        for k in range(1, min(len(applicable_rules) + 1, self.max_search_depth + 1)):
            for rule_combo in combinations(applicable_rules, k):
                # Apply combo to an ephemeral in-memory clone of signals
                simulated_signals, applied_perturbations = self._apply_rule_combo(signals, rule_combo)

                # Re-evaluate complete policy on simulated signals
                sim_result = self.triage_engine.evaluate(
                    signals=simulated_signals,
                    scan_id=f"{scan_id}-sim",
                )

                if sim_result.decision == target_disposition:
                    hamming = len(applied_perturbations)
                    feasibility_penalty = sum(p.cost_weight for p in applied_perturbations)
                    lex_key = tuple(sorted(p.rule_name for p in applied_perturbations))
                    candidate_solutions.append(
                        (hamming, feasibility_penalty, lex_key, applied_perturbations, sim_result)
                    )

            if candidate_solutions:
                # Found solutions at depth k; stop searching deeper to guarantee minimal Hamming distance
                break

        if not candidate_solutions:
            return CounterfactualResult(
                original_disposition=original_disp,
                target_disposition=target_disposition,
                status="UNREACHABLE",
                perturbations=(),
                hamming_distance=0,
                feasibility_score=float("inf"),
                resulting_disposition=original_disp,
                resulting_findings=tuple(f["finding_id"] for f in base_result.findings),
                explanation=(
                    f"Target disposition '{target_disposition}' cannot be reached within "
                    f"maximum search depth k={self.max_search_depth}."
                ),
            )

        # 5. Deterministic tie-breaking:
        # Sorted by: (1) Hamming distance, (2) Feasibility penalty, (3) Lexicographical key
        candidate_solutions.sort(key=lambda item: (item[0], item[1], item[2]))
        best_hamming, best_feasibility, _, best_perturbations, best_sim_result = candidate_solutions[0]

        rule_summaries = [f"{p.rule_name} ({p.feasibility.value})" for p in best_perturbations]
        explanation = (
            f"Minimal counterfactual found ({len(best_perturbations)} perturbation(s), "
            f"feasibility penalty={best_feasibility:.1f}): "
            + "; ".join(rule_summaries)
            + f" transitions disposition from '{original_disp}' to '{target_disposition}'."
        )

        return CounterfactualResult(
            original_disposition=original_disp,
            target_disposition=target_disposition,
            status="SUCCESS",
            perturbations=best_perturbations,
            hamming_distance=best_hamming,
            feasibility_score=best_feasibility,
            resulting_disposition=best_sim_result.decision,
            resulting_findings=tuple(f["finding_id"] for f in best_sim_result.findings),
            explanation=explanation,
        )

    def _apply_rule_combo(
        self,
        original_signals: Sequence[SignalRecord],
        rules: Sequence[PermittedMutationRule],
    ) -> Tuple[List[SignalRecord], Tuple[CounterfactualPerturbation, ...]]:
        """Apply a combination of perturbation rules to an ephemeral in-memory copy of signals."""
        current_signals: List[SignalRecord] = list(original_signals)
        applied: List[CounterfactualPerturbation] = []

        for rule in rules:
            # 1. Identify signals to remove
            removed_records = [s for s in current_signals if s.kind in rule.source_kinds]
            current_signals = [s for s in current_signals if s.kind not in rule.source_kinds]

            # 2. Identify signals to add
            added_records: List[SignalRecord] = []
            for dest_kind in rule.destination_kinds:
                # Inherit evidence_ids and source from first removed record, or use placeholder
                ev_ids = removed_records[0].evidence_ids if removed_records else ["sim-ev-001"]
                src = removed_records[0].source if removed_records else "simulated_counterfactual"
                added_records.append(
                    SignalRecord(
                        kind=dest_kind,
                        evidence_ids=list(ev_ids),
                        source=f"simulated_{src}",
                        confidence=SignalConfidence.HIGH_CONFIDENCE,
                    )
                )

            current_signals.extend(added_records)

            applied.append(
                CounterfactualPerturbation(
                    rule_name=rule.rule_name,
                    action=rule.action,
                    removed_signals=tuple(s.kind.value for s in removed_records),
                    added_signals=tuple(s.kind.value for s in added_records),
                    feasibility=rule.feasibility,
                    cost_weight=rule.cost_weight,
                    description=rule.description,
                )
            )

        return current_signals, tuple(applied)
