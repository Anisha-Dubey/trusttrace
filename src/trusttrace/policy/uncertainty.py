"""Uncertainty quantification and abstention engine — Worker 03 Phase 04.

Implements structured uncertainty modeling distinguishing:
- DATA_ABSENCE: A required observation was not available or not supplied.
- COLLECTION_FAILURE: A collector explicitly failed or timed out.
- UNCHECKED_COVERAGE: A check was not run, target was safety-blocked, or budget exhausted.
- TEMPORAL_STALENESS: Evidence is outside an explicitly configured, source-specific freshness window.
- EVIDENCE_CONFLICT: Genuine contemporaneous contradiction for the same target and scope.

Also provides:
- ConfidenceBand: Ordinal policy categories (NOT calibrated probabilities).
- FreshnessPolicy: Configurable source-specific time windows.
- AbstentionNotice: Explicit, plain-language rationales when policy abstains or caps at inconclusive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .policy_input import CoverageSummary, EvidenceItem, PolicyInput
from .signal_taxonomy import SignalDimension, SignalKind, SignalRecord


class UncertaintyType(str, Enum):
    """Categorical classification of evidence and assessment uncertainty."""

    DATA_ABSENCE = "data_absence"
    COLLECTION_FAILURE = "collection_failure"
    UNCHECKED_COVERAGE = "unchecked_coverage"
    TEMPORAL_STALENESS = "temporal_staleness"
    EVIDENCE_CONFLICT = "evidence_conflict"


class ConfidenceBand(str, Enum):
    """Ordinal confidence band representing assessment grounding.

    CRITICAL INVARIANT: These are policy categories, NOT calibrated numeric probabilities.
    Never present weighted scores or heuristic metrics as mathematical probabilities.
    """

    SUFFICIENT_FOR_SCOPED_OBSERVATION = "sufficient_for_scoped_observation"
    LIMITED_OBSERVATION = "limited_observation"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONTRADICTORY_EVIDENCE = "contradictory_evidence"


# Default freshness windows in seconds:
# DNS: 24h (86400s)
# TLS certificate: 7 days (604800s)
# Threat intelligence / reputation: 12h (43200s)
# HTTP headers / redirect: 24h (86400s)
# Community reports: 48h (172800s)
# Default fallback: 7 days (604800s)
DEFAULT_FRESHNESS_WINDOWS: Mapping[str, int] = MappingProxyType({
    "dns": 86400,
    "dns_resolution": 86400,
    "threat_intel": 43200,
    "threat_feed": 43200,
    "reputation": 43200,
    "http": 86400,
    "http_headers": 86400,
    "redirect_chain": 86400,
    "tls": 604800,
    "tls_certificate": 604800,
    "tls_hostname_validation": 604800,
    "community_report": 172800,
    "default": 604800,
})


@dataclass(frozen=True)
class FreshnessPolicy:
    """Configurable freshness windows per source family or collector kind."""

    windows: Mapping[str, int] = DEFAULT_FRESHNESS_WINDOWS

    def get_window(self, kind: str) -> int:
        """Return the maximum freshness window in seconds for the given kind."""
        k = kind.strip().lower()
        if k in self.windows:
            return self.windows[k]
        # Check prefix match (e.g. 'threat_feed_match' -> 'threat_feed')
        for prefix, win in self.windows.items():
            if k.startswith(prefix):
                return win
        return self.windows.get("default", 604800)

    def evaluate_freshness(
        self,
        kind: str,
        observed_at_iso: str,
        now_dt: Optional[datetime] = None,
    ) -> Tuple[bool, float, int]:
        """Evaluate if an observation timestamp is stale.

        Returns:
            Tuple of (is_stale, age_seconds, max_allowed_seconds).
        """
        max_allowed = self.get_window(kind)
        now = now_dt or datetime.now(timezone.utc)

        try:
            ts_clean = observed_at_iso.strip()
            if ts_clean.endswith("Z"):
                ts_clean = ts_clean[:-1] + "+00:00"
            obs_dt = datetime.fromisoformat(ts_clean)
            if obs_dt.tzinfo is None:
                obs_dt = obs_dt.replace(tzinfo=timezone.utc)
        except Exception:
            # If timestamp cannot be parsed, treat as stale
            return True, float("inf"), max_allowed

        age_seconds = max(0.0, (now - obs_dt).total_seconds())
        is_stale = age_seconds > max_allowed
        return is_stale, age_seconds, max_allowed


@dataclass(frozen=True)
class UncertaintyRecord:
    """A granular observation of uncertainty encountered during evaluation."""

    uncertainty_type: UncertaintyType
    affected_dimensions: Tuple[str, ...]
    evidence_ids: Tuple[str, ...] = ()
    collector_or_check: str = ""
    target_scope: Optional[str] = None
    explanation: str = ""
    details: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uncertainty_type": self.uncertainty_type.value,
            "affected_dimensions": list(self.affected_dimensions),
            "evidence_ids": list(self.evidence_ids),
            "collector_or_check": self.collector_or_check,
            "target_scope": self.target_scope,
            "explanation": self.explanation,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class AbstentionNotice:
    """Explicit human-readable explanation when triage policy abstains or caps at inconclusive."""

    reason_code: str
    affected_dimensions: Tuple[str, ...]
    missing_or_failed_checks: Tuple[str, ...]
    target_scope: Optional[str]
    is_rescan_recommended: bool
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reason_code": self.reason_code,
            "affected_dimensions": list(self.affected_dimensions),
            "missing_or_failed_checks": list(self.missing_or_failed_checks),
            "target_scope": self.target_scope,
            "is_rescan_recommended": self.is_rescan_recommended,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class UncertaintyAssessment:
    """Complete uncertainty evaluation for a policy triage result."""

    confidence_band: ConfidenceBand
    uncertainties: Tuple[UncertaintyRecord, ...]
    abstention_notice: Optional[AbstentionNotice]
    affected_dimensions: Mapping[str, Tuple[UncertaintyType, ...]]
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "confidence_band": self.confidence_band.value,
            "uncertainties": [u.to_dict() for u in self.uncertainties],
            "abstention_notice": self.abstention_notice.to_dict() if self.abstention_notice else None,
            "affected_dimensions": {k: [ut.value for ut in v] for k, v in self.affected_dimensions.items()},
            "rationale": self.rationale,
        }


class UncertaintyEngine:
    """Analyzes evidence, coverage, and signals to quantify uncertainty and generate abstentions."""

    def __init__(self, freshness_policy: Optional[FreshnessPolicy] = None):
        self.freshness_policy = freshness_policy or FreshnessPolicy()

    def assess_evidence(
        self,
        policy_input: PolicyInput,
        signals: Sequence[SignalRecord],
        decision: str,
        dimensions: Dict[str, str],
    ) -> UncertaintyAssessment:
        """Perform comprehensive uncertainty assessment from canonical PolicyInput and signals."""
        records: List[UncertaintyRecord] = []
        dim_map: Dict[str, Set[UncertaintyType]] = {
            "identity": set(),
            "certificate": set(),
            "behavior": set(),
            "evidence_quality": set(),
        }

        # 1. Inspect Coverage Metadata (Unchecked Coverage / Collection Failure)
        failed_checks: List[str] = []
        not_run_checks: List[str] = []

        if policy_input.coverage is not None:
            cov = policy_input.coverage

            if cov.checks_failed > 0:
                failed_checks.append(f"{cov.checks_failed} failed checks")
                rec = UncertaintyRecord(
                    uncertainty_type=UncertaintyType.COLLECTION_FAILURE,
                    affected_dimensions=("evidence_quality",),
                    collector_or_check="coverage_summary",
                    target_scope=policy_input.target,
                    explanation=f"{cov.checks_failed} collector check(s) failed execution.",
                    details=MappingProxyType({"failed_count": cov.checks_failed}),
                )
                records.append(rec)
                dim_map["evidence_quality"].add(UncertaintyType.COLLECTION_FAILURE)

            if cov.checks_not_run > 0:
                not_run_checks.append(f"{cov.checks_not_run} not-run checks")
                rec = UncertaintyRecord(
                    uncertainty_type=UncertaintyType.UNCHECKED_COVERAGE,
                    affected_dimensions=("evidence_quality",),
                    collector_or_check="coverage_summary",
                    target_scope=policy_input.target,
                    explanation=f"{cov.checks_not_run} planned check(s) were not run or blocked.",
                    details=MappingProxyType({"not_run_count": cov.checks_not_run}),
                )
                records.append(rec)
                dim_map["evidence_quality"].add(UncertaintyType.UNCHECKED_COVERAGE)

        # 2. Inspect Raw Evidence Items for Failures, Blocked Destination, and Staleness
        for item in policy_input.evidence:
            # Collection failures
            if item.status in ("failed", "unavailable"):
                dim = self._map_kind_to_dimension(item.kind)
                rec = UncertaintyRecord(
                    uncertainty_type=UncertaintyType.COLLECTION_FAILURE,
                    affected_dimensions=(dim, "evidence_quality"),
                    evidence_ids=(item.evidence_id,),
                    collector_or_check=item.source,
                    target_scope=policy_input.target,
                    explanation=f"Collector '{item.source}' reported status '{item.status}' for kind '{item.kind}'.",
                )
                records.append(rec)
                dim_map[dim].add(UncertaintyType.COLLECTION_FAILURE)
                dim_map["evidence_quality"].add(UncertaintyType.COLLECTION_FAILURE)
                if item.source not in failed_checks:
                    failed_checks.append(item.source)

            # Blocked / Not Run (Safety Gate or Policy Block)
            elif item.status in ("blocked", "not_run"):
                dim = self._map_kind_to_dimension(item.kind)
                rec = UncertaintyRecord(
                    uncertainty_type=UncertaintyType.UNCHECKED_COVERAGE,
                    affected_dimensions=(dim, "evidence_quality"),
                    evidence_ids=(item.evidence_id,),
                    collector_or_check=item.source,
                    target_scope=policy_input.target,
                    explanation=f"Check for '{item.kind}' was '{item.status}' by policy or safety budget.",
                )
                records.append(rec)
                dim_map[dim].add(UncertaintyType.UNCHECKED_COVERAGE)
                dim_map["evidence_quality"].add(UncertaintyType.UNCHECKED_COVERAGE)
                if item.source not in not_run_checks:
                    not_run_checks.append(item.source)

            # Temporal Staleness evaluation
            if item.status == "observed" and item.observed_at:
                is_stale, age, max_win = self.freshness_policy.evaluate_freshness(
                    item.kind, item.observed_at
                )
                if is_stale:
                    dim = self._map_kind_to_dimension(item.kind)
                    rec = UncertaintyRecord(
                        uncertainty_type=UncertaintyType.TEMPORAL_STALENESS,
                        affected_dimensions=(dim, "evidence_quality"),
                        evidence_ids=(item.evidence_id,),
                        collector_or_check=item.source,
                        target_scope=policy_input.target,
                        explanation=f"Evidence '{item.kind}' ({item.evidence_id}) is stale: age {int(age)}s exceeds freshness window {max_win}s.",
                        details=MappingProxyType({"age_seconds": age, "max_allowed_seconds": max_win}),
                    )
                    records.append(rec)
                    dim_map[dim].add(UncertaintyType.TEMPORAL_STALENESS)
                    dim_map["evidence_quality"].add(UncertaintyType.TEMPORAL_STALENESS)

        # 3. Inspect Missing Required Dimensions (Data Absence)
        if dimensions.get("certificate") in ("not_checked", "unknown"):
            rec = UncertaintyRecord(
                uncertainty_type=UncertaintyType.DATA_ABSENCE,
                affected_dimensions=("certificate",),
                collector_or_check="tls_collector",
                target_scope=policy_input.target,
                explanation="No valid or conclusive TLS certificate evidence supplied.",
            )
            records.append(rec)
            dim_map["certificate"].add(UncertaintyType.DATA_ABSENCE)

        if dimensions.get("identity") == "unknown":
            rec = UncertaintyRecord(
                uncertainty_type=UncertaintyType.DATA_ABSENCE,
                affected_dimensions=("identity",),
                collector_or_check="identity_authorizer",
                target_scope=policy_input.target,
                explanation="No domain authorization or identity provenance evidence available.",
            )
            records.append(rec)
            dim_map["identity"].add(UncertaintyType.DATA_ABSENCE)

        # 4. Inspect Contemporaneous Evidence Conflict
        conflict_records = self._detect_evidence_conflicts(signals, policy_input.target)
        records.extend(conflict_records)
        for cr in conflict_records:
            for d in cr.affected_dimensions:
                dim_map[d].add(UncertaintyType.EVIDENCE_CONFLICT)

        # 5. Derive Ordinal ConfidenceBand
        has_conflict = any(r.uncertainty_type == UncertaintyType.EVIDENCE_CONFLICT for r in records)
        has_failure = any(r.uncertainty_type == UncertaintyType.COLLECTION_FAILURE for r in records)
        has_unchecked = any(r.uncertainty_type == UncertaintyType.UNCHECKED_COVERAGE for r in records)
        has_stale = any(r.uncertainty_type == UncertaintyType.TEMPORAL_STALENESS for r in records)
        all_failed = (
            dimensions.get("evidence_quality") == "unavailable"
            or (len(policy_input.evidence) > 0 and all(e.status in ("failed", "unavailable") for e in policy_input.evidence))
        )

        if has_conflict:
            band = ConfidenceBand.CONTRADICTORY_EVIDENCE
            rationale = "Contemporaneous contradictory observations detected for the same target and scope."
        elif all_failed or (decision == "inconclusive" and (has_failure and not any(e.status == "observed" for e in policy_input.evidence))):
            band = ConfidenceBand.INSUFFICIENT_EVIDENCE
            rationale = "Insufficient successful evidence collected to support an affirmative policy disposition."
        elif has_unchecked or has_failure or has_stale or dimensions.get("evidence_quality") in ("partial", "weak"):
            band = ConfidenceBand.LIMITED_OBSERVATION
            rationale = "Assessment grounded in limited observation; some checks failed, were not run, or were stale."
        else:
            band = ConfidenceBand.SUFFICIENT_FOR_SCOPED_OBSERVATION
            rationale = "All planned collectors succeeded within freshness windows for the scoped target."

        # 6. Formulate Abstention Notice when Inconclusive or Conflict
        abstention: Optional[AbstentionNotice] = None
        if decision == "inconclusive" or band in (ConfidenceBand.CONTRADICTORY_EVIDENCE, ConfidenceBand.INSUFFICIENT_EVIDENCE):
            abstention = self._build_abstention_notice(
                decision=decision,
                band=band,
                target_scope=policy_input.target,
                failed_checks=failed_checks,
                not_run_checks=not_run_checks,
                records=records,
            )

        return UncertaintyAssessment(
            confidence_band=band,
            uncertainties=tuple(records),
            abstention_notice=abstention,
            affected_dimensions=MappingProxyType({k: tuple(v) for k, v in dim_map.items()}),
            rationale=rationale,
        )

    def assess_signals(
        self,
        signals: Sequence[SignalRecord],
        decision: str,
        dimensions: Dict[str, str],
        target_scope: Optional[str] = None,
    ) -> UncertaintyAssessment:
        """Lightweight assessment when only signals are directly available (e.g. unit tests/fixtures)."""
        records: List[UncertaintyRecord] = []
        dim_map: Dict[str, Set[UncertaintyType]] = {
            "identity": set(),
            "certificate": set(),
            "behavior": set(),
            "evidence_quality": set(),
        }

        failed_checks: List[str] = []
        for s in signals:
            if s.kind in (SignalKind.COLLECTOR_FAILURE, SignalKind.TLS_UNAVAILABLE):
                rec = UncertaintyRecord(
                    uncertainty_type=UncertaintyType.COLLECTION_FAILURE,
                    affected_dimensions=(s.dimension.value, "evidence_quality"),
                    evidence_ids=tuple(s.evidence_ids),
                    collector_or_check=s.source,
                    target_scope=target_scope,
                    explanation=f"Signal {s.kind.value} from {s.source} indicates collector failure.",
                )
                records.append(rec)
                dim_map[s.dimension.value].add(UncertaintyType.COLLECTION_FAILURE)
                dim_map["evidence_quality"].add(UncertaintyType.COLLECTION_FAILURE)
                failed_checks.append(s.source)
            elif s.kind == SignalKind.STALE_EVIDENCE:
                rec = UncertaintyRecord(
                    uncertainty_type=UncertaintyType.TEMPORAL_STALENESS,
                    affected_dimensions=(s.dimension.value, "evidence_quality"),
                    evidence_ids=tuple(s.evidence_ids),
                    collector_or_check=s.source,
                    target_scope=target_scope,
                    explanation=f"Signal indicates stale evidence from {s.source}.",
                )
                records.append(rec)
                dim_map[s.dimension.value].add(UncertaintyType.TEMPORAL_STALENESS)
                dim_map["evidence_quality"].add(UncertaintyType.TEMPORAL_STALENESS)

        # Conflict check
        conflict_records = self._detect_evidence_conflicts(signals, target_scope)
        records.extend(conflict_records)
        for cr in conflict_records:
            for d in cr.affected_dimensions:
                dim_map[d].add(UncertaintyType.EVIDENCE_CONFLICT)

        has_conflict = any(r.uncertainty_type == UncertaintyType.EVIDENCE_CONFLICT for r in records)
        has_failure = any(r.uncertainty_type == UncertaintyType.COLLECTION_FAILURE for r in records)
        all_failed = dimensions.get("evidence_quality") == "unavailable" and not any(
            s.kind == SignalKind.COLLECTOR_SUCCESS for s in signals
        )

        if has_conflict:
            band = ConfidenceBand.CONTRADICTORY_EVIDENCE
            rationale = "Contradictory signals present across sources."
        elif all_failed or (decision == "inconclusive" and has_failure and not any(s.kind == SignalKind.COLLECTOR_SUCCESS for s in signals)):
            band = ConfidenceBand.INSUFFICIENT_EVIDENCE
            rationale = "Insufficient evidence to draw a conclusion."
        elif has_failure or dimensions.get("evidence_quality") in ("partial", "weak"):
            band = ConfidenceBand.LIMITED_OBSERVATION
            rationale = "Assessment grounded in partial or limited observations."
        else:
            band = ConfidenceBand.SUFFICIENT_FOR_SCOPED_OBSERVATION
            rationale = "Signals provide sufficient basis for scoped disposition."

        abstention: Optional[AbstentionNotice] = None
        if decision == "inconclusive" or band in (ConfidenceBand.CONTRADICTORY_EVIDENCE, ConfidenceBand.INSUFFICIENT_EVIDENCE):
            abstention = self._build_abstention_notice(
                decision=decision,
                band=band,
                target_scope=target_scope,
                failed_checks=failed_checks,
                not_run_checks=[],
                records=records,
            )

        return UncertaintyAssessment(
            confidence_band=band,
            uncertainties=tuple(records),
            abstention_notice=abstention,
            affected_dimensions=MappingProxyType({k: tuple(v) for k, v in dim_map.items()}),
            rationale=rationale,
        )

    def _detect_evidence_conflicts(
        self,
        signals: Sequence[SignalRecord],
        target_scope: Optional[str],
    ) -> List[UncertaintyRecord]:
        """Detect genuine contemporaneous contradictions across signals."""
        records: List[UncertaintyRecord] = []
        kinds = {s.kind for s in signals}

        # 1. Behavioral contradiction: THREAT_FEED_MATCH vs NO_THREAT_MATCH
        if SignalKind.THREAT_FEED_MATCH in kinds and SignalKind.NO_THREAT_MATCH in kinds:
            threat_sigs = [s for s in signals if s.kind == SignalKind.THREAT_FEED_MATCH]
            no_threat_sigs = [s for s in signals if s.kind == SignalKind.NO_THREAT_MATCH]
            ev_ids = tuple(
                eid
                for s in (threat_sigs + no_threat_sigs)
                for eid in s.evidence_ids
            )
            records.append(
                UncertaintyRecord(
                    uncertainty_type=UncertaintyType.EVIDENCE_CONFLICT,
                    affected_dimensions=("behavior", "evidence_quality"),
                    evidence_ids=ev_ids,
                    collector_or_check="threat_feed_providers",
                    target_scope=target_scope,
                    explanation=(
                        "Contemporaneous provider observations materially disagree: one provider reports a threat match "
                        "while another reports no threat observed for the target and time window (EVID-004)."
                    ),
                )
            )

        # 2. Certificate contradiction: TLS_VALID vs TLS_EXPIRED / TLS_MISMATCH
        if SignalKind.TLS_VALID in kinds and (
            SignalKind.TLS_EXPIRED in kinds or SignalKind.TLS_MISMATCH in kinds
        ):
            cert_sigs = [
                s for s in signals
                if s.kind in (SignalKind.TLS_VALID, SignalKind.TLS_EXPIRED, SignalKind.TLS_MISMATCH)
            ]
            ev_ids = tuple(eid for s in cert_sigs for eid in s.evidence_ids)
            records.append(
                UncertaintyRecord(
                    uncertainty_type=UncertaintyType.EVIDENCE_CONFLICT,
                    affected_dimensions=("certificate", "evidence_quality"),
                    evidence_ids=ev_ids,
                    collector_or_check="tls_collector",
                    target_scope=target_scope,
                    explanation=(
                        "Conflicting TLS observations: both valid certificate and invalid/expired certificate records present."
                    ),
                )
            )

        # 3. Community report contradiction: CORROBORATED vs DISPUTED
        if (
            SignalKind.COMMUNITY_REPORT_CORROBORATED in kinds
            and SignalKind.COMMUNITY_REPORT_DISPUTED in kinds
        ):
            comm_sigs = [
                s for s in signals
                if s.kind in (SignalKind.COMMUNITY_REPORT_CORROBORATED, SignalKind.COMMUNITY_REPORT_DISPUTED)
            ]
            ev_ids = tuple(eid for s in comm_sigs for eid in s.evidence_ids)
            records.append(
                UncertaintyRecord(
                    uncertainty_type=UncertaintyType.EVIDENCE_CONFLICT,
                    affected_dimensions=("behavior", "evidence_quality"),
                    evidence_ids=ev_ids,
                    collector_or_check="community_reputation",
                    target_scope=target_scope,
                    explanation=(
                        "Conflicting community intelligence: reports for this target are concurrently marked corroborated and disputed."
                    ),
                )
            )

        return records

    def _build_abstention_notice(
        self,
        decision: str,
        band: ConfidenceBand,
        target_scope: Optional[str],
        failed_checks: List[str],
        not_run_checks: List[str],
        records: List[UncertaintyRecord],
    ) -> AbstentionNotice:
        """Formulate explicit human-readable abstention notice with rescan advice."""
        if band == ConfidenceBand.CONTRADICTORY_EVIDENCE:
            return AbstentionNotice(
                reason_code="ABSTAIN_EVIDENCE_CONFLICT",
                affected_dimensions=("behavior", "evidence_quality"),
                missing_or_failed_checks=tuple(failed_checks),
                target_scope=target_scope,
                is_rescan_recommended=True,
                explanation=(
                    f"Evaluation abstained from affirmative verdict on '{target_scope or 'target'}' due to material evidence conflict. "
                    "Current provider observations disagree for the same target and time window (EVID-004). "
                    "Both evidence trails are retained; a fresh scan may resolve the discrepancy."
                ),
            )

        if any(r.uncertainty_type == UncertaintyType.COLLECTION_FAILURE for r in records) and not any(
            r.uncertainty_type == UncertaintyType.UNCHECKED_COVERAGE for r in records
        ):
            return AbstentionNotice(
                reason_code="ABSTAIN_COLLECTION_FAILURE",
                affected_dimensions=("evidence_quality", "behavior"),
                missing_or_failed_checks=tuple(failed_checks),
                target_scope=target_scope,
                is_rescan_recommended=True,
                explanation=(
                    f"Evaluation abstained from affirmative verdict on '{target_scope or 'target'}' because critical collectors failed or timed out: "
                    f"{', '.join(failed_checks) or 'all collectors'}. Host reachability or threat presence could not be verified (EVID-001). "
                    "A re-scan is recommended once network or provider availability is restored."
                ),
            )

        if any(r.uncertainty_type == UncertaintyType.UNCHECKED_COVERAGE for r in records):
            return AbstentionNotice(
                reason_code="ABSTAIN_UNCHECKED_COVERAGE",
                affected_dimensions=("evidence_quality",),
                missing_or_failed_checks=tuple(not_run_checks),
                target_scope=target_scope,
                is_rescan_recommended=False,
                explanation=(
                    f"Evaluation abstained from definitive disposition on '{target_scope or 'target'}' because required inspection checks were blocked or not run: "
                    f"{', '.join(not_run_checks) or 'policy/budget block'}. Safety or rate-limit policy prevented execution."
                ),
            )

        return AbstentionNotice(
            reason_code="ABSTAIN_INSUFFICIENT_EVIDENCE",
            affected_dimensions=("evidence_quality", "identity", "behavior"),
            missing_or_failed_checks=tuple(failed_checks),
            target_scope=target_scope,
            is_rescan_recommended=True,
            explanation=(
                f"Evaluation inconclusive on '{target_scope or 'target'}': insufficient verifiable evidence available to substantiate a high-risk or benign disposition."
            ),
        )

    def _map_kind_to_dimension(self, kind: str) -> str:
        """Map evidence kind to primary architectural dimension."""
        k = kind.strip().lower()
        if "tls" in k or "certificate" in k:
            return "certificate"
        if "authoriz" in k or "identity" in k or "whois" in k or "domain" in k:
            return "identity"
        if "threat" in k or "reputation" in k or "dns" in k or "http" in k or "redirect" in k or "community" in k:
            return "behavior"
        return "evidence_quality"
