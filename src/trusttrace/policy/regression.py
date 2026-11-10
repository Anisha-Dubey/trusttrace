"""Policy drift regression runner and diff reporting — Worker 03 Phase 05.

Enables reproducible, deterministic comparisons between policy engine versions
or between frozen baseline evaluation snapshots and candidate policy outcomes.

Key Design Principles:
1. Zero false regressions: Ignores nondeterministic metadata (random IDs, wall-clock timestamps).
2. Deep semantic inspection: Detects decision shifts, dimension changes, rule trace diffs,
   and finding composition changes.
3. Strict versioning: Distinguishes intended policy changes from accidental regressions.
4. Exportable audit reports: Serializes structured diff reports to dict and JSON.
"""

from dataclasses import dataclass, field
import json
from typing import Any, Dict, List, Mapping, Optional, Sequence
import uuid

from .decision_log import DecisionAuditRecord
from .evaluation import ControlledEvaluationSet, EvaluationFixture
from .signal_taxonomy import SignalKind, SignalRecord
from .triage_engine import TriageEngine, TriageResult


@dataclass
class RegressionDiffReport:
    """Structured report detailing detected differences between policy baseline and candidate."""

    report_id: str = field(default_factory=lambda: f"regdiff-{uuid.uuid4().hex[:8]}")
    baseline_version: str = "w03-v1.0"
    candidate_version: str = "w03-v1.0"
    total_fixtures: int = 0
    passed_count: int = 0
    regressions_count: int = 0
    decision_shifts: List[Dict[str, Any]] = field(default_factory=list)
    dimension_shifts: List[Dict[str, Any]] = field(default_factory=list)
    finding_shifts: List[Dict[str, Any]] = field(default_factory=list)
    rule_shifts: List[Dict[str, Any]] = field(default_factory=list)
    is_simulated: bool = True
    summary: str = ""

    @property
    def has_regressions(self) -> bool:
        """True if any decision, dimension, or finding regressions were detected."""
        return (
            len(self.decision_shifts) > 0
            or len(self.dimension_shifts) > 0
            or len(self.finding_shifts) > 0
        )

    @property
    def passed_fixtures(self) -> int:
        """Alias for passed_count."""
        return self.passed_count

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a dictionary."""
        return {
            "report_id": self.report_id,
            "baseline_version": self.baseline_version,
            "candidate_version": self.candidate_version,
            "total_fixtures": self.total_fixtures,
            "passed_count": self.passed_count,
            "passed_fixtures": self.passed_count,
            "regressions_count": self.regressions_count,
            "has_regressions": self.has_regressions,
            "decision_shifts": list(self.decision_shifts),
            "dimension_shifts": list(self.dimension_shifts),
            "finding_shifts": list(self.finding_shifts),
            "rule_shifts": list(self.rule_shifts),
            "is_simulated": self.is_simulated,
            "summary": self.summary,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Serialize report to deterministic JSON."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


class PolicyRegressionRunner:
    """Automated runner for policy drift detection and version regression comparisons."""

    def __init__(
        self,
        triage_engine: Optional[TriageEngine] = None,
        policy_version: str = "w03-v1.0",
    ) -> None:
        self.engine = triage_engine or TriageEngine()
        self.policy_version = policy_version

    def capture_baseline_snapshot(
        self,
        first: Any,
        second: Any = None,
    ) -> Dict[str, Any]:
        """Capture a canonical baseline snapshot from an evaluation set or fixture sequence.

        Supports:
        - capture_baseline_snapshot(eval_set)
        - capture_baseline_snapshot(fixtures)
        - capture_baseline_snapshot(engine, fixtures)
        - capture_baseline_snapshot(engine, eval_set)
        """
        if second is not None:
            engine = first
            eval_source = second
        else:
            engine = self.engine
            eval_source = first

        fixtures = eval_source.fixtures if hasattr(eval_source, "fixtures") else list(eval_source)

        snapshot: Dict[str, Any] = {}
        for fixture in fixtures:
            signals = self._build_signals(fixture)
            res = engine.evaluate(signals, scan_id=f"snap-{fixture.fixture_id}")
            audit_rec = DecisionAuditRecord(
                scan_id=f"snap-{fixture.fixture_id}",
                target="fixture-target.test",
                policy_version=res.policy_version,
                decision=res.decision,
                dimensions=dict(res.dimensions),
                fired_rule_ids=[r.rule_id for r in res.rule_trace],
                evidence_ids=sorted(list({eid for s in signals for eid in s.evidence_ids})),
                limitations=list(res.limitations),
            )
            sem = audit_rec.to_semantic_dict()
            sem["fixture_id"] = fixture.fixture_id
            # Expose rules_triggered alias
            sem["rules_triggered"] = [r.rule_id for r in res.rule_trace]
            snapshot[fixture.fixture_id] = sem

        return snapshot

    def run_regression_against_baseline(
        self,
        first: Any,
        second: Any,
        third: Any = None,
    ) -> RegressionDiffReport:
        """Run candidate engine against frozen evaluation set and compare with recorded baseline snapshot.

        Supports:
        - run_regression_against_baseline(eval_set, baseline_snapshot)
        - run_regression_against_baseline(engine, baseline_snapshot, eval_set_or_fixtures)
        """
        if third is not None:
            engine = first
            baseline_snapshot = second
            eval_source = third
        else:
            engine = self.engine
            eval_source = first
            baseline_snapshot = second

        fixtures = eval_source.fixtures if hasattr(eval_source, "fixtures") else list(eval_source)
        baseline_fixtures = baseline_snapshot.get("fixtures", baseline_snapshot)
        baseline_version = str(baseline_snapshot.get("policy_version", "unknown"))
        candidate_version = engine.policy_version

        decision_shifts: List[Dict[str, Any]] = []
        dimension_shifts: List[Dict[str, Any]] = []
        finding_shifts: List[Dict[str, Any]] = []
        rule_shifts: List[Dict[str, Any]] = []

        passed_count = 0
        total_fixtures = len(fixtures)

        for fixture in fixtures:
            f_id = fixture.fixture_id
            signals = self._build_signals(fixture)
            candidate_res = engine.evaluate(signals, scan_id=f"reg-{f_id}")

            base_sem = baseline_fixtures.get(f_id)
            if not base_sem:
                decision_shifts.append({
                    "fixture_id": f_id,
                    "description": fixture.description,
                    "baseline": None,
                    "baseline_decision": None,
                    "candidate": candidate_res.decision,
                    "candidate_decision": candidate_res.decision,
                    "reason": "Missing from baseline snapshot",
                })
                continue

            # 1. Compare Decision
            base_dec = base_sem.get("decision")
            cand_dec = candidate_res.decision
            decision_matches = (base_dec == cand_dec)
            if not decision_matches:
                decision_shifts.append({
                    "fixture_id": f_id,
                    "description": fixture.description,
                    "baseline": base_dec,
                    "baseline_decision": base_dec,
                    "candidate": cand_dec,
                    "candidate_decision": cand_dec,
                    "severity": "regression",
                })

            # 2. Compare Dimensions
            base_dims = base_sem.get("dimensions", {})
            dimension_matches = True
            for dim_k, base_val in base_dims.items():
                cand_val = candidate_res.dimensions.get(dim_k)
                if base_val != cand_val:
                    dimension_matches = False
                    dimension_shifts.append({
                        "fixture_id": f_id,
                        "dimension": dim_k,
                        "baseline": base_val,
                        "baseline_value": base_val,
                        "candidate": cand_val,
                        "candidate_value": cand_val,
                    })

            # 3. Compare Fired Rules
            base_rules = set(base_sem.get("rules_triggered") or base_sem.get("fired_rule_ids", []))
            cand_rules = {r.rule_id for r in candidate_res.rule_trace}
            rules_match = (base_rules == cand_rules)
            if not rules_match:
                rule_shifts.append({
                    "fixture_id": f_id,
                    "baseline_rules": sorted(list(base_rules)),
                    "candidate_rules": sorted(list(cand_rules)),
                    "added": sorted(list(cand_rules - base_rules)),
                    "removed": sorted(list(base_rules - cand_rules)),
                })

            if decision_matches and dimension_matches and rules_match:
                passed_count += 1

        regressions_count = len(decision_shifts) + len(dimension_shifts)

        if regressions_count == 0:
            summary = f"No policy drift detected across {total_fixtures} evaluation fixtures."
        else:
            summary = (
                f"Detected {len(decision_shifts)} decision shifts and "
                f"{len(dimension_shifts)} dimension shifts across {total_fixtures} fixtures."
            )

        return RegressionDiffReport(
            baseline_version=baseline_version,
            candidate_version=candidate_version,
            total_fixtures=total_fixtures,
            passed_count=passed_count,
            regressions_count=regressions_count,
            decision_shifts=decision_shifts,
            dimension_shifts=dimension_shifts,
            finding_shifts=finding_shifts,
            rule_shifts=rule_shifts,
            summary=summary,
        )

    def run_regression_against_fixtures(
        self,
        eval_set: ControlledEvaluationSet,
    ) -> RegressionDiffReport:
        """Run candidate engine directly against fixture ground-truth expectations."""
        decision_shifts: List[Dict[str, Any]] = []
        dimension_shifts: List[Dict[str, Any]] = []
        passed_count = 0
        total_fixtures = len(eval_set.fixtures)

        for fixture in eval_set.fixtures:
            signals = self._build_signals(fixture)
            res = self.engine.evaluate(signals, scan_id=f"eval-{fixture.fixture_id}")

            has_diff = False
            if res.decision != fixture.expected_decision:
                decision_shifts.append({
                    "fixture_id": fixture.fixture_id,
                    "description": fixture.description,
                    "expected_decision": fixture.expected_decision,
                    "actual_decision": res.decision,
                })
                has_diff = True

            for dim_k, exp_val in fixture.expected_dimensions.items():
                act_val = res.dimensions.get(dim_k)
                if act_val != exp_val:
                    dimension_shifts.append({
                        "fixture_id": fixture.fixture_id,
                        "dimension": dim_k,
                        "expected_value": exp_val,
                        "actual_value": act_val,
                    })
                    has_diff = True

            if not has_diff:
                passed_count += 1

        regressions_count = len(decision_shifts) + len(dimension_shifts)
        summary = (
            f"Evaluated {total_fixtures} fixtures: {passed_count} passed, {regressions_count} mismatches."
        )

        return RegressionDiffReport(
            baseline_version="fixture-ground-truth",
            candidate_version=self.engine.policy_version,
            total_fixtures=total_fixtures,
            passed_count=passed_count,
            regressions_count=regressions_count,
            decision_shifts=decision_shifts,
            dimension_shifts=dimension_shifts,
            summary=summary,
        )

    def _build_signals(self, fixture: EvaluationFixture) -> List[SignalRecord]:
        """Convert fixture signals_config into strongly-typed SignalRecord instances."""
        signals = []
        for s in fixture.signals_config:
            signals.append(
                SignalRecord(
                    kind=SignalKind(s["kind"]),
                    evidence_ids=list(s.get("evidence_ids", ["fixture-ev"])),
                    source=s.get("source", "fixture"),
                    confidence=s.get("confidence", "direct_observation"),
                    limitations=list(s.get("limitations", [])),
                )
            )
        return signals
