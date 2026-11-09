"""Decision audit log — Worker 03 Phase 01.

Every triage decision is logged with the rule version, signals, rationale,
and a stable entry ID. This supports:
- Regression tracking: if a rule changes, compare old vs new decisions.
- Transparency: every report can cite exactly which rules and version produced it.
- Claim audit: the decision log provides evidence for pitch/demo reviews.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class DecisionLogEntry:
    """Immutable record of a single triage decision.

    Attributes:
        entry_id: Stable unique identifier.
        scan_id: The scan this decision relates to.
        policy_version: Version of the policy rules that produced the decision.
        decision: Final disposition (high_risk, caution, etc.).
        dimensions: Dimension values at time of decision.
        rule_ids_fired: Which rules contributed to the decision.
        rationale_summary: Human-readable rationale chain.
        signal_kinds: Signal kinds that were input to the engine.
        evidence_ids: All evidence IDs considered.
        limitations: Explicit limitations and caveats.
        created_at: UTC ISO-8601 timestamp.
    """

    entry_id: str = field(default_factory=lambda: f"dlog-{uuid.uuid4().hex[:8]}")
    scan_id: str = ""
    policy_version: str = ""
    decision: str = ""
    dimensions: Dict[str, str] = field(default_factory=dict)
    rule_ids_fired: List[str] = field(default_factory=list)
    rationale_summary: str = ""
    signal_kinds: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict for storage or JSON export."""
        return {
            "entry_id": self.entry_id,
            "scan_id": self.scan_id,
            "policy_version": self.policy_version,
            "decision": self.decision,
            "dimensions": dict(self.dimensions),
            "rule_ids_fired": list(self.rule_ids_fired),
            "rationale_summary": self.rationale_summary,
            "signal_kinds": list(self.signal_kinds),
            "evidence_ids": list(self.evidence_ids),
            "limitations": list(self.limitations),
            "created_at": self.created_at,
        }


class DecisionLog:
    """In-memory decision audit trail.

    In production this would be backed by an append-only store.
    For the MVP, it collects entries in a list for test verification
    and demo purposes.
    """

    def __init__(self) -> None:
        self._entries: List[DecisionLogEntry] = []

    def record(
        self,
        scan_id: str,
        triage_result: Any,  # TriageResult from triage_engine
        signal_kinds: Optional[List[str]] = None,
        evidence_ids: Optional[List[str]] = None,
    ) -> DecisionLogEntry:
        """Record a triage decision in the audit log.

        Args:
            scan_id: The scan this decision relates to.
            triage_result: A TriageResult object from TriageEngine.evaluate().
            signal_kinds: Optional list of signal kind strings.
            evidence_ids: Optional list of all evidence IDs considered.

        Returns:
            The created DecisionLogEntry.
        """
        entry = DecisionLogEntry(
            scan_id=scan_id,
            policy_version=triage_result.policy_version,
            decision=triage_result.decision,
            dimensions=dict(triage_result.dimensions),
            rule_ids_fired=[r.rule_id for r in triage_result.rule_trace],
            rationale_summary=triage_result.rationale_summary,
            signal_kinds=signal_kinds or [],
            evidence_ids=evidence_ids or [],
            limitations=list(triage_result.limitations),
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> List[DecisionLogEntry]:
        """Return all logged entries (read-only view)."""
        return list(self._entries)

    def find_by_scan(self, scan_id: str) -> List[DecisionLogEntry]:
        """Find all decision log entries for a given scan."""
        return [e for e in self._entries if e.scan_id == scan_id]

    def find_by_policy_version(self, version: str) -> List[DecisionLogEntry]:
        """Find all entries produced by a specific policy version."""
        return [e for e in self._entries if e.policy_version == version]

    def clear(self) -> None:
        """Clear the log (useful for tests)."""
        self._entries.clear()
