"""Decision audit log — Worker 03 Phase 01.

Every triage decision is logged with the rule version, signals, rationale,
and a stable entry ID. This supports:
- Regression tracking: if a rule changes, compare old vs new decisions.
- Transparency: every report can cite exactly which rules and version produced it.
- Claim audit: the decision log provides evidence for pitch/demo reviews.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union
import uuid


@dataclass
class DecisionAuditRecord:
    """Serializable, immutable audit record of a policy decision for regression tracking.

    Strictly separates semantic decision outputs from event metadata (IDs, timestamps)
    to enable zero-false-positive deterministic regression testing.
    """

    audit_id: str = field(default_factory=lambda: f"audit-{uuid.uuid4().hex[:12]}")
    scan_id: str = ""
    target: str = ""
    policy_version: str = ""
    canonical_input_fingerprint: str = ""
    decision: str = ""
    dimensions: Dict[str, str] = field(default_factory=dict)
    fired_rule_ids: List[str] = field(default_factory=list)
    uncertainty_codes: List[str] = field(default_factory=list)
    confidence_band: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    # Convenience / compatibility parameters
    findings: Optional[List[Any]] = None
    uncertainty: Optional[Any] = None
    rules_triggered: Optional[List[str]] = None

    def __post_init__(self) -> None:
        if self.rules_triggered is not None and not self.fired_rule_ids:
            self.fired_rule_ids = list(self.rules_triggered)
        if self.findings is not None and not self.finding_ids:
            self.finding_ids = [
                f.get("finding_id", f.get("code", str(f))) if isinstance(f, dict) else str(f)
                for f in self.findings
            ]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete audit record to plain dictionary."""
        return {
            "audit_id": self.audit_id,
            "scan_id": self.scan_id,
            "target": self.target,
            "policy_version": self.policy_version,
            "canonical_input_fingerprint": self.canonical_input_fingerprint,
            "decision": self.decision,
            "dimensions": dict(self.dimensions),
            "fired_rule_ids": list(self.fired_rule_ids),
            "uncertainty_codes": list(self.uncertainty_codes),
            "confidence_band": self.confidence_band,
            "evidence_ids": list(self.evidence_ids),
            "finding_ids": list(self.finding_ids),
            "limitations": list(self.limitations),
            "diagnostics": list(self.diagnostics),
            "timestamp": self.timestamp,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Deterministic JSON string serialization with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_semantic_dict(self) -> Dict[str, Any]:
        """Extract canonical semantic fields only, excluding event IDs and timestamps.

        Used for regression comparisons to ensure nondeterministic metadata does not
        trigger false-positive regression diffs.
        """
        return {
            "policy_version": self.policy_version,
            "target": self.target,
            "decision": self.decision,
            "dimensions": dict(self.dimensions),
            "fired_rule_ids": sorted(self.fired_rule_ids),
            "rules_triggered": sorted(self.fired_rule_ids),
            "uncertainty_codes": sorted(self.uncertainty_codes),
            "confidence_band": self.confidence_band,
            "evidence_ids": sorted(self.evidence_ids),
            "finding_ids": sorted(self.finding_ids),
            "findings": list(self.findings) if self.findings is not None else [],
            "uncertainty": self.uncertainty if self.uncertainty is not None else {},
            "limitations": sorted(self.limitations),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DecisionAuditRecord":
        """Deserialize from plain dictionary."""
        return cls(
            audit_id=str(data.get("audit_id", "")),
            scan_id=str(data.get("scan_id", "")),
            target=str(data.get("target", "")),
            policy_version=str(data.get("policy_version", "")),
            canonical_input_fingerprint=str(data.get("canonical_input_fingerprint", "")),
            decision=str(data.get("decision", "")),
            dimensions=dict(data.get("dimensions", {})),
            fired_rule_ids=list(data.get("fired_rule_ids", [])),
            uncertainty_codes=list(data.get("uncertainty_codes", [])),
            confidence_band=str(data.get("confidence_band", "")),
            evidence_ids=list(data.get("evidence_ids", [])),
            finding_ids=list(data.get("finding_ids", [])),
            limitations=list(data.get("limitations", [])),
            diagnostics=list(data.get("diagnostics", [])),
            timestamp=str(data.get("timestamp", "")),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "DecisionAuditRecord":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))


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
        self._audit_records: List[DecisionAuditRecord] = []

    def record_audit(
        self,
        scan_id_or_record: Union[str, DecisionAuditRecord],
        triage_result: Any = None,
        target: str = "",
        signals: Optional[Sequence[Any]] = None,
        policy_input: Optional[Any] = None,
    ) -> DecisionAuditRecord:
        """Create and store a serializable DecisionAuditRecord."""
        if isinstance(scan_id_or_record, DecisionAuditRecord):
            self._audit_records.append(scan_id_or_record)
            return scan_id_or_record

        scan_id = str(scan_id_or_record)
        canonical_fp = ""
        evidence_ids: List[str] = []
        if signals:
            sig_reps = []
            for s in signals:
                eids = sorted(getattr(s, "evidence_ids", []))
                sig_reps.append(f"{getattr(s, 'kind', '')}:{eids}")
                evidence_ids.extend(eids)
            canonical_fp = hashlib.sha256(";".join(sorted(sig_reps)).encode("utf-8")).hexdigest()
        elif policy_input and hasattr(policy_input, "evidence"):
            ev_reps = [f"{e.kind}:{e.evidence_id}:{e.status}" for e in policy_input.evidence]
            evidence_ids.extend([e.evidence_id for e in policy_input.evidence])
            canonical_fp = hashlib.sha256(";".join(sorted(ev_reps)).encode("utf-8")).hexdigest()

        uncertainty_codes: List[str] = []
        confidence_band: str = ""
        if hasattr(triage_result, "uncertainty") and triage_result.uncertainty:
            unc = triage_result.uncertainty
            confidence_band = getattr(getattr(unc, "confidence_band", None), "value", str(getattr(unc, "confidence_band", "")))
            if hasattr(unc, "uncertainties"):
                uncertainty_codes = [
                    getattr(getattr(u, "uncertainty_type", None), "value", str(getattr(u, "uncertainty_type", "")))
                    for u in unc.uncertainties
                ]

        finding_ids: List[str] = []
        if hasattr(triage_result, "findings") and triage_result.findings:
            finding_ids = [f.get("finding_id", "") for f in triage_result.findings if isinstance(f, dict)]

        diag_dicts: List[Dict[str, Any]] = []
        if hasattr(triage_result, "diagnostics") and triage_result.diagnostics:
            diag_dicts = [d.to_dict() if hasattr(d, "to_dict") else dict(d) for d in triage_result.diagnostics]

        record = DecisionAuditRecord(
            scan_id=scan_id,
            target=target or getattr(policy_input, "target", ""),
            policy_version=getattr(triage_result, "policy_version", ""),
            canonical_input_fingerprint=canonical_fp,
            decision=getattr(triage_result, "decision", ""),
            dimensions=dict(getattr(triage_result, "dimensions", {})),
            fired_rule_ids=[r.rule_id for r in getattr(triage_result, "rule_trace", [])],
            uncertainty_codes=uncertainty_codes,
            confidence_band=confidence_band,
            evidence_ids=sorted(list(set(evidence_ids))),
            finding_ids=finding_ids,
            limitations=list(getattr(triage_result, "limitations", [])),
            diagnostics=diag_dicts,
        )
        self._audit_records.append(record)
        return record

    @property
    def audit_records(self) -> List[DecisionAuditRecord]:
        """Return all logged serializable audit records."""
        return list(self._audit_records)

    def find_audit_by_scan(self, scan_id: str) -> Optional[DecisionAuditRecord]:
        """Find the first audit record for a given scan, or None."""
        for r in self._audit_records:
            if r.scan_id == scan_id:
                return r
        return None

    def find_all_audits_by_scan(self, scan_id: str) -> List[DecisionAuditRecord]:
        """Find all audit records for a given scan."""
        return [r for r in self._audit_records if r.scan_id == scan_id]

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
        self._audit_records.clear()

