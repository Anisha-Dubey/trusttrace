"""Conservative deterministic triage engine — Worker 03 Phase 01.

Implements the decision policy table from .brain/.work/shared/decision_policy_table.md
with the following invariants:

- TLS validity alone never yields identity=supported (TLS-001)
- Absent threat-feed match never yields "safe" (EVID-002)
- Expired/mismatched TLS alone is not proof of phishing (TLS-002)
- IDN lookalike alone is at most caution (conservative heuristic)
- Collector failures produce partial/inconclusive, never clean (EVID-001)
- Conflicting signals are retained, never silently averaged (EVID-004)
- Community reports remain unverified unless independently corroborated (COMM-001/002)
- Every decision cites evidence IDs and policy version

Each rule is a named, versioned function that maps signals → dimension values
and disposition ceiling. The engine composes rules deterministically with no
learned weights, random thresholds, or opaque scoring.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .signal_taxonomy import (
    SignalKind,
    SignalRecord,
    SignalDimension,
    DimensionAssessment,
)


# Policy version tracks rule changes; bump on any disposition logic change.
POLICY_VERSION = "w03-v1.0"


@dataclass
class RuleResult:
    """Output of a single named rule evaluation."""

    rule_id: str
    rule_version: str
    disposition_ceiling: Optional[str]  # max severity this rule allows
    dimension_updates: Dict[str, str]  # dimension → value
    findings: List[Dict[str, Any]] = field(default_factory=list)
    rationale: str = ""
    limitations: List[str] = field(default_factory=list)


@dataclass
class TriageResult:
    """Full triage output conforming to scan_report.schema.json structure."""

    decision: str  # high_risk | caution | no_threat_observed | inconclusive | failed
    dimensions: Dict[str, str]
    findings: List[Dict[str, Any]]
    rule_trace: List[RuleResult]
    policy_version: str
    limitations: List[str]
    rationale_summary: str

    def to_report_fragment(self) -> Dict[str, Any]:
        """Return dict suitable for merging into a scan report."""
        return {
            "decision": self.decision,
            "policy_version": self.policy_version,
            "dimensions": dict(self.dimensions),
            "findings": list(self.findings),
            "limitations": list(self.limitations),
        }


class TriageEngine:
    """Transparent, rule-based triage engine.

    Design principles:
    1. Deterministic: same signals → same output, always.
    2. Conservative: disposition ceiling never exceeds evidence warrant.
    3. Transparent: every output references rules, evidence IDs, and rationale.
    4. No hidden scores: no opaque weighted sums or learned parameters.
    """

    def __init__(self, policy_version: str = POLICY_VERSION):
        self.policy_version = policy_version

    def evaluate(self, signals: List[SignalRecord]) -> TriageResult:
        """Run all rules against the signal set and compose a triage result.

        Args:
            signals: Typed, provenance-linked signals from collectors/evidence.

        Returns:
            TriageResult with decision, dimensions, findings, and full rule trace.
        """
        # Classify signals by dimension.
        by_dimension: Dict[SignalDimension, List[SignalRecord]] = {
            dim: [] for dim in SignalDimension
        }
        for sig in signals:
            by_dimension[sig.dimension].append(sig)

        # Initialize dimensions to conservative defaults.
        dimensions: Dict[str, str] = {
            "identity": "unknown",
            "certificate": "not_checked",
            "behavior": "unknown",
            "evidence_quality": "unavailable",
        }

        rule_results: List[RuleResult] = []
        all_findings: List[Dict[str, Any]] = []
        all_limitations: List[str] = []
        disposition_ceilings: List[str] = []

        # Run each rule in sequence; later rules can tighten but not weaken.
        rules = [
            self._rule_certificate,
            self._rule_identity,
            self._rule_behavior,
            self._rule_evidence_quality,
            self._rule_community_reports,
            self._rule_conflict_detection,
        ]

        for rule_fn in rules:
            result = rule_fn(signals, by_dimension, dimensions)
            rule_results.append(result)

            # Apply dimension updates.
            for dim_key, dim_val in result.dimension_updates.items():
                dimensions[dim_key] = dim_val

            all_findings.extend(result.findings)
            all_limitations.extend(result.limitations)

            if result.disposition_ceiling:
                disposition_ceilings.append(result.disposition_ceiling)

        # Compose final decision from disposition ceilings.
        decision = self._compose_decision(disposition_ceilings, dimensions, signals)

        # Build rationale summary.
        rationale_parts = [r.rationale for r in rule_results if r.rationale]
        rationale_summary = " | ".join(rationale_parts) if rationale_parts else "No rules fired."

        return TriageResult(
            decision=decision,
            dimensions=dimensions,
            findings=all_findings,
            rule_trace=rule_results,
            policy_version=self.policy_version,
            limitations=all_limitations,
            rationale_summary=rationale_summary,
        )

    # ─── Individual Named Rules ───────────────────────────────────────

    def _rule_certificate(
        self,
        signals: List[SignalRecord],
        by_dim: Dict[SignalDimension, List[SignalRecord]],
        current_dims: Dict[str, str],
    ) -> RuleResult:
        """RULE-CERT-001: Map TLS signals to certificate dimension.

        - Valid TLS → valid_for_hostname (but NOT identity=supported; TLS-001)
        - Expired/mismatch → invalid_or_expired (not proof of phishing; TLS-002)
        - Unavailable → unavailable
        - No TLS signals → not_checked
        """
        cert_signals = by_dim.get(SignalDimension.CERTIFICATE, [])
        updates: Dict[str, str] = {}
        rationale_parts: List[str] = []
        limitations: List[str] = []
        findings: List[Dict[str, Any]] = []

        if not cert_signals:
            updates["certificate"] = "not_checked"
            rationale_parts.append("No certificate signals received; marking not_checked.")
        else:
            has_valid = any(s.kind == SignalKind.TLS_VALID for s in cert_signals)
            has_expired = any(s.kind == SignalKind.TLS_EXPIRED for s in cert_signals)
            has_mismatch = any(s.kind == SignalKind.TLS_MISMATCH for s in cert_signals)
            has_unavail = any(s.kind == SignalKind.TLS_UNAVAILABLE for s in cert_signals)

            if has_valid and not has_expired and not has_mismatch:
                updates["certificate"] = "valid_for_hostname"
                rationale_parts.append("TLS certificate valid for hostname.")
            elif has_expired or has_mismatch:
                updates["certificate"] = "invalid_or_expired"
                rationale_parts.append(
                    "TLS certificate expired or hostname-mismatched; this is a technical "
                    "warning, not sole proof of phishing (TLS-002)."
                )
                limitations.append(
                    "Certificate invalidity alone is insufficient evidence of malicious intent."
                )
                # Generate a finding for the TLS issue.
                ev_ids = []
                for s in cert_signals:
                    if s.kind in (SignalKind.TLS_EXPIRED, SignalKind.TLS_MISMATCH):
                        ev_ids.extend(s.evidence_ids)
                findings.append({
                    "finding_id": f"finding-cert-{uuid.uuid4().hex[:6]}",
                    "kind": "certificate_issue",
                    "severity": "medium",
                    "summary": "TLS certificate is expired or mismatched for the hostname.",
                    "evidence_ids": ev_ids,
                    "rule_id": "RULE-CERT-001",
                    "rule_version": self.policy_version,
                    "created_at": _now_iso(),
                    "limitations": [
                        "Technical certificate failure is not sole proof of phishing (TLS-002)."
                    ],
                })
            elif has_unavail:
                updates["certificate"] = "unavailable"
                rationale_parts.append("TLS certificate check failed or unavailable.")
            else:
                updates["certificate"] = "not_checked"

        return RuleResult(
            rule_id="RULE-CERT-001",
            rule_version=self.policy_version,
            disposition_ceiling=None,
            dimension_updates=updates,
            findings=findings,
            rationale=" ".join(rationale_parts),
            limitations=limitations,
        )

    def _rule_identity(
        self,
        signals: List[SignalRecord],
        by_dim: Dict[SignalDimension, List[SignalRecord]],
        current_dims: Dict[str, str],
    ) -> RuleResult:
        """RULE-ID-001: Map identity signals. TLS alone → unverified (TLS-001)."""
        id_signals = by_dim.get(SignalDimension.IDENTITY, [])
        updates: Dict[str, str] = {}
        rationale_parts: List[str] = []
        limitations: List[str] = []

        has_tls_match = any(s.kind == SignalKind.TLS_HOSTNAME_MATCH for s in id_signals)
        has_authorization = any(
            s.kind == SignalKind.AUTHORIZATION_EVIDENCE for s in id_signals
        )
        has_idn = any(s.kind == SignalKind.IDN_LOOKALIKE for s in id_signals)

        if has_authorization:
            updates["identity"] = "supported"
            rationale_parts.append(
                "Identity supported by authorization evidence beyond TLS."
            )
        elif has_idn:
            updates["identity"] = "unverified"
            rationale_parts.append(
                "IDN/lookalike heuristic detected; identity remains unverified. "
                "This is a candidate-generation signal that can produce false positives."
            )
            limitations.append(
                "IDN lookalike alone is not proof of impersonation."
            )
        elif has_tls_match:
            # Invariant TLS-001: valid TLS alone → unverified, NOT supported.
            updates["identity"] = "unverified"
            rationale_parts.append(
                "TLS hostname match confirms certificate covers domain, "
                "but this is NOT identity authorization (TLS-001)."
            )
            limitations.append(
                "TLS validity does not verify organizational identity."
            )
        else:
            updates["identity"] = "unknown"
            rationale_parts.append("No identity signals available.")

        return RuleResult(
            rule_id="RULE-ID-001",
            rule_version=self.policy_version,
            disposition_ceiling=None,
            dimension_updates=updates,
            rationale=" ".join(rationale_parts),
            limitations=limitations,
        )

    def _rule_behavior(
        self,
        signals: List[SignalRecord],
        by_dim: Dict[SignalDimension, List[SignalRecord]],
        current_dims: Dict[str, str],
    ) -> RuleResult:
        """RULE-BEH-001: Map behavior signals with conservative disposition ceilings.

        - Threat feed match with valid provider → high_risk ceiling (if provider supports it)
        - Suspicious redirect/headers → caution ceiling
        - No threat match → no_threat_observed only with declared coverage
        - Unverified community report → caution ceiling at most
        """
        beh_signals = by_dim.get(SignalDimension.BEHAVIOR, [])
        updates: Dict[str, str] = {}
        findings: List[Dict[str, Any]] = []
        rationale_parts: List[str] = []
        limitations: List[str] = []
        ceiling: Optional[str] = None

        has_threat = any(s.kind == SignalKind.THREAT_FEED_MATCH for s in beh_signals)
        has_suspicious = any(
            s.kind in (SignalKind.SUSPICIOUS_REDIRECT, SignalKind.SUSPICIOUS_HEADERS)
            for s in beh_signals
        )
        has_no_threat = any(s.kind == SignalKind.NO_THREAT_MATCH for s in beh_signals)
        has_community_unverified = any(
            s.kind == SignalKind.COMMUNITY_REPORT_UNVERIFIED for s in beh_signals
        )
        has_community_corroborated = any(
            s.kind == SignalKind.COMMUNITY_REPORT_CORROBORATED for s in beh_signals
        )

        if has_threat:
            updates["behavior"] = "malicious_evidence"
            ceiling = "high_risk"
            rationale_parts.append(
                "Threat feed match found; ceiling set to high_risk subject to "
                "provider terms and freshness."
            )
            # Generate threat finding.
            for s in beh_signals:
                if s.kind == SignalKind.THREAT_FEED_MATCH:
                    findings.append({
                        "finding_id": f"finding-threat-{uuid.uuid4().hex[:6]}",
                        "kind": "threat_feed_match",
                        "severity": "high",
                        "summary": "URL/domain matches an active threat intelligence feed entry.",
                        "evidence_ids": s.evidence_ids,
                        "rule_id": "RULE-BEH-001",
                        "rule_version": self.policy_version,
                        "created_at": _now_iso(),
                        "limitations": s.limitations,
                    })
        elif has_suspicious:
            updates["behavior"] = "suspicious"
            ceiling = "caution"
            rationale_parts.append(
                "Suspicious behavior signals detected; ceiling set to caution."
            )
            for s in beh_signals:
                if s.kind in (SignalKind.SUSPICIOUS_REDIRECT, SignalKind.SUSPICIOUS_HEADERS):
                    findings.append({
                        "finding_id": f"finding-susp-{uuid.uuid4().hex[:6]}",
                        "kind": s.kind.value,
                        "severity": "medium",
                        "summary": f"Suspicious signal: {s.kind.value}.",
                        "evidence_ids": s.evidence_ids,
                        "rule_id": "RULE-BEH-001",
                        "rule_version": self.policy_version,
                        "created_at": _now_iso(),
                        "limitations": s.limitations,
                    })
        elif has_community_corroborated:
            updates["behavior"] = "suspicious"
            ceiling = "caution"
            rationale_parts.append(
                "Corroborated community report elevates behavior to suspicious; "
                "ceiling remains caution per policy."
            )
        elif has_community_unverified:
            updates["behavior"] = "unknown"
            ceiling = "caution"
            rationale_parts.append(
                "Unverified community report present; behavior remains unknown "
                "but ceiling is capped at caution."
            )
            limitations.append(
                "Community report is unverified; no automatic label applied."
            )
        elif has_no_threat:
            updates["behavior"] = "no_threat_observed"
            rationale_parts.append(
                "No threat feed match; behavior set to no_threat_observed "
                "within the scope of checked sources."
            )
            limitations.append(
                "Absence of threat-feed match does not imply safe; scope is limited "
                "to checked sources (EVID-002)."
            )
        else:
            updates["behavior"] = "unknown"
            rationale_parts.append("No behavior signals available.")

        return RuleResult(
            rule_id="RULE-BEH-001",
            rule_version=self.policy_version,
            disposition_ceiling=ceiling,
            dimension_updates=updates,
            findings=findings,
            rationale=" ".join(rationale_parts),
            limitations=limitations,
        )

    def _rule_evidence_quality(
        self,
        signals: List[SignalRecord],
        by_dim: Dict[SignalDimension, List[SignalRecord]],
        current_dims: Dict[str, str],
    ) -> RuleResult:
        """RULE-EVQUAL-001: Assess evidence quality from collector outcomes.

        - All collectors succeeded → strong
        - Some failed → partial; decision capped at inconclusive unless strong
          independent evidence exists
        - All failed → unavailable; decision is inconclusive
        - Stale evidence → weak; flag staleness
        """
        eq_signals = by_dim.get(SignalDimension.EVIDENCE_QUALITY, [])
        updates: Dict[str, str] = {}
        rationale_parts: List[str] = []
        limitations: List[str] = []
        ceiling: Optional[str] = None

        has_success = any(s.kind == SignalKind.COLLECTOR_SUCCESS for s in eq_signals)
        has_failure = any(s.kind == SignalKind.COLLECTOR_FAILURE for s in eq_signals)
        has_stale = any(s.kind == SignalKind.STALE_EVIDENCE for s in eq_signals)
        has_conflict = any(s.kind == SignalKind.CONFLICTING_SIGNALS for s in eq_signals)

        if has_conflict:
            updates["evidence_quality"] = "partial"
            ceiling = "inconclusive"
            rationale_parts.append(
                "Conflicting high-quality signals detected; evidence quality is partial "
                "and decision is capped at inconclusive. Both supporting and opposing "
                "evidence are retained (EVID-004)."
            )
            limitations.append(
                "Material conflict among signals; cautious/inconclusive policy applied."
            )
        elif has_stale and not has_success:
            updates["evidence_quality"] = "weak"
            ceiling = "inconclusive"
            rationale_parts.append(
                "Only stale evidence available; quality is weak."
            )
            limitations.append(
                "Evidence is stale; observation time and freshness displayed."
            )
        elif has_failure and not has_success:
            updates["evidence_quality"] = "unavailable"
            ceiling = "inconclusive"
            rationale_parts.append(
                "All collectors failed; evidence quality is unavailable (EVID-001)."
            )
            limitations.append(
                "No successful observations; unable to make confident assessment."
            )
        elif has_failure and has_success:
            updates["evidence_quality"] = "partial"
            rationale_parts.append(
                "Some collectors succeeded, some failed; evidence is partial (EVID-001)."
            )
            limitations.append(
                "Partial evidence; some checks failed or were not completed."
            )
        elif has_stale and has_success:
            updates["evidence_quality"] = "partial"
            rationale_parts.append(
                "Mix of fresh and stale evidence; quality is partial."
            )
            limitations.append(
                "Some evidence may be stale."
            )
        elif has_success:
            updates["evidence_quality"] = "strong"
            rationale_parts.append("All collectors succeeded; evidence quality is strong.")
        else:
            updates["evidence_quality"] = "unavailable"
            rationale_parts.append("No evidence quality signals available.")

        return RuleResult(
            rule_id="RULE-EVQUAL-001",
            rule_version=self.policy_version,
            disposition_ceiling=ceiling,
            dimension_updates=updates,
            rationale=" ".join(rationale_parts),
            limitations=limitations,
        )

    def _rule_community_reports(
        self,
        signals: List[SignalRecord],
        by_dim: Dict[SignalDimension, List[SignalRecord]],
        current_dims: Dict[str, str],
    ) -> RuleResult:
        """RULE-COMM-001: Community report constraints.

        - Unverified reports stay unverified; no automatic labels (COMM-001)
        - Corroborated: only from independent source families (COMM-002)
        - Disputed: conflict retained, both trails shown (COMM-003)
        """
        comm_signals = [
            s for s in signals if s.kind in (
                SignalKind.COMMUNITY_REPORT_UNVERIFIED,
                SignalKind.COMMUNITY_REPORT_CORROBORATED,
                SignalKind.COMMUNITY_REPORT_DISPUTED,
            )
        ]
        findings: List[Dict[str, Any]] = []
        rationale_parts: List[str] = []
        limitations: List[str] = []

        for s in comm_signals:
            if s.kind == SignalKind.COMMUNITY_REPORT_UNVERIFIED:
                findings.append({
                    "finding_id": f"finding-comm-{uuid.uuid4().hex[:6]}",
                    "kind": "community_report",
                    "severity": "info",
                    "summary": "Unverified community report exists for this domain.",
                    "evidence_ids": s.evidence_ids,
                    "rule_id": "RULE-COMM-001",
                    "rule_version": self.policy_version,
                    "created_at": _now_iso(),
                    "limitations": [
                        "Report is unverified; no automatic label or training applied."
                    ],
                })
                rationale_parts.append("Unverified community report noted; no label applied.")
            elif s.kind == SignalKind.COMMUNITY_REPORT_CORROBORATED:
                findings.append({
                    "finding_id": f"finding-comm-{uuid.uuid4().hex[:6]}",
                    "kind": "community_report_corroborated",
                    "severity": "medium",
                    "summary": "Community report corroborated by independent source families.",
                    "evidence_ids": s.evidence_ids,
                    "rule_id": "RULE-COMM-001",
                    "rule_version": self.policy_version,
                    "created_at": _now_iso(),
                    "limitations": s.limitations,
                })
                rationale_parts.append("Corroborated community report strengthens caution.")
            elif s.kind == SignalKind.COMMUNITY_REPORT_DISPUTED:
                findings.append({
                    "finding_id": f"finding-comm-{uuid.uuid4().hex[:6]}",
                    "kind": "community_report_disputed",
                    "severity": "info",
                    "summary": "Community report is disputed; both evidence trails retained.",
                    "evidence_ids": s.evidence_ids,
                    "rule_id": "RULE-COMM-001",
                    "rule_version": self.policy_version,
                    "created_at": _now_iso(),
                    "limitations": [
                        "Disputed community reports retained without resolution; "
                        "cautious policy applied."
                    ],
                })
                rationale_parts.append("Disputed community report; conflict retained.")
                limitations.append("Disputed community report; both trails shown.")

        return RuleResult(
            rule_id="RULE-COMM-001",
            rule_version=self.policy_version,
            disposition_ceiling=None,
            dimension_updates={},
            findings=findings,
            rationale=" ".join(rationale_parts) if rationale_parts else "",
            limitations=limitations,
        )

    def _rule_conflict_detection(
        self,
        signals: List[SignalRecord],
        by_dim: Dict[SignalDimension, List[SignalRecord]],
        current_dims: Dict[str, str],
    ) -> RuleResult:
        """RULE-CONFLICT-001: Detect material conflicts and enforce cautious policy.

        If both threat-match and no-threat-match are present, or both valid and
        invalid TLS are present, mark as conflicting and cap at inconclusive.
        """
        limitations: List[str] = []
        ceiling: Optional[str] = None
        rationale_parts: List[str] = []
        updates: Dict[str, str] = {}

        kinds = {s.kind for s in signals}

        # Behavioral conflict: threat match + no threat match
        if SignalKind.THREAT_FEED_MATCH in kinds and SignalKind.NO_THREAT_MATCH in kinds:
            ceiling = "inconclusive"
            updates["evidence_quality"] = "partial"
            limitations.append(
                "Conflicting behavior signals: both threat match and no-threat match "
                "present. Cautious/inconclusive policy applied (EVID-004)."
            )
            rationale_parts.append("Material behavioral conflict detected.")

        # Certificate conflict: valid + expired/mismatch
        if SignalKind.TLS_VALID in kinds and (
            SignalKind.TLS_EXPIRED in kinds or SignalKind.TLS_MISMATCH in kinds
        ):
            ceiling = "inconclusive"
            updates["evidence_quality"] = "partial"
            limitations.append(
                "Conflicting certificate signals: both valid and invalid TLS evidence."
            )
            rationale_parts.append("Material certificate conflict detected.")

        # Community conflict: corroborated + disputed
        if (
            SignalKind.COMMUNITY_REPORT_CORROBORATED in kinds
            and SignalKind.COMMUNITY_REPORT_DISPUTED in kinds
        ):
            ceiling = "inconclusive"
            limitations.append(
                "Conflicting community reports: both corroborated and disputed."
            )
            rationale_parts.append("Community report conflict detected.")

        return RuleResult(
            rule_id="RULE-CONFLICT-001",
            rule_version=self.policy_version,
            disposition_ceiling=ceiling,
            dimension_updates=updates,
            rationale=" ".join(rationale_parts) if rationale_parts else "",
            limitations=limitations,
        )

    # ─── Decision Composition ─────────────────────────────────────────

    def _compose_decision(
        self,
        ceilings: List[str],
        dimensions: Dict[str, str],
        signals: List[SignalRecord],
    ) -> str:
        """Compose final decision from disposition ceilings.

        Priority order (most restrictive wins):
        1. inconclusive (if any rule mandates it)
        2. caution
        3. high_risk (only if evidence strongly warrants and no conflict)
        4. no_threat_observed (only if all checks ran and no suspicious signals)
        5. failed (if no evidence at all)

        Invariant EVID-002: absent threat-feed match alone never yields "safe".
        """
        SEVERITY_ORDER = {
            "failed": 0,
            "inconclusive": 1,
            "caution": 2,
            "high_risk": 3,
            "no_threat_observed": 4,
        }

        if not ceilings:
            # No rule set a ceiling; infer from dimensions.
            ev_quality = dimensions.get("evidence_quality", "unavailable")
            behavior = dimensions.get("behavior", "unknown")

            if ev_quality == "unavailable":
                return "inconclusive"
            if behavior == "unknown":
                return "inconclusive"
            if behavior == "no_threat_observed" and ev_quality == "strong":
                return "no_threat_observed"
            if behavior == "malicious_evidence":
                return "high_risk"
            if behavior == "suspicious":
                return "caution"
            return "inconclusive"

        # Find the most restrictive ceiling (lowest severity order).
        min_ceiling = min(ceilings, key=lambda c: SEVERITY_ORDER.get(c, 999))
        return min_ceiling


def _now_iso() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

