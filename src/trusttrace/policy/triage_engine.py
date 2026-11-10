"""Conservative deterministic triage engine — Worker 03 Phase 03.

Implements the decision policy table with the following invariants:
- TLS validity alone never yields identity=supported (TLS-001)
- Absent threat-feed match never yields 'safe' (EVID-002)
- Expired/mismatched TLS alone is not proof of phishing (TLS-002)
- IDN lookalike alone is at most caution (conservative heuristic)
- Collector failures produce partial/inconclusive, never clean (EVID-001)
- Conflicting signals are retained, never silently averaged (EVID-004)
- Community reports remain unverified unless independently corroborated (COMM-001/002)
- Every decision cites evidence IDs and policy version
- Deterministic finding IDs via canonical JSON serialization and full SHA-256
- Zero orphan findings: finding-to-evidence referential integrity enforced
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Union
import uuid

from .diagnostics import (
    DiagnosticCode,
    DiagnosticCollector,
    DiagnosticRecord,
    DiagnosticSeverity,
)
from .fusion import (
    GateResult,
    ModalityAvailabilityGate,
    ModalityAvailabilityMask,
    ModalityClassifier,
    ModalityKind,
    ModalityProfile,
    ModalityStatus,
    parse_and_validate_target,
)
from .input_validation import EvidenceValidator, ValidationResult
from .integrity_auditor import (
    AuditIssue,
    AuditRuleId,
    AuditSeverity,
    ReportAuditResult,
    ReportIntegrityAuditor,
)
from .policy_input import PolicyInput
from .signal_extractor import EvidenceSignalExtractor, SignalExtractionResult
from .signal_taxonomy import (
    DimensionAssessment,
    SignalConfidence,
    SignalDimension,
    SignalKind,
    SignalRecord,
)
from .uncertainty import (
    AbstentionNotice,
    ConfidenceBand,
    FreshnessPolicy,
    UncertaintyAssessment,
    UncertaintyEngine,
    UncertaintyRecord,
    UncertaintyType,
)

# Policy version tracks rule changes; bump on any disposition logic change.
POLICY_VERSION = "w03-v1.0"


def generate_deterministic_finding_id(
    scan_id: str,
    rule_id: str,
    evidence_ids: Sequence[str],
) -> str:
    """Generate a stable finding ID via canonical JSON serialization and full SHA-256.

    Invariants:
    1. Permutation invariant: evidence_ids are strictly sorted before hashing.
    2. Cross-scan separated: scan_id is explicitly bound in the canonical payload.
    3. Canonical JSON: keys sorted with compact delimiters (no whitespace variance).
    4. Full digest: 64-hex character SHA-256 hash.
    """
    canonical_payload = {
        "evidence_ids": sorted(str(eid) for eid in evidence_ids),
        "rule_id": str(rule_id),
        "scan_id": str(scan_id),
    }
    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"finding-{digest}"


@dataclass
class RuleResult:
    """Output of a single named rule evaluation."""

    rule_id: str
    rule_version: str
    disposition_ceiling: Optional[str]  # max severity this rule allows
    dimension_updates: Dict[str, str]  # dimension -> value
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
    diagnostics: Tuple[DiagnosticRecord, ...] = field(default_factory=tuple)
    uncertainty: Optional[UncertaintyAssessment] = None
    availability_mask: Optional[ModalityAvailabilityMask] = None

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
    """Transparent, rule-based triage engine."""

    def __init__(
        self,
        policy_version: str = POLICY_VERSION,
        freshness_policy: Optional[FreshnessPolicy] = None,
    ):
        self.policy_version = policy_version
        self.validator = EvidenceValidator()
        self.extractor = EvidenceSignalExtractor()
        self.uncertainty_engine = UncertaintyEngine(freshness_policy=freshness_policy)
        self.integrity_auditor = ReportIntegrityAuditor()

    def audit_report(self, report: Dict[str, Any]) -> ReportAuditResult:
        """Audit a complete report dictionary against TRUSTTRACE safety invariants."""
        return self.integrity_auditor.audit_report(report)

    def audit_triage_result(
        self,
        result: TriageResult,
        policy_input: Optional[PolicyInput] = None,
    ) -> ReportAuditResult:
        """Audit a TriageResult and associated evidence before report publication."""
        candidate_report: Dict[str, Any] = {
            "schema_version": "1.0",
            "scan_id": policy_input.scan_id if policy_input else "scan-audited",
            "decision": result.decision,
            "policy_version": result.policy_version,
            "dimensions": dict(result.dimensions),
            "findings": list(result.findings),
            "limitations": list(result.limitations),
        }
        if policy_input:
            if policy_input.coverage:
                candidate_report["coverage"] = {
                    "checks_total": policy_input.coverage.checks_total,
                    "checks_observed": policy_input.coverage.checks_observed,
                    "checks_failed": policy_input.coverage.checks_failed,
                    "checks_not_run": policy_input.coverage.checks_not_run,
                }
            candidate_report["evidence"] = [
                {
                    "evidence_id": item.evidence_id,
                    "kind": item.kind,
                    "source": item.source,
                    "status": item.status,
                }
                for item in policy_input.evidence
            ]
            candidate_report["community_reports"] = [
                {
                    "report_id": r.report_id,
                    "verification_state": r.verification_state,
                }
                for r in policy_input.community_reports
            ]

        return self.integrity_auditor.audit_report(candidate_report)

    def evaluate_evidence(self, policy_input: Union[PolicyInput, Mapping[str, Any], Any]) -> TriageResult:
        """Evaluate raw PolicyInput or canonical dict through validation, signal extraction, and triage.

        Pipeline:
        1. Parse issue rejection gate.
        2. Contract validation & diagnostics collection.
        3. Deterministic signal extraction.
        4. Triage rule execution.
        5. Finding-to-evidence referential integrity enforcement (orphan suppression).
        6. Deterministic finding ID generation.
        7. Positive threat evidence preservation against unrelated collector failures.
        8. Coverage deficit limitations merger.
        9. Uncertainty quantification & abstention notice generation.
        """
        if not isinstance(policy_input, PolicyInput):
            if hasattr(policy_input, "to_v1_contract_dict") and callable(getattr(policy_input, "to_v1_contract_dict")):
                policy_input = PolicyInput.from_v1_dict(policy_input.to_v1_contract_dict(), strict=False)
            elif hasattr(policy_input, "model_dump") and callable(getattr(policy_input, "model_dump")):
                policy_input = PolicyInput.from_v1_dict(policy_input.model_dump(), strict=False)
            elif isinstance(policy_input, Mapping):
                policy_input = PolicyInput.from_v1_dict(policy_input, strict=False)
            else:
                raise TypeError(f"Expected PolicyInput or mapping, got {type(policy_input)}")

        diagnostics_collector = DiagnosticCollector()

        # Step 1: Parse issue rejection gate
        if not policy_input.is_valid:
            diagnostics_collector.record(
                code=DiagnosticCode.INPUT_PARSE_ERROR,
                severity=DiagnosticSeverity.ERROR,
                message=f"PolicyInput contains {len(policy_input.parse_issues)} unresolved parse issues",
                action_taken="Quarantined input; emitted inconclusive triage result",
            )
            uncertainty_assessment = self.uncertainty_engine.assess_evidence(
                policy_input=policy_input,
                signals=(),
                decision="inconclusive",
                dimensions={
                    "identity": "unknown",
                    "certificate": "not_checked",
                    "behavior": "unknown",
                    "evidence_quality": "unavailable",
                },
            )
            return TriageResult(
                decision="inconclusive",
                dimensions={
                    "identity": "unknown",
                    "certificate": "not_checked",
                    "behavior": "unknown",
                    "evidence_quality": "unavailable",
                },
                findings=[],
                rule_trace=[],
                policy_version=self.policy_version,
                limitations=[
                    "Scan input contains syntax or type parse issues; evaluation withheld (EVID-001)."
                ],
                rationale_summary="Input failed canonical parsing validation.",
                diagnostics=diagnostics_collector.records,
                uncertainty=uncertainty_assessment,
            )

        # Step 2: Input Contract Validation
        val_result = self.validator.validate(policy_input)
        diagnostics_collector.extend(val_result.diagnostics)

        if not val_result.is_valid:
            uncertainty_assessment = self.uncertainty_engine.assess_evidence(
                policy_input=policy_input,
                signals=(),
                decision="inconclusive",
                dimensions={
                    "identity": "unknown",
                    "certificate": "not_checked",
                    "behavior": "unknown",
                    "evidence_quality": "unavailable",
                },
            )
            return TriageResult(
                decision="inconclusive",
                dimensions={
                    "identity": "unknown",
                    "certificate": "not_checked",
                    "behavior": "unknown",
                    "evidence_quality": "unavailable",
                },
                findings=[],
                rule_trace=[],
                policy_version=self.policy_version,
                limitations=[
                    "Scan input failed contract validation checks; evaluation withheld."
                ],
                rationale_summary="Input failed contract validation.",
                diagnostics=diagnostics_collector.records,
                uncertainty=uncertainty_assessment,
            )

        # Step 2b: Target Validation & Multimodal Availability Masking (Phase 07)
        availability_mask = ModalityAvailabilityGate.build_mask(
            evidence_items=policy_input.evidence,
            target=policy_input.target,
            community_reports=policy_input.community_reports,
        )

        if not availability_mask.is_target_valid:
            diagnostics_collector.record(
                code=DiagnosticCode.INPUT_PARSE_ERROR,
                severity=DiagnosticSeverity.ERROR,
                message=f"Target '{policy_input.target}' is malformed or invalid URL/hostname",
                action_taken="Emitted inconclusive triage result due to invalid target",
            )
            uncertainty_assessment = self.uncertainty_engine.assess_evidence(
                policy_input=policy_input,
                signals=(),
                decision="inconclusive",
                dimensions={
                    "identity": "unverified",
                    "certificate": "not_checked",
                    "behavior": "unknown",
                    "evidence_quality": "unavailable",
                },
            )
            return TriageResult(
                decision="inconclusive",
                dimensions={
                    "identity": "unverified",
                    "certificate": "not_checked",
                    "behavior": "unknown",
                    "evidence_quality": "unavailable",
                },
                findings=[],
                rule_trace=[],
                policy_version=self.policy_version,
                limitations=[
                    f"Target '{policy_input.target}' is malformed or unsupported scheme; evaluation withheld."
                ],
                rationale_summary="Target parsing validation failed.",
                diagnostics=diagnostics_collector.records,
                uncertainty=uncertainty_assessment,
                availability_mask=availability_mask,
            )

        # Record unknown evidence kinds preserved in mask
        for unmapped in availability_mask.unmapped_records:
            diagnostics_collector.record(
                code=DiagnosticCode.UNSUPPORTED_EVIDENCE_KIND,
                severity=DiagnosticSeverity.WARNING,
                message=f"Evidence item '{unmapped.get('evidence_id')}' with kind '{unmapped.get('kind')}' was unmapped; preserved in unmapped_records",
                evidence_ids=(unmapped.get("evidence_id"),) if unmapped.get("evidence_id") else (),
                action_taken="Preserved record in mask.unmapped_records without dropping",
            )

        # Step 3: Signal Extraction
        sig_result = self.extractor.extract_signals(policy_input)
        diagnostics_collector.extend(sig_result.diagnostics)

        # Step 4: Run Deterministic Triage Rules
        base_result = self.evaluate(
            signals=list(sig_result.signals),
            scan_id=policy_input.scan_id,
        )

        # Step 5: Enforce Finding-to-Evidence Referential Integrity (Orphan Suppression)
        valid_ev_ids: Set[str] = {
            item.evidence_id for item in policy_input.evidence
        } | {
            rep.report_id for rep in policy_input.community_reports
        }

        sanitized_findings: List[Dict[str, Any]] = []
        orphan_limitations: List[str] = []

        for f in base_result.findings:
            f_ev_ids = f.get("evidence_ids", [])
            orphans = [eid for eid in f_ev_ids if eid not in valid_ev_ids]

            if orphans:
                # Suppress orphan finding completely!
                diagnostics_collector.record(
                    code=DiagnosticCode.ORPHAN_FINDING_SUPPRESSED,
                    severity=DiagnosticSeverity.WARNING,
                    message=f"Suppressed orphan finding '{f.get('kind')}' referencing unknown evidence IDs: {orphans}",
                    evidence_ids=tuple(orphans),
                    action_taken="Suppressed orphan finding from output report",
                    details={"finding_summary": f.get("summary"), "rule_id": f.get("rule_id")},
                )
                orphan_limitations.append(
                    f"Orphan finding '{f.get('kind')}' suppressed due to missing supporting evidence reference."
                )
            else:
                # Deterministic finding ID generation
                f_copy = dict(f)
                f_copy["finding_id"] = generate_deterministic_finding_id(
                    scan_id=policy_input.scan_id,
                    rule_id=f.get("rule_id", "RULE-UNKNOWN"),
                    evidence_ids=f_ev_ids,
                )
                sanitized_findings.append(f_copy)

        # Step 6: Coverage Deficit Limitations Merger
        combined_limitations = list(base_result.limitations)
        combined_limitations.extend(orphan_limitations)

        if policy_input.coverage is not None:
            cov = policy_input.coverage
            if not cov.is_aggregate_complete():
                cov_msg = (
                    f"Coverage is partial: {cov.checks_not_run} checks not run, "
                    f"{cov.checks_failed} checks failed out of {cov.checks_total} total."
                )
                if cov_msg not in combined_limitations:
                    combined_limitations.append(cov_msg)

        # Step 7: Multimodal Availability Gate Evaluation & Positive Threat Preservation (Phase 07)
        has_positive_threat = any(s.kind == SignalKind.THREAT_FEED_MATCH for s in sig_result.signals)
        gate_result = ModalityAvailabilityGate.evaluate_gate(
            mask=availability_mask,
            has_positive_threat=has_positive_threat,
        )

        for diag_code in gate_result.diagnostics:
            if diag_code == DiagnosticCode.COVERAGE_DEFICIT:
                diagnostics_collector.record(
                    code=DiagnosticCode.COVERAGE_DEFICIT,
                    severity=DiagnosticSeverity.WARNING,
                    message=gate_result.reason,
                    action_taken="Enforced multimodal availability gate requirement",
                )
            elif diag_code == DiagnosticCode.STALE_EVIDENCE_FLAGGED:
                diagnostics_collector.record(
                    code=DiagnosticCode.STALE_EVIDENCE_FLAGGED,
                    severity=DiagnosticSeverity.WARNING,
                    message=gate_result.reason,
                    action_taken="Enforced freshness requirement on threat intelligence",
                )
            elif diag_code == DiagnosticCode.INPUT_PARSE_ERROR:
                diagnostics_collector.record(
                    code=DiagnosticCode.INPUT_PARSE_ERROR,
                    severity=DiagnosticSeverity.ERROR,
                    message=gate_result.reason,
                    action_taken="Quarantined input with invalid target",
                )

        final_decision = base_result.decision
        if gate_result.requires_inconclusive and final_decision == "no_threat_observed":
            final_decision = "inconclusive"
            if gate_result.reason not in combined_limitations:
                combined_limitations.append(gate_result.reason)

        # Step 8: Uncertainty Quantification & Abstention Notice Generation
        uncertainty_assessment = self.uncertainty_engine.assess_evidence(
            policy_input=policy_input,
            signals=sig_result.signals,
            decision=final_decision,
            dimensions=base_result.dimensions,
        )

        if uncertainty_assessment.abstention_notice:
            abstain_text = uncertainty_assessment.abstention_notice.explanation
            if abstain_text not in combined_limitations:
                combined_limitations.append(abstain_text)

        return TriageResult(
            decision=final_decision,
            dimensions=base_result.dimensions,
            findings=sanitized_findings,
            rule_trace=base_result.rule_trace,
            policy_version=self.policy_version,
            limitations=combined_limitations,
            rationale_summary=base_result.rationale_summary,
            diagnostics=diagnostics_collector.records,
            uncertainty=uncertainty_assessment,
            availability_mask=availability_mask,
        )

    def evaluate(
        self,
        signals: List[SignalRecord],
        scan_id: Optional[str] = None,
    ) -> TriageResult:
        """Run all rules against the signal set and compose a triage result.

        Args:
            signals: Typed, provenance-linked signals from collectors/evidence.
            scan_id: Optional scan ID for deterministic finding ID generation.

        Returns:
            TriageResult with decision, dimensions, findings, and full rule trace.
        """
        effective_scan_id = scan_id or f"scan-{uuid.uuid4().hex[:8]}"

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
            result = rule_fn(signals, by_dimension, dimensions, effective_scan_id)
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

        # Uncertainty quantification
        uncertainty_assessment = self.uncertainty_engine.assess_signals(
            signals=signals,
            decision=decision,
            dimensions=dimensions,
        )

        if uncertainty_assessment.abstention_notice:
            abstain_text = uncertainty_assessment.abstention_notice.explanation
            if abstain_text not in all_limitations:
                all_limitations.append(abstain_text)

        return TriageResult(
            decision=decision,
            dimensions=dimensions,
            findings=all_findings,
            rule_trace=rule_results,
            policy_version=self.policy_version,
            limitations=all_limitations,
            rationale_summary=rationale_summary,
            uncertainty=uncertainty_assessment,
        )

    # ─── Individual Named Rules ───────────────────────────────────────

    def _rule_certificate(
        self,
        signals: List[SignalRecord],
        by_dim: Dict[SignalDimension, List[SignalRecord]],
        current_dims: Dict[str, str],
        scan_id: str,
    ) -> RuleResult:
        """RULE-CERT-001: Map TLS signals to certificate dimension."""
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
                ev_ids: List[str] = []
                for s in cert_signals:
                    if s.kind in (SignalKind.TLS_EXPIRED, SignalKind.TLS_MISMATCH):
                        ev_ids.extend(s.evidence_ids)

                findings.append({
                    "finding_id": generate_deterministic_finding_id(scan_id, "RULE-CERT-001", ev_ids),
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
        scan_id: str,
    ) -> RuleResult:
        """RULE-ID-001: Map identity signals. TLS alone -> unverified (TLS-001)."""
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
        scan_id: str,
    ) -> RuleResult:
        """RULE-BEH-001: Map behavior signals with conservative disposition ceilings."""
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
            for s in beh_signals:
                if s.kind == SignalKind.THREAT_FEED_MATCH:
                    findings.append({
                        "finding_id": generate_deterministic_finding_id(scan_id, "RULE-BEH-001", s.evidence_ids),
                        "kind": "threat_feed_match",
                        "severity": "high",
                        "summary": "URL/domain matches an active threat intelligence feed entry.",
                        "evidence_ids": list(s.evidence_ids),
                        "rule_id": "RULE-BEH-001",
                        "rule_version": self.policy_version,
                        "created_at": _now_iso(),
                        "limitations": list(s.limitations),
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
                        "finding_id": generate_deterministic_finding_id(scan_id, "RULE-BEH-001", s.evidence_ids),
                        "kind": s.kind.value,
                        "severity": "medium",
                        "summary": f"Suspicious signal: {s.kind.value}.",
                        "evidence_ids": list(s.evidence_ids),
                        "rule_id": "RULE-BEH-001",
                        "rule_version": self.policy_version,
                        "created_at": _now_iso(),
                        "limitations": list(s.limitations),
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
        scan_id: str,
    ) -> RuleResult:
        """RULE-EVQUAL-001: Assess evidence quality from collector outcomes."""
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
        scan_id: str,
    ) -> RuleResult:
        """RULE-COMM-001: Community report constraints."""
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
                    "finding_id": generate_deterministic_finding_id(scan_id, "RULE-COMM-001", s.evidence_ids),
                    "kind": "community_report",
                    "severity": "info",
                    "summary": "Unverified community report exists for this domain.",
                    "evidence_ids": list(s.evidence_ids),
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
                    "finding_id": generate_deterministic_finding_id(scan_id, "RULE-COMM-001", s.evidence_ids),
                    "kind": "community_report_corroborated",
                    "severity": "medium",
                    "summary": "Community report corroborated by independent source families.",
                    "evidence_ids": list(s.evidence_ids),
                    "rule_id": "RULE-COMM-001",
                    "rule_version": self.policy_version,
                    "created_at": _now_iso(),
                    "limitations": list(s.limitations),
                })
                rationale_parts.append("Corroborated community report strengthens caution.")
            elif s.kind == SignalKind.COMMUNITY_REPORT_DISPUTED:
                findings.append({
                    "finding_id": generate_deterministic_finding_id(scan_id, "RULE-COMM-001", s.evidence_ids),
                    "kind": "community_report_disputed",
                    "severity": "info",
                    "summary": "Community report is disputed; both evidence trails retained.",
                    "evidence_ids": list(s.evidence_ids),
                    "rule_id": "RULE-COMM-001",
                    "rule_version": self.policy_version,
                    "created_at": _now_iso(),
                    "limitations": [
                        "Disputed community reports retained without resolution; cautious policy applied."
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
        scan_id: str,
    ) -> RuleResult:
        """RULE-CONFLICT-001: Detect material conflicts and enforce cautious policy."""
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

        Preservation of Positive Threat Evidence:
        If valid positive threat evidence is observed (THREAT_FEED_MATCH) and no material
        conflict exists, high_risk is preserved even if unrelated collectors encountered partial failures.
        """
        SEVERITY_ORDER = {
            "failed": 0,
            "inconclusive": 1,
            "caution": 2,
            "high_risk": 3,
            "no_threat_observed": 4,
        }

        # Positive threat evidence preservation check
        has_threat = any(s.kind == SignalKind.THREAT_FEED_MATCH for s in signals)
        has_threat_conflict = any(s.kind == SignalKind.NO_THREAT_MATCH for s in signals)

        if has_threat and not has_threat_conflict:
            # Positive threat is preserved; remove inconclusive ceilings from unrelated collector failures
            ceilings = [c for c in ceilings if c != "inconclusive"]
            if "high_risk" not in ceilings:
                ceilings.append("high_risk")

        if not ceilings:
            ev_quality = dimensions.get("evidence_quality", "unavailable")
            behavior = dimensions.get("behavior", "unknown")

            if behavior == "malicious_evidence":
                return "high_risk"
            if ev_quality == "unavailable":
                return "inconclusive"
            if behavior == "unknown":
                return "inconclusive"
            if behavior == "no_threat_observed" and ev_quality == "strong":
                return "no_threat_observed"
            if behavior == "suspicious":
                return "caution"
            return "inconclusive"

        min_ceiling = min(ceilings, key=lambda c: SEVERITY_ORDER.get(c, 999))
        return min_ceiling


def _now_iso() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
