"""Input Validation Engine for Worker 03 Phase 03.

Validates canonical v1 policy inputs prior to signal extraction and triage evaluation.
Produces structured validation results and integrates with the diagnostics engine.

Invariants:
1. Pure Python standard library only.
2. Input immutability: Never mutates policy inputs or evidence items.
3. No silent data loss: Every validation failure produces structured ValidationIssue
   and DiagnosticRecord entries.
4. Non-duplication: Does NOT duplicate Worker 01 URL/SSRF checks or Worker 02
   persistence validation; focuses strictly on evidence integrity, provenance,
   target scope, and coverage consistency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .diagnostics import DiagnosticCode, DiagnosticCollector, DiagnosticRecord, DiagnosticSeverity
from .policy_input import CommunityReportItem, CoverageSummary, EvidenceItem, PolicyInput


VALID_EVIDENCE_STATUSES = frozenset({"observed", "failed", "unavailable", "blocked", "not_run"})
VALID_SOURCE_RELIABILITIES = frozenset({
    "direct_observation",
    "verified_source",
    "reputable_third_party",
    "unverified_third_party",
    "untrusted",
    "heuristic",
    "corroborated",
})
VALID_COMMUNITY_STATES = frozenset({"verified", "unverified", "disputed", "rejected"})


@dataclass(frozen=True)
class ValidationIssue:
    """Structured representation of a validation anomaly or policy violation."""

    path: str
    code: DiagnosticCode
    severity: DiagnosticSeverity
    message: str
    invalid_value: Any = None


@dataclass(frozen=True)
class ValidationResult:
    """Aggregate result of input validation.

    Attributes:
        is_valid: True if there are zero ERROR-level validation issues.
        issues: Tuple of all recorded ValidationIssue instances.
        diagnostics: Tuple of generated DiagnosticRecord instances.
    """

    is_valid: bool
    issues: Tuple[ValidationIssue, ...] = field(default_factory=tuple)
    diagnostics: Tuple[DiagnosticRecord, ...] = field(default_factory=tuple)


def _validate_iso_utc_timestamp(ts: str) -> bool:
    """Validate that timestamp string is valid ISO-8601 in UTC."""
    if not isinstance(ts, str) or not ts.strip():
        return False
    try:
        norm = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(norm)
        # Verify UTC timezone
        tz = dt.tzinfo
        if tz is None:
            return False
        return dt.utcoffset() == timezone.utc.utcoffset(None)
    except Exception:
        return False


class EvidenceValidator:
    """Validates PolicyInput against canonical v1 contracts and policy boundaries."""

    def __init__(self) -> None:
        pass

    def validate(self, policy_input: PolicyInput) -> ValidationResult:
        """Execute all validation checks on policy_input.

        Returns:
            ValidationResult with boolean is_valid, structured issues, and diagnostics.
        """
        collector = DiagnosticCollector()
        issues: List[ValidationIssue] = []

        # 1. Unresolved parse issues gate
        if not policy_input.is_valid:
            for p_issue in policy_input.parse_issues:
                issue = ValidationIssue(
                    path=p_issue.path,
                    code=DiagnosticCode.INPUT_PARSE_ERROR,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Parse issue: {p_issue.message}",
                    invalid_value=p_issue.invalid_value,
                )
                issues.append(issue)
                collector.record(
                    code=DiagnosticCode.INPUT_PARSE_ERROR,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Input parse error at '{p_issue.path}': {p_issue.message}",
                    action_taken="Quarantined input from evaluation",
                    details={"path": p_issue.path, "invalid_value": repr(p_issue.invalid_value)},
                )

        # 2. Required root metadata
        target = policy_input.target.strip() if policy_input.target else ""
        if not target:
            issue = ValidationIssue(
                path="target",
                code=DiagnosticCode.INPUT_PARSE_ERROR,
                severity=DiagnosticSeverity.ERROR,
                message="Target domain/host must be specified and non-empty",
                invalid_value=policy_input.target,
            )
            issues.append(issue)
            collector.record(
                code=DiagnosticCode.INPUT_PARSE_ERROR,
                severity=DiagnosticSeverity.ERROR,
                message="Missing or blank target",
                action_taken="Marked input invalid",
            )

        scan_id = policy_input.scan_id.strip() if policy_input.scan_id else ""
        if not scan_id:
            issue = ValidationIssue(
                path="scan_id",
                code=DiagnosticCode.INPUT_PARSE_ERROR,
                severity=DiagnosticSeverity.ERROR,
                message="Scan ID must be specified and non-empty",
                invalid_value=policy_input.scan_id,
            )
            issues.append(issue)
            collector.record(
                code=DiagnosticCode.INPUT_PARSE_ERROR,
                severity=DiagnosticSeverity.ERROR,
                message="Missing or blank scan_id",
                action_taken="Marked input invalid",
            )

        # 3. Evidence Batch Validation
        seen_evidence_ids: Set[str] = set()
        for idx, item in enumerate(policy_input.evidence):
            item_path = f"evidence[{idx}]"

            # Check duplicate evidence_id
            if item.evidence_id in seen_evidence_ids:
                issue = ValidationIssue(
                    path=f"{item_path}.evidence_id",
                    code=DiagnosticCode.DUPLICATE_EVIDENCE_ID,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Duplicate evidence ID '{item.evidence_id}' encountered",
                    invalid_value=item.evidence_id,
                )
                issues.append(issue)
                collector.record(
                    code=DiagnosticCode.DUPLICATE_EVIDENCE_ID,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Duplicate evidence ID '{item.evidence_id}'",
                    evidence_ids=(item.evidence_id,),
                    action_taken="Flagged duplicate evidence ID",
                )
            else:
                seen_evidence_ids.add(item.evidence_id)

            # Check status
            if item.status not in VALID_EVIDENCE_STATUSES:
                issue = ValidationIssue(
                    path=f"{item_path}.status",
                    code=DiagnosticCode.MALFORMED_PAYLOAD,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Invalid evidence status '{item.status}' (expected one of {sorted(VALID_EVIDENCE_STATUSES)})",
                    invalid_value=item.status,
                )
                issues.append(issue)
                collector.record(
                    code=DiagnosticCode.MALFORMED_PAYLOAD,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Invalid evidence status '{item.status}'",
                    evidence_ids=(item.evidence_id,),
                    action_taken="Flagged invalid status",
                )

            # Check source reliability
            if item.reliability not in VALID_SOURCE_RELIABILITIES:
                issue = ValidationIssue(
                    path=f"{item_path}.reliability",
                    code=DiagnosticCode.MALFORMED_PAYLOAD,
                    severity=DiagnosticSeverity.WARNING,
                    message=f"Unknown source reliability '{item.reliability}'",
                    invalid_value=item.reliability,
                )
                issues.append(issue)
                collector.record(
                    code=DiagnosticCode.MALFORMED_PAYLOAD,
                    severity=DiagnosticSeverity.WARNING,
                    message=f"Unknown reliability '{item.reliability}'",
                    evidence_ids=(item.evidence_id,),
                    action_taken="Downgraded reliability handling",
                )

            # Check timestamp
            if not _validate_iso_utc_timestamp(item.observed_at):
                issue = ValidationIssue(
                    path=f"{item_path}.observed_at",
                    code=DiagnosticCode.MALFORMED_PAYLOAD,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Invalid ISO-8601 UTC timestamp '{item.observed_at}'",
                    invalid_value=item.observed_at,
                )
                issues.append(issue)
                collector.record(
                    code=DiagnosticCode.MALFORMED_PAYLOAD,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Invalid observation timestamp '{item.observed_at}'",
                    evidence_ids=(item.evidence_id,),
                    action_taken="Flagged invalid timestamp",
                )

            # Check payload scope / target matching if payload has explicit target/hostname
            if isinstance(item.value, Mapping):
                ev_target = item.value.get("hostname") or item.value.get("target") or item.value.get("domain")
                if ev_target and isinstance(ev_target, str) and target:
                    ev_t_lower = ev_target.strip().lower()
                    target_lower = target.lower()
                    if ev_t_lower != target_lower and not ev_t_lower.endswith("." + target_lower):
                        issue = ValidationIssue(
                            path=f"{item_path}.value.hostname",
                            code=DiagnosticCode.TARGET_SCOPE_MISMATCH,
                            severity=DiagnosticSeverity.WARNING,
                            message=f"Evidence payload target '{ev_target}' does not match scan target '{target}'",
                            invalid_value=ev_target,
                        )
                        issues.append(issue)
                        collector.record(
                            code=DiagnosticCode.TARGET_SCOPE_MISMATCH,
                            severity=DiagnosticSeverity.WARNING,
                            message=f"Evidence payload target '{ev_target}' mismatch with scan target '{target}'",
                            evidence_ids=(item.evidence_id,),
                            action_taken="Preserved scope mismatch diagnostic",
                        )

        # 4. Coverage Validation
        if policy_input.coverage is not None:
            cov = policy_input.coverage
            total_sum = cov.checks_observed + cov.checks_failed + cov.checks_not_run
            if total_sum != cov.checks_total:
                issue = ValidationIssue(
                    path="coverage",
                    code=DiagnosticCode.COVERAGE_DEFICIT,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Coverage arithmetic mismatch: observed ({cov.checks_observed}) + failed ({cov.checks_failed}) + not_run ({cov.checks_not_run}) != total ({cov.checks_total})",
                )
                issues.append(issue)
                collector.record(
                    code=DiagnosticCode.COVERAGE_DEFICIT,
                    severity=DiagnosticSeverity.ERROR,
                    message="Coverage invariant violated",
                    action_taken="Flagged coverage error",
                )
            elif not cov.is_aggregate_complete():
                collector.record(
                    code=DiagnosticCode.COVERAGE_DEFICIT,
                    severity=DiagnosticSeverity.INFO,
                    message=f"Coverage is partial: {cov.checks_not_run} checks not run, {cov.checks_failed} checks failed",
                    action_taken="Appended coverage deficit limitation",
                    details={"checks_total": cov.checks_total, "checks_observed": cov.checks_observed, "checks_failed": cov.checks_failed, "checks_not_run": cov.checks_not_run},
                )

        # 5. Community Reports Validation
        for idx, rep in enumerate(policy_input.community_reports):
            rep_path = f"community_reports[{idx}]"

            # Target matching
            if rep.normalized_domain and target:
                if rep.normalized_domain.strip().lower() != target.lower():
                    issue = ValidationIssue(
                        path=f"{rep_path}.normalized_domain",
                        code=DiagnosticCode.TARGET_SCOPE_MISMATCH,
                        severity=DiagnosticSeverity.WARNING,
                        message=f"Community report domain '{rep.normalized_domain}' does not match scan target '{target}'",
                        invalid_value=rep.normalized_domain,
                    )
                    issues.append(issue)
                    collector.record(
                        code=DiagnosticCode.TARGET_SCOPE_MISMATCH,
                        severity=DiagnosticSeverity.WARNING,
                        message=f"Community report domain '{rep.normalized_domain}' does not match scan target '{target}'",
                        action_taken="Suppressed community signal extraction",
                        details={"report_id": rep.report_id, "report_domain": rep.normalized_domain, "target": target},
                    )

            # Verification state
            if rep.verification_state not in VALID_COMMUNITY_STATES:
                issue = ValidationIssue(
                    path=f"{rep_path}.verification_state",
                    code=DiagnosticCode.MALFORMED_PAYLOAD,
                    severity=DiagnosticSeverity.WARNING,
                    message=f"Unknown verification state '{rep.verification_state}'",
                    invalid_value=rep.verification_state,
                )
                issues.append(issue)

            # Linked evidence referential integrity
            for lid in rep.linked_evidence_ids:
                if lid not in seen_evidence_ids:
                    collector.record(
                        code=DiagnosticCode.UNLINKED_COMMUNITY_REPORT,
                        severity=DiagnosticSeverity.WARNING,
                        message=f"Community report '{rep.report_id}' references non-existent evidence ID '{lid}'",
                        action_taken="Treated report as unlinked",
                        details={"report_id": rep.report_id, "missing_evidence_id": lid},
                    )

            # Timestamp check
            if rep.submitted_at and not _validate_iso_utc_timestamp(rep.submitted_at):
                issue = ValidationIssue(
                    path=f"{rep_path}.submitted_at",
                    code=DiagnosticCode.MALFORMED_PAYLOAD,
                    severity=DiagnosticSeverity.WARNING,
                    message=f"Invalid submitted_at timestamp '{rep.submitted_at}'",
                    invalid_value=rep.submitted_at,
                )
                issues.append(issue)

        has_blocking_errors = any(i.severity == DiagnosticSeverity.ERROR for i in issues)
        return ValidationResult(
            is_valid=not has_blocking_errors,
            issues=tuple(issues),
            diagnostics=collector.records,
        )
