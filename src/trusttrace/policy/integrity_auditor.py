"""Automated report integrity auditor — Worker 03 Phase 04.

Enforces TRUSTTRACE core safety and claim discipline invariants before reports are published:
- Rule 1 (INV-TLS-001): Reject reports where identity="supported" without explicit authorization evidence.
- Rule 2 (INV-EVID-002): Reject affirmative global safety claims ('safe', 'clean'); missing feed match is not proof of safety.
  Distinguishes affirmative claims from explanatory/negated disclaimers.
- Rule 3 (INV-COV-001): Ensure no_threat_observed under partial coverage explicitly discloses limited scope.
- Rule 4 (INV-CLAIM-001): Anti-marketing guard detecting unsupported absolute assertions ('100% safe', 'bulletproof', 'zero false positives').
- Rule 5 (INV-FINDING-001): Finding referential integrity (finding evidence_ids must point to declared evidence).
- Rule 6 (INV-COV-002): Coverage arithmetic integrity (checks_total == checks_observed + checks_failed + checks_not_run).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple


class AuditSeverity(str, Enum):
    """Severity of an audit finding."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class AuditRuleId(str, Enum):
    """Standardized rule identifiers for report integrity invariants."""

    TLS_001 = "INV-TLS-001"
    EVID_002 = "INV-EVID-002"
    COV_001 = "INV-COV-001"
    CLAIM_001 = "INV-CLAIM-001"
    FINDING_001 = "INV-FINDING-001"
    COV_002 = "INV-COV-002"


@dataclass(frozen=True)
class AuditIssue:
    """A single finding from report integrity audit."""

    rule_id: str
    severity: AuditSeverity
    affected_field: str
    evidence_references: Tuple[str, ...] = ()
    explanation: str = ""
    details: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "affected_field": self.affected_field,
            "evidence_references": list(self.evidence_references),
            "explanation": self.explanation,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class ReportAuditResult:
    """Consolidated report audit outcome."""

    is_valid: bool
    issues: Tuple[AuditIssue, ...]
    rules_checked: Tuple[str, ...]

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == AuditSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == AuditSeverity.WARNING)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issues": [i.to_dict() for i in self.issues],
            "rules_checked": list(self.rules_checked),
        }


class ReportIntegrityAuditor:
    """Automated invariant auditor for TRUSTTRACE reports and triage results."""

    # Absolute marketing terms prohibited unless explicitly negated
    ABSOLUTE_MARKETING_PATTERNS = [
        re.compile(r"\b100\s*%\s*(safe|secure|clean|protected|accurate)\b", re.IGNORECASE),
        re.compile(r"\b(bulletproof|impenetrable|unhackable|unbreakable)\b", re.IGNORECASE),
        re.compile(r"\bguaranteed\s+(phishing|malware|threat)[\s-]*free\b", re.IGNORECASE),
        re.compile(r"\bguaranteed\s+safe(ty)?\b", re.IGNORECASE),
        re.compile(r"\bzero\s+(false\s+positives?|false\s+negatives?|risk)\b", re.IGNORECASE),
        re.compile(r"\bperfect\s+protection\b", re.IGNORECASE),
    ]

    # Affirmative safety words prohibited in affirmative context (EVID-002)
    GLOBAL_SAFETY_PATTERNS = [
        re.compile(r"\b(this\s+(site|url|domain)\s+is\s+(safe|clean|verified\s+safe))\b", re.IGNORECASE),
        re.compile(r"\b(site|domain|url)\s+is\s+100%\s+safe\b", re.IGNORECASE),
        re.compile(r"\bverified\s+safe\s+destination\b", re.IGNORECASE),
        re.compile(r"\bguaranteed\s+clean\b", re.IGNORECASE),
        re.compile(r"\bconclusively\s+safe\b", re.IGNORECASE),
    ]

    # Negation indicators indicating educational / disclaimer context
    NEGATION_INDICATORS = [
        "not ", "never ", "no ", "without ", "cannot ", "can't ", "does not ", "doesn't ",
        "is not ", "isn't ", "fail to ", "failed to ", "insufficient to ", "not proof of ",
        "not evidence of ", "does not guarantee ", "does not imply ", "does not mean ",
        "absence of ", "neither ", "unable to ", "cannot establish ",
    ]

    def audit_report(self, report: Dict[str, Any]) -> ReportAuditResult:
        """Audit a complete scan report dictionary against all core invariants.

        Args:
            report: A dictionary structured according to scan_report.schema.json.

        Returns:
            ReportAuditResult with detailed issues and pass/fail validity.
        """
        issues: List[AuditIssue] = []
        rules_checked = [
            AuditRuleId.TLS_001.value,
            AuditRuleId.EVID_002.value,
            AuditRuleId.COV_001.value,
            AuditRuleId.CLAIM_001.value,
            AuditRuleId.FINDING_001.value,
            AuditRuleId.COV_002.value,
        ]

        # ─── Rule 1 (INV-TLS-001): Identity Authorization vs TLS Validity ─
        self._check_rule_tls_001(report, issues)

        # ─── Rule 2 (INV-EVID-002): Affirmative Global Safety Claims ──────
        self._check_rule_evid_002(report, issues)

        # ─── Rule 3 (INV-COV-001): Coverage Invariant & No-Threat Scope ──
        self._check_rule_cov_001(report, issues)

        # ─── Rule 4 (INV-CLAIM-001): Anti-Marketing Guard ────────────────
        self._check_rule_claim_001(report, issues)

        # ─── Rule 5 (INV-FINDING-001): Finding Evidence Referential Integrity
        self._check_rule_finding_001(report, issues)

        # ─── Rule 6 (INV-COV-002): Coverage Arithmetic Integrity ─────────
        self._check_rule_cov_002(report, issues)

        is_valid = not any(i.severity == AuditSeverity.ERROR for i in issues)
        return ReportAuditResult(
            is_valid=is_valid,
            issues=tuple(issues),
            rules_checked=tuple(rules_checked),
        )

    # ─── Invariant Implementations ─────────────────────────────────────

    def _check_rule_tls_001(self, report: Dict[str, Any], issues: List[AuditIssue]) -> None:
        """Reject identity='supported' unless explicit authorization evidence is present."""
        dimensions = report.get("dimensions", {})
        identity_val = dimensions.get("identity")

        if identity_val == "supported":
            evidence_items = report.get("evidence", [])
            has_auth = False
            auth_ids: List[str] = []

            for ev in evidence_items:
                kind = str(ev.get("kind", "")).lower()
                status = str(ev.get("status", "")).lower()
                if status == "observed" and (
                    "authoriz" in kind
                    or "domain_ownership" in kind
                    or "brand_authorization" in kind
                    or "verified_identity" in kind
                ):
                    has_auth = True
                    auth_ids.append(str(ev.get("evidence_id", "")))

            # If evidence list is omitted or no authorization evidence was found
            if not has_auth:
                issues.append(
                    AuditIssue(
                        rule_id=AuditRuleId.TLS_001.value,
                        severity=AuditSeverity.ERROR,
                        affected_field="dimensions.identity",
                        explanation=(
                            "Report specifies identity='supported' without explicit, valid authorization evidence. "
                            "TLS validity alone confirms certificate coverage, not organizational identity authorization (TLS-001)."
                        ),
                    )
                )

    def _check_rule_evid_002(self, report: Dict[str, Any], issues: List[AuditIssue]) -> None:
        """Reject affirmative global claims ('safe', 'clean'); absence of threat feed match is not proof of safety."""
        decision = str(report.get("decision", "")).lower()
        if decision in ("safe", "clean"):
            issues.append(
                AuditIssue(
                    rule_id=AuditRuleId.EVID_002.value,
                    severity=AuditSeverity.ERROR,
                    affected_field="decision",
                    explanation=f"Affirmative decision '{decision}' is forbidden. Absence of threats is at most 'no_threat_observed' (EVID-002).",
                )
            )

        # Inspect free text fields: findings summaries, limitations, rationale
        texts_to_check: List[Tuple[str, str]] = []
        for i, f in enumerate(report.get("findings", [])):
            texts_to_check.append((f"findings[{i}].summary", str(f.get("summary", ""))))
            for j, lim in enumerate(f.get("limitations", [])):
                texts_to_check.append((f"findings[{i}].limitations[{j}]", str(lim)))

        for i, lim in enumerate(report.get("limitations", [])):
            texts_to_check.append((f"limitations[{i}]", str(lim)))

        for field_name, text in texts_to_check:
            if not text:
                continue
            for pat in self.GLOBAL_SAFETY_PATTERNS:
                match = pat.search(text)
                if match:
                    matched_str = match.group(0)
                    if not self._is_negated_or_disclaimer(text, match.start()):
                        issues.append(
                            AuditIssue(
                                rule_id=AuditRuleId.EVID_002.value,
                                severity=AuditSeverity.ERROR,
                                affected_field=field_name,
                                explanation=(
                                    f"Prohibited affirmative safety assertion detected: '{matched_str}'. "
                                    "A clean check or missing threat feed match is never affirmative proof of safety (EVID-002)."
                                ),
                                details=MappingProxyType({"matched_text": matched_str}),
                            )
                        )

    def _check_rule_cov_001(self, report: Dict[str, Any], issues: List[AuditIssue]) -> None:
        """Ensure no_threat_observed under partial coverage explicitly discloses limited scope."""
        decision = str(report.get("decision", "")).lower()
        if decision != "no_threat_observed":
            return

        coverage = report.get("coverage", {})
        if not coverage:
            return

        checks_total = coverage.get("checks_total", 0)
        checks_failed = coverage.get("checks_failed", 0)
        checks_not_run = coverage.get("checks_not_run", 0)

        # Incomplete coverage check
        if (checks_failed > 0 or checks_not_run > 0) and checks_total > 0:
            limitations = report.get("limitations", [])
            has_coverage_disclosure = any(
                ("partial" in lim.lower() or "not run" in lim.lower() or "failed" in lim.lower() or "limited" in lim.lower() or "coverage" in lim.lower())
                for lim in limitations
            )
            ev_quality = report.get("dimensions", {}).get("evidence_quality", "")

            if not has_coverage_disclosure or ev_quality == "strong":
                issues.append(
                    AuditIssue(
                        rule_id=AuditRuleId.COV_001.value,
                        severity=AuditSeverity.ERROR,
                        affected_field="decision",
                        explanation=(
                            f"Decision is 'no_threat_observed' but coverage is partial ({checks_failed} failed, {checks_not_run} not run) "
                            "without explicit disclosure in limitations or with ungrounded evidence_quality='strong'. "
                            "An unqualified safety assurance cannot be issued under partial coverage."
                        ),
                        details=MappingProxyType({
                            "checks_failed": checks_failed,
                            "checks_not_run": checks_not_run,
                            "evidence_quality": ev_quality,
                        }),
                    )
                )

    def _check_rule_claim_001(self, report: Dict[str, Any], issues: List[AuditIssue]) -> None:
        """Detect unsupported absolute marketing assertions ('100% secure', 'bulletproof', 'zero false positives')."""
        texts_to_check: List[Tuple[str, str]] = []
        for i, f in enumerate(report.get("findings", [])):
            texts_to_check.append((f"findings[{i}].summary", str(f.get("summary", ""))))
            for j, lim in enumerate(f.get("limitations", [])):
                texts_to_check.append((f"findings[{i}].limitations[{j}]", str(lim)))

        for i, lim in enumerate(report.get("limitations", [])):
            texts_to_check.append((f"limitations[{i}]", str(lim)))

        for field_name, text in texts_to_check:
            if not text:
                continue
            for pat in self.ABSOLUTE_MARKETING_PATTERNS:
                match = pat.search(text)
                if match:
                    matched_str = match.group(0)
                    if not self._is_negated_or_disclaimer(text, match.start()):
                        issues.append(
                            AuditIssue(
                                rule_id=AuditRuleId.CLAIM_001.value,
                                severity=AuditSeverity.ERROR,
                                affected_field=field_name,
                                explanation=(
                                    f"Prohibited absolute marketing assertion detected: '{matched_str}'. "
                                    "Absolute security or perfection claims violate TRUSTTRACE claim discipline."
                                ),
                                details=MappingProxyType({"matched_text": matched_str}),
                            )
                        )

    def _check_rule_finding_001(self, report: Dict[str, Any], issues: List[AuditIssue]) -> None:
        """Confirm all finding evidence_ids point to declared evidence records in the report."""
        findings = report.get("findings", [])
        evidence_list = report.get("evidence", [])
        community_reports = report.get("community_reports", [])

        declared_ids: Set[str] = {
            str(e.get("evidence_id")) for e in evidence_list if e.get("evidence_id")
        } | {
            str(r.get("report_id")) for r in community_reports if r.get("report_id")
        }

        for i, f in enumerate(findings):
            ev_ids = f.get("evidence_ids", [])
            finding_id = f.get("finding_id", f"finding[{i}]")

            if not ev_ids:
                issues.append(
                    AuditIssue(
                        rule_id=AuditRuleId.FINDING_001.value,
                        severity=AuditSeverity.ERROR,
                        affected_field=f"findings[{i}].evidence_ids",
                        explanation=f"Finding '{finding_id}' has empty evidence_ids. Every finding must cite at least one evidence ID.",
                    )
                )
                continue

            # If declared evidence records are present, verify referential integrity
            if declared_ids:
                orphans = [eid for eid in ev_ids if str(eid) not in declared_ids]
                if orphans:
                    issues.append(
                        AuditIssue(
                            rule_id=AuditRuleId.FINDING_001.value,
                            severity=AuditSeverity.ERROR,
                            affected_field=f"findings[{i}].evidence_ids",
                            evidence_references=tuple(orphans),
                            explanation=(
                                f"Finding '{finding_id}' references undeclared evidence ID(s): {orphans}. "
                                "Findings must maintain referential integrity with declared scan evidence."
                            ),
                        )
                    )

    def _check_rule_cov_002(self, report: Dict[str, Any], issues: List[AuditIssue]) -> None:
        """Confirm checks_total == checks_observed + checks_failed + checks_not_run."""
        coverage = report.get("coverage")
        if not coverage or not isinstance(coverage, dict):
            return

        total = coverage.get("checks_total")
        observed = coverage.get("checks_observed")
        failed = coverage.get("checks_failed")
        not_run = coverage.get("checks_not_run")

        if (
            isinstance(total, int)
            and isinstance(observed, int)
            and isinstance(failed, int)
            and isinstance(not_run, int)
        ):
            if total != (observed + failed + not_run):
                issues.append(
                    AuditIssue(
                        rule_id=AuditRuleId.COV_002.value,
                        severity=AuditSeverity.ERROR,
                        affected_field="coverage.checks_total",
                        explanation=(
                            f"Coverage arithmetic inconsistency: checks_total ({total}) != "
                            f"checks_observed ({observed}) + checks_failed ({failed}) + checks_not_run ({not_run})."
                        ),
                        details=MappingProxyType({
                            "checks_total": total,
                            "checks_observed": observed,
                            "checks_failed": failed,
                            "checks_not_run": not_run,
                        }),
                    )
                )

    def _is_negated_or_disclaimer(self, text: str, match_pos: int) -> bool:
        """Check if a match position is preceded by a negation or educational disclaimer."""
        # Inspect up to 60 characters preceding the match
        start_idx = max(0, match_pos - 60)
        window = text[start_idx:match_pos].lower()

        # Check for negation indicators in the preceding window
        for neg in self.NEGATION_INDICATORS:
            if neg in window:
                return True

        # Check for clause / sentence boundary in the full text
        lower_full = text.lower()
        if "never 'safe'" in lower_full or 'never "safe"' in lower_full:
            return True
        if "not proof of" in lower_full or "does not establish" in lower_full or "not sole proof" in lower_full:
            return True

        return False
