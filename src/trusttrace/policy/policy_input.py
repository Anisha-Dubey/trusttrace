"""Policy Input Data Transfer Objects (DTOs) for Worker 03 Phase 03.

Defines immutable, strongly-typed internal representations of canonical v1 evidence,
coverage summary, community report items, and overall policy input.

Immutability & Safety Guarantees:
1. Pure Python standard library only (dataclasses, typing, types.MappingProxyType).
2. Input immutability: Parsing functions NEVER mutate caller inputs or nested objects.
3. Shallow and deep immutability:
   - All DTOs are decorated with @dataclass(frozen=True), preventing attribute reassignment.
   - All collection fields (limitations, linked_evidence_ids, evidence, community_reports,
     parse_issues) are immutable tuples.
   - All unparsed_fields mappings and nested dictionary values are wrapped in read-only
     types.MappingProxyType, preventing in-place key/value manipulation.
4. No silent record loss: Malformed records, missing required fields, or invalid types
   produce explicit structured `ParseIssue` instances.
   - When strict=True (default), `PolicyInputParseError` is raised.
   - When strict=False, issues are recorded in `PolicyInput.parse_issues`.
5. Evaluation gate: `PolicyInput.is_valid` returns True only if there are zero parse issues.
   Downstream triage engines MUST check `policy_input.is_valid` before evaluating.
6. No unsafe type coercion: Booleans are rejected as integers; numbers are rejected as strings.
7. Sequence integrity: Fields expecting sequences reject bare strings and require homogeneous
   non-empty string elements.
8. Unknown field isolation: Extra fields are isolated into unparsed_fields (MappingProxyType)
   and cannot silently become policy signals.
9. Coverage contract discipline: Worker 02 `calculate_coverage()` counts evidence records,
   not named collector checks. `CoverageSummary.is_aggregate_complete()` validates aggregate
   record execution completeness only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


def _is_exact_int(val: Any) -> bool:
    """Check if value is strictly an int, excluding bools (which inherit from int)."""
    return isinstance(val, int) and not isinstance(val, bool)


def _is_exact_str(val: Any) -> bool:
    """Check if value is strictly a string."""
    return isinstance(val, str)


def _deep_freeze_value(val: Any) -> Any:
    """Recursively freeze mappings into MappingProxyType and sequences into tuples."""
    if isinstance(val, Mapping):
        return MappingProxyType({k: _deep_freeze_value(v) for k, v in val.items()})
    if isinstance(val, (list, tuple)) and not isinstance(val, (str, bytes)):
        return tuple(_deep_freeze_value(v) for v in val)
    return val


@dataclass(frozen=True)
class ParseIssue:
    """Structured representation of a validation or parsing issue."""

    path: str
    message: str
    invalid_value: Any = None


class PolicyInputParseError(ValueError):
    """Raised when canonical input fails strict parsing/validation."""

    def __init__(self, message: str, issues: Sequence[ParseIssue]):
        super().__init__(message)
        self.issues: Tuple[ParseIssue, ...] = tuple(issues)

    def __str__(self) -> str:
        base = super().__str__()
        if not self.issues:
            return base
        details = "\n  - ".join(f"[{i.path}] {i.message} (got: {repr(i.invalid_value)})" for i in self.issues)
        return f"{base}\nValidation issues ({len(self.issues)}):\n  - {details}"


@dataclass(frozen=True)
class EvidenceItem:
    """Canonical representation of an evidence item parsed from Worker 02 output.

    Attributes:
        evidence_id: Unique identifier of the evidence item.
        kind: Evidence category/kind (e.g. 'tls_cert', 'dns_resolution', 'threat_intelligence').
        source: Collector or feed identifier.
        observed_at: ISO-8601 observation timestamp string.
        status: Collection status ('observed', 'failed', 'unavailable', 'blocked', 'not_run').
        reliability: Assessed source reliability string.
        value: Extracted payload/evidence observation value (deeply frozen).
        limitations: Sequence of stated limitations or warnings.
        unparsed_fields: Read-only mapping of preserved extra/unknown fields.
    """

    evidence_id: str
    kind: str
    source: str
    observed_at: str
    status: str
    reliability: str
    value: Any
    limitations: Tuple[str, ...] = field(default_factory=tuple)
    unparsed_fields: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        path_prefix: str = "evidence",
        strict: bool = True,
    ) -> Tuple[Optional[EvidenceItem], List[ParseIssue]]:
        """Parse an evidence dictionary into an EvidenceItem."""
        if not isinstance(data, Mapping):
            issue = ParseIssue(path=path_prefix, message="Evidence item must be a mapping", invalid_value=data)
            if strict:
                raise PolicyInputParseError("Invalid evidence item mapping", [issue])
            return None, [issue]

        issues: List[ParseIssue] = []

        ev_id = data.get("evidence_id")
        if ev_id is None or not _is_exact_str(ev_id):
            issues.append(ParseIssue(path=f"{path_prefix}.evidence_id", message="Missing or invalid string 'evidence_id'", invalid_value=ev_id))
        elif not ev_id.strip():
            issues.append(ParseIssue(path=f"{path_prefix}.evidence_id", message="Field 'evidence_id' cannot be blank", invalid_value=ev_id))

        kind = data.get("kind")
        if kind is None or not _is_exact_str(kind):
            issues.append(ParseIssue(path=f"{path_prefix}.kind", message="Missing or invalid string 'kind'", invalid_value=kind))
        elif not kind.strip():
            issues.append(ParseIssue(path=f"{path_prefix}.kind", message="Field 'kind' cannot be blank", invalid_value=kind))

        source = data.get("source")
        if source is None or not _is_exact_str(source):
            issues.append(ParseIssue(path=f"{path_prefix}.source", message="Missing or invalid string 'source'", invalid_value=source))
        elif not source.strip():
            issues.append(ParseIssue(path=f"{path_prefix}.source", message="Field 'source' cannot be blank", invalid_value=source))

        observed_at = data.get("observed_at")
        if observed_at is None or not _is_exact_str(observed_at):
            issues.append(ParseIssue(path=f"{path_prefix}.observed_at", message="Missing or invalid string 'observed_at'", invalid_value=observed_at))
        elif not observed_at.strip():
            issues.append(ParseIssue(path=f"{path_prefix}.observed_at", message="Field 'observed_at' cannot be blank", invalid_value=observed_at))

        status = data.get("status")
        if status is None or not _is_exact_str(status):
            issues.append(ParseIssue(path=f"{path_prefix}.status", message="Missing or invalid string 'status'", invalid_value=status))
        elif not status.strip():
            issues.append(ParseIssue(path=f"{path_prefix}.status", message="Field 'status' cannot be blank", invalid_value=status))

        reliability = data.get("reliability")
        if reliability is None or not _is_exact_str(reliability):
            issues.append(ParseIssue(path=f"{path_prefix}.reliability", message="Missing or invalid string 'reliability'", invalid_value=reliability))
        elif not reliability.strip():
            issues.append(ParseIssue(path=f"{path_prefix}.reliability", message="Field 'reliability' cannot be blank", invalid_value=reliability))

        if "value" not in data:
            issues.append(ParseIssue(path=f"{path_prefix}.value", message="Missing required field 'value'"))

        limitations_raw = data.get("limitations")
        limitations_list: List[str] = []
        if limitations_raw is not None:
            if isinstance(limitations_raw, (str, bytes)) or not isinstance(limitations_raw, Sequence):
                issues.append(
                    ParseIssue(
                        path=f"{path_prefix}.limitations",
                        message="Field 'limitations' must be a sequence of strings, not a bare string or non-sequence",
                        invalid_value=limitations_raw,
                    )
                )
            else:
                for l_idx, lim in enumerate(limitations_raw):
                    if not _is_exact_str(lim):
                        issues.append(ParseIssue(path=f"{path_prefix}.limitations[{l_idx}]", message="Limitation item must be a string", invalid_value=lim))
                    elif not lim.strip():
                        issues.append(ParseIssue(path=f"{path_prefix}.limitations[{l_idx}]", message="Limitation item cannot be blank", invalid_value=lim))
                    else:
                        limitations_list.append(lim)

        if issues:
            if strict:
                raise PolicyInputParseError(f"Evidence item at '{path_prefix}' has {len(issues)} validation issues", issues)
            return None, issues

        known_keys = {"evidence_id", "kind", "source", "observed_at", "status", "reliability", "value", "limitations"}
        unparsed = {k: _deep_freeze_value(v) for k, v in data.items() if k not in known_keys}

        item = cls(
            evidence_id=ev_id,  # type: ignore[arg-type]
            kind=kind,          # type: ignore[arg-type]
            source=source,      # type: ignore[arg-type]
            observed_at=observed_at,  # type: ignore[arg-type]
            status=status,      # type: ignore[arg-type]
            reliability=reliability,  # type: ignore[arg-type]
            value=_deep_freeze_value(data["value"]),
            limitations=tuple(limitations_list),
            unparsed_fields=MappingProxyType(unparsed),
        )
        return item, []


@dataclass(frozen=True)
class CoverageSummary:
    """Aggregate coverage summary parsed from Worker 02 evidence output.

    Attributes:
        checks_total: Total number of expected or registered evidence checks.
        checks_observed: Total number of successfully observed evidence checks.
        checks_failed: Total number of failed evidence checks.
        checks_not_run: Total number of checks not run, unavailable, or blocked.
        scan_profile: Declared scan profile string (e.g. 'full', 'quick', 'custom'), or None.
        unparsed_fields: Read-only mapping of preserved extra/unknown fields.
    """

    checks_total: int
    checks_observed: int
    checks_failed: int
    checks_not_run: int
    scan_profile: Optional[str] = None
    unparsed_fields: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def is_aggregate_complete(self) -> bool:
        """Evaluate aggregate numerical completeness of the evidence collection.

        Returns True ONLY if:
        1. checks_total is strictly positive (> 0),
        2. checks_observed equals checks_total,
        3. checks_failed is exactly 0,
        4. checks_not_run is exactly 0.
        """
        return (
            self.checks_total > 0
            and self.checks_failed == 0
            and self.checks_not_run == 0
            and self.checks_observed == self.checks_total
        )

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        path_prefix: str = "coverage",
        strict: bool = True,
    ) -> Tuple[Optional[CoverageSummary], List[ParseIssue]]:
        """Parse coverage summary dictionary with strict type and arithmetic checks."""
        if not isinstance(data, Mapping):
            issue = ParseIssue(path=path_prefix, message="Coverage summary must be a mapping", invalid_value=data)
            if strict:
                raise PolicyInputParseError("Invalid coverage summary mapping", [issue])
            return None, [issue]

        issues: List[ParseIssue] = []

        c_total = data.get("checks_total")
        if c_total is None or not _is_exact_int(c_total):
            issues.append(ParseIssue(path=f"{path_prefix}.checks_total", message="Field 'checks_total' must be an integer (booleans rejected)", invalid_value=c_total))

        c_obs = data.get("checks_observed")
        if c_obs is None or not _is_exact_int(c_obs):
            issues.append(ParseIssue(path=f"{path_prefix}.checks_observed", message="Field 'checks_observed' must be an integer (booleans rejected)", invalid_value=c_obs))

        c_failed = data.get("checks_failed")
        if c_failed is None or not _is_exact_int(c_failed):
            issues.append(ParseIssue(path=f"{path_prefix}.checks_failed", message="Field 'checks_failed' must be an integer (booleans rejected)", invalid_value=c_failed))

        c_not_run = data.get("checks_not_run")
        if c_not_run is None or not _is_exact_int(c_not_run):
            issues.append(ParseIssue(path=f"{path_prefix}.checks_not_run", message="Field 'checks_not_run' must be an integer (booleans rejected)", invalid_value=c_not_run))

        c_profile = data.get("scan_profile")
        if c_profile is not None and not _is_exact_str(c_profile):
            issues.append(ParseIssue(path=f"{path_prefix}.scan_profile", message="Field 'scan_profile' must be a string", invalid_value=c_profile))

        # Arithmetic cross-validation
        if not issues:
            assert isinstance(c_total, int) and isinstance(c_obs, int) and isinstance(c_failed, int) and isinstance(c_not_run, int)
            if c_total < 0 or c_obs < 0 or c_failed < 0 or c_not_run < 0:
                issues.append(ParseIssue(path=path_prefix, message="Coverage check counts cannot be negative"))
            elif (c_obs + c_failed + c_not_run) != c_total:
                issues.append(
                    ParseIssue(
                        path=path_prefix,
                        message=(
                            f"Coverage arithmetic mismatch: checks_observed ({c_obs}) + "
                            f"checks_failed ({c_failed}) + checks_not_run ({c_not_run}) "
                            f"!= checks_total ({c_total})"
                        ),
                    )
                )

        if issues:
            if strict:
                raise PolicyInputParseError(f"Coverage summary at '{path_prefix}' has {len(issues)} validation issues", issues)
            return None, issues

        known_keys = {"checks_total", "checks_observed", "checks_failed", "checks_not_run", "scan_profile"}
        unparsed = {k: _deep_freeze_value(v) for k, v in data.items() if k not in known_keys}

        summary = cls(
            checks_total=c_total,       # type: ignore[arg-type]
            checks_observed=c_obs,     # type: ignore[arg-type]
            checks_failed=c_failed,     # type: ignore[arg-type]
            checks_not_run=c_not_run,   # type: ignore[arg-type]
            scan_profile=c_profile,
            unparsed_fields=MappingProxyType(unparsed),
        )
        return summary, []


@dataclass(frozen=True)
class CommunityReportItem:
    """Canonical representation of an external community report item.

    Attributes:
        report_id: Unique identifier of the report.
        normalized_domain: Target domain normalized for matching.
        claim_type: Stated claim type (e.g. 'phishing', 'malware', 'benign').
        verification_state: Verification status ('verified', 'unverified', 'rejected', 'disputed').
        independent_source_count: Count of distinct independent corroborating sources.
        linked_evidence_ids: Identifiers of linked evidence items.
        submitted_at: ISO-8601 submission timestamp string.
        unparsed_fields: Read-only mapping of preserved extra/unknown fields.
    """

    report_id: str
    normalized_domain: str
    claim_type: str
    verification_state: str
    independent_source_count: int
    linked_evidence_ids: Tuple[str, ...] = field(default_factory=tuple)
    submitted_at: Optional[str] = None
    unparsed_fields: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        path_prefix: str = "community_reports",
        strict: bool = True,
    ) -> Tuple[Optional[CommunityReportItem], List[ParseIssue]]:
        """Parse community report dictionary with strict type checking."""
        if not isinstance(data, Mapping):
            issue = ParseIssue(path=path_prefix, message="Community report item must be a mapping", invalid_value=data)
            if strict:
                raise PolicyInputParseError("Invalid community report mapping", [issue])
            return None, [issue]

        issues: List[ParseIssue] = []

        rep_id = data.get("report_id")
        if rep_id is None or not _is_exact_str(rep_id):
            issues.append(ParseIssue(path=f"{path_prefix}.report_id", message="Missing or invalid string 'report_id'", invalid_value=rep_id))
        elif not rep_id.strip():
            issues.append(ParseIssue(path=f"{path_prefix}.report_id", message="Field 'report_id' cannot be blank", invalid_value=rep_id))

        domain = data.get("normalized_domain")
        if domain is None or not _is_exact_str(domain):
            issues.append(ParseIssue(path=f"{path_prefix}.normalized_domain", message="Missing or invalid string 'normalized_domain'", invalid_value=domain))
        elif not domain.strip():
            issues.append(ParseIssue(path=f"{path_prefix}.normalized_domain", message="Field 'normalized_domain' cannot be blank", invalid_value=domain))

        claim = data.get("claim_type")
        if claim is None or not _is_exact_str(claim):
            issues.append(ParseIssue(path=f"{path_prefix}.claim_type", message="Missing or invalid string 'claim_type'", invalid_value=claim))
        elif not claim.strip():
            issues.append(ParseIssue(path=f"{path_prefix}.claim_type", message="Field 'claim_type' cannot be blank", invalid_value=claim))

        v_state = data.get("verification_state")
        if v_state is None or not _is_exact_str(v_state):
            issues.append(ParseIssue(path=f"{path_prefix}.verification_state", message="Missing or invalid string 'verification_state'", invalid_value=v_state))
        elif not v_state.strip():
            issues.append(ParseIssue(path=f"{path_prefix}.verification_state", message="Field 'verification_state' cannot be blank", invalid_value=v_state))

        src_cnt = data.get("independent_source_count")
        if src_cnt is None or not _is_exact_int(src_cnt):
            issues.append(ParseIssue(path=f"{path_prefix}.independent_source_count", message="Missing or invalid integer 'independent_source_count' (booleans rejected)", invalid_value=src_cnt))
        elif src_cnt < 0:
            issues.append(ParseIssue(path=f"{path_prefix}.independent_source_count", message="independent_source_count cannot be negative", invalid_value=src_cnt))

        linked_raw = data.get("linked_evidence_ids")
        linked_list: List[str] = []
        if linked_raw is not None:
            if isinstance(linked_raw, (str, bytes)) or not isinstance(linked_raw, Sequence):
                issues.append(
                    ParseIssue(
                        path=f"{path_prefix}.linked_evidence_ids",
                        message="Field 'linked_evidence_ids' must be a sequence of strings, not a bare string or non-sequence",
                        invalid_value=linked_raw,
                    )
                )
            else:
                for l_idx, lid in enumerate(linked_raw):
                    if not _is_exact_str(lid):
                        issues.append(ParseIssue(path=f"{path_prefix}.linked_evidence_ids[{l_idx}]", message="Linked evidence ID must be a string", invalid_value=lid))
                    elif not lid.strip():
                        issues.append(ParseIssue(path=f"{path_prefix}.linked_evidence_ids[{l_idx}]", message="Linked evidence ID cannot be blank", invalid_value=lid))
                    else:
                        linked_list.append(lid)

        sub_at = data.get("submitted_at")
        if sub_at is not None and not _is_exact_str(sub_at):
            issues.append(ParseIssue(path=f"{path_prefix}.submitted_at", message="Field 'submitted_at' must be a string", invalid_value=sub_at))

        if issues:
            if strict:
                raise PolicyInputParseError(f"Community report at '{path_prefix}' has {len(issues)} validation issues", issues)
            return None, issues

        known_keys = {"report_id", "normalized_domain", "claim_type", "verification_state", "independent_source_count", "linked_evidence_ids", "submitted_at"}
        unparsed = {k: _deep_freeze_value(v) for k, v in data.items() if k not in known_keys}

        item = cls(
            report_id=rep_id,  # type: ignore[arg-type]
            normalized_domain=domain,  # type: ignore[arg-type]
            claim_type=claim,  # type: ignore[arg-type]
            verification_state=v_state,  # type: ignore[arg-type]
            independent_source_count=src_cnt,  # type: ignore[arg-type]
            linked_evidence_ids=tuple(linked_list),
            submitted_at=sub_at,
            unparsed_fields=MappingProxyType(unparsed),
        )
        return item, []


@dataclass(frozen=True)
class PolicyInput:
    """Root canonical DTO representing all evidence and inputs provided to Worker 03.

    Attributes:
        scan_id: Scanned run or job identifier.
        target: Target domain or hostname being evaluated.
        scan_profile: Declared scan profile (e.g. 'standard', 'fixture', 'full').
        evidence: Tuple of validated EvidenceItem instances.
        coverage: Optional CoverageSummary instance.
        community_reports: Tuple of validated CommunityReportItem instances.
        parse_issues: Tuple of ParseIssue instances recorded when parsed with strict=False.
        unparsed_fields: Read-only mapping of preserved extra/unknown top-level fields.
    """

    scan_id: str
    target: str
    scan_profile: str
    evidence: Tuple[EvidenceItem, ...] = field(default_factory=tuple)
    coverage: Optional[CoverageSummary] = None
    community_reports: Tuple[CommunityReportItem, ...] = field(default_factory=tuple)
    parse_issues: Tuple[ParseIssue, ...] = field(default_factory=tuple)
    unparsed_fields: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def is_valid(self) -> bool:
        """Return True only if this PolicyInput has zero parse issues and non-empty target."""
        return len(self.parse_issues) == 0 and bool(self.target and self.target.strip())

    @classmethod
    def from_v1_dict(
        cls,
        data: Mapping[str, Any],
        strict: bool = True,
    ) -> PolicyInput:
        """Parse canonical v1 dictionary into strongly-typed, immutable PolicyInput."""
        if not isinstance(data, Mapping):
            issue = ParseIssue(path="$", message="Top-level input must be a mapping", invalid_value=data)
            if strict:
                raise PolicyInputParseError("Top-level input must be a mapping", [issue])
            return cls(
                scan_id="",
                target="",
                scan_profile="",
                parse_issues=(issue,),
            )

        issues: List[ParseIssue] = []

        # --- scan_id ---
        scan_id = data.get("scan_id")
        if scan_id is None:
            issues.append(ParseIssue(path="scan_id", message="Missing required field 'scan_id'"))
            scan_id_val = ""
        elif not _is_exact_str(scan_id):
            issues.append(ParseIssue(path="scan_id", message="Field 'scan_id' must be a string", invalid_value=scan_id))
            scan_id_val = ""
        elif not scan_id.strip():
            issues.append(ParseIssue(path="scan_id", message="Field 'scan_id' cannot be blank", invalid_value=scan_id))
            scan_id_val = ""
        else:
            scan_id_val = scan_id

        # --- target resolution (accept 'target' or 'normalized_host') ---
        target = data.get("target")
        if target is None:
            target = data.get("normalized_host")

        if target is None:
            issues.append(ParseIssue(path="target", message="Missing required field 'target' (or 'normalized_host')"))
            target_val = ""
        elif not _is_exact_str(target):
            issues.append(ParseIssue(path="target", message="Field 'target' / 'normalized_host' must be a string", invalid_value=target))
            target_val = ""
        elif not target.strip():
            issues.append(ParseIssue(path="target", message="Target domain/host cannot be blank", invalid_value=target))
            target_val = ""
        else:
            target_val = target

        # --- scan_profile (accept 'scan_profile', 'profile', or coverage.scan_profile; default 'standard') ---
        scan_profile = data.get("scan_profile")
        if scan_profile is None:
            scan_profile = data.get("profile")
        if scan_profile is None and isinstance(data.get("coverage"), Mapping):
            scan_profile = data["coverage"].get("scan_profile")

        if scan_profile is None:
            scan_profile_val = "standard"
        elif not _is_exact_str(scan_profile):
            issues.append(ParseIssue(path="scan_profile", message="Field 'scan_profile' must be a string", invalid_value=scan_profile))
            scan_profile_val = ""
        elif not scan_profile.strip():
            issues.append(ParseIssue(path="scan_profile", message="Field 'scan_profile' cannot be blank", invalid_value=scan_profile))
            scan_profile_val = ""
        else:
            scan_profile_val = scan_profile

        # --- Preserved top-level unknown fields ---
        known_top_keys = {
            "scan_id",
            "target",
            "normalized_host",
            "scan_profile",
            "profile",
            "evidence",
            "coverage",
            "community_reports",
        }
        top_unparsed = {k: _deep_freeze_value(v) for k, v in data.items() if k not in known_top_keys}

        # --- Evidence Parsing ---
        evidence_items: List[EvidenceItem] = []
        raw_evidence = data.get("evidence")
        if raw_evidence is not None:
            if isinstance(raw_evidence, (str, bytes)) or not isinstance(raw_evidence, Sequence):
                issues.append(ParseIssue(path="evidence", message="Field 'evidence' must be a list/sequence", invalid_value=raw_evidence))
            else:
                for idx, item in enumerate(raw_evidence):
                    item_path = f"evidence[{idx}]"
                    ev_item, ev_issues = EvidenceItem.from_dict(item, path_prefix=item_path, strict=False)
                    if ev_issues:
                        issues.extend(ev_issues)
                    elif ev_item is not None:
                        evidence_items.append(ev_item)

        # --- Coverage Parsing ---
        coverage_summary: Optional[CoverageSummary] = None
        raw_coverage = data.get("coverage")
        if raw_coverage is not None:
            cov_summary, cov_issues = CoverageSummary.from_dict(raw_coverage, path_prefix="coverage", strict=False)
            if cov_issues:
                issues.extend(cov_issues)
            else:
                coverage_summary = cov_summary

        # --- Community Reports Parsing ---
        community_items: List[CommunityReportItem] = []
        raw_reports = data.get("community_reports")
        if raw_reports is not None:
            if isinstance(raw_reports, (str, bytes)) or not isinstance(raw_reports, Sequence):
                issues.append(ParseIssue(path="community_reports", message="Field 'community_reports' must be a list/sequence", invalid_value=raw_reports))
            else:
                for idx, rep in enumerate(raw_reports):
                    rep_path = f"community_reports[{idx}]"
                    comm_item, comm_issues = CommunityReportItem.from_dict(rep, path_prefix=rep_path, strict=False)
                    if comm_issues:
                        issues.extend(comm_issues)
                    elif comm_item is not None:
                        community_items.append(comm_item)

        if strict and issues:
            raise PolicyInputParseError(f"Failed to parse policy input ({len(issues)} issues found)", issues)

        return cls(
            scan_id=scan_id_val,
            target=target_val,
            scan_profile=scan_profile_val,
            evidence=tuple(evidence_items),
            coverage=coverage_summary,
            community_reports=tuple(community_items),
            parse_issues=tuple(issues),
            unparsed_fields=MappingProxyType(top_unparsed),
        )
