"""TRUSTTRACE Multimodal Availability Masking & Missing-Modality Fusion.

Implements Sections 9.1-9.4 of the TRUSTTRACE ML Research & Engineering Handbook:
- Robust target URL/scheme parsing with https default for bare domains.
- 4-stage exact evidence modality classifier (DNS, TLS, Threat Intel, Community).
- Deterministic 32-subset status aggregation preserving partial coverage and limitations.
- MultimodalAvailabilityMask with derived convenience properties.
- Availability gate enforcing non-bypassable safety invariants for clean claims
  while preserving positive threat indicators against unrelated collection failures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
import urllib.parse

from trusttrace.policy.diagnostics import DiagnosticCode
from trusttrace.policy.uncertainty import FreshnessPolicy


class ModalityKind(str, Enum):
    """Canonical evidence modalities evaluated in policy fusion."""

    DNS = "dns"
    TLS = "tls"
    THREAT_INTEL = "threat_intel"
    COMMUNITY = "community"
    UNKNOWN = "unknown"


class ModalityStatus(str, Enum):
    """Aggregated availability status for a single evidence modality."""

    OBSERVED_COMPLETE = "observed_complete"
    OBSERVED_PARTIAL = "observed_partial"
    BLOCKED = "blocked"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    NOT_RUN = "not_run"
    MISSING = "missing"


@dataclass
class ModalityProfile:
    """Detailed availability profile for a single modality."""

    kind: ModalityKind
    status: ModalityStatus
    primary_status: str  # "observed" | "blocked" | "failed" | "unavailable" | "not_run"
    evidence_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    observed_count: int = 0
    has_warnings: bool = False
    raw_statuses: List[str] = field(default_factory=list)
    stale_evidence_ids: List[str] = field(default_factory=list)


@dataclass
class ModalityAvailabilityMask:
    """Multimodal availability representation preserving full structural telemetry.

    Derives boolean convenience flags without discarding rich partial coverage.
    """

    modalities: Dict[ModalityKind, ModalityProfile]
    unmapped_records: List[Dict[str, Any]] = field(default_factory=list)
    target_scheme: Optional[str] = None
    target_hostname: Optional[str] = None
    target_port: Optional[int] = None
    is_target_valid: bool = True

    @property
    def dns_available(self) -> bool:
        prof = self.modalities.get(ModalityKind.DNS)
        return prof is not None and prof.status in (
            ModalityStatus.OBSERVED_COMPLETE,
            ModalityStatus.OBSERVED_PARTIAL,
        )

    @property
    def tls_available(self) -> bool:
        prof = self.modalities.get(ModalityKind.TLS)
        return prof is not None and prof.status in (
            ModalityStatus.OBSERVED_COMPLETE,
            ModalityStatus.OBSERVED_PARTIAL,
        )

    @property
    def threat_intel_available(self) -> bool:
        prof = self.modalities.get(ModalityKind.THREAT_INTEL)
        return prof is not None and prof.status in (
            ModalityStatus.OBSERVED_COMPLETE,
            ModalityStatus.OBSERVED_PARTIAL,
        )

    @property
    def community_available(self) -> bool:
        prof = self.modalities.get(ModalityKind.COMMUNITY)
        return prof is not None and prof.status in (
            ModalityStatus.OBSERVED_COMPLETE,
            ModalityStatus.OBSERVED_PARTIAL,
        )

    @property
    def is_tls_applicable(self) -> bool:
        """TLS is mandatory for HTTPS targets, but non-applicable for plain HTTP."""
        return self.target_scheme == "https"

    @property
    def availability_vector(self) -> Dict[str, bool]:
        """Convenience derived boolean availability vector."""
        return {
            "dns": self.dns_available,
            "tls": self.tls_available,
            "threat_intel": self.threat_intel_available,
            "community": self.community_available,
        }


def parse_and_validate_target(
    raw_target: str,
) -> Tuple[Optional[str], Optional[str], Optional[int], bool]:
    """Parse and conservatively validate scan target using urllib.parse.urlsplit.

    Rules:
    - Rejects empty, whitespace-only, or non-string targets.
    - Bare domains default to scheme='https' per Section 9.2 of the Handbook.
    - Explicit 'http://' makes TLS non-applicable.
    - Explicit 'https://' mandates TLS evaluation regardless of port.
    - Unsupported schemes (e.g. ftp://, ws://) or empty hostnames fail validation.
    - Malformed IPv6 brackets or colon formats fail validation.

    Returns:
        (scheme, hostname, port, is_valid)
    """
    if not raw_target or not isinstance(raw_target, str) or not raw_target.strip():
        return None, None, None, False

    target = raw_target.strip()

    if "://" not in target:
        parse_target = f"https://{target}"
    else:
        parse_target = target

    try:
        parsed = urllib.parse.urlsplit(parse_target)
    except Exception:
        return None, None, None, False

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None, None, None, False

    hostname = parsed.hostname
    if not hostname or len(hostname.strip()) == 0:
        return None, None, None, False

    # Catch malformed IPv6 brackets
    if hostname.startswith("[") and not hostname.endswith("]"):
        return None, None, None, False

    port = parsed.port
    return scheme, hostname.lower(), port, True


# ─────────────────────────────────────────────────────────────────────────────
# 4-Stage Exact Modality Classifier
# ─────────────────────────────────────────────────────────────────────────────

EXACT_KIND_MAP: Dict[str, ModalityKind] = {
    # DNS Modality
    "dns_resolution": ModalityKind.DNS,
    "dns_record": ModalityKind.DNS,
    "dns_records": ModalityKind.DNS,
    "dns_sec": ModalityKind.DNS,
    # TLS Modality
    "tls_handshake": ModalityKind.TLS,
    "tls_certificate": ModalityKind.TLS,
    "tls_cert": ModalityKind.TLS,
    "tls_hostname_validation": ModalityKind.TLS,
    "x509_certificate": ModalityKind.TLS,
    "ssl_handshake": ModalityKind.TLS,
    # Threat Intelligence Modality
    "threat_intel": ModalityKind.THREAT_INTEL,
    "threat_intelligence": ModalityKind.THREAT_INTEL,
    "threat_indicator": ModalityKind.THREAT_INTEL,
    "threat_feed": ModalityKind.THREAT_INTEL,
    "domain_reputation": ModalityKind.THREAT_INTEL,
    "url_reputation": ModalityKind.THREAT_INTEL,
    "ip_reputation": ModalityKind.THREAT_INTEL,
    "blocklist_entry": ModalityKind.THREAT_INTEL,
    # Community Modality
    "community_report": ModalityKind.COMMUNITY,
    "community_vote": ModalityKind.COMMUNITY,
    "user_feedback": ModalityKind.COMMUNITY,
    "crowdsourced_score": ModalityKind.COMMUNITY,
}

EXACT_SOURCE_MAP: Dict[str, ModalityKind] = {
    # DNS Collectors
    "dns_collector": ModalityKind.DNS,
    "system_dns": ModalityKind.DNS,
    "google_dns": ModalityKind.DNS,
    "cloudflare_dns": ModalityKind.DNS,
    # TLS Collectors (fixture_adapter deliberately excluded to prevent misclassification)
    "tls_collector": ModalityKind.TLS,
    "ssl_scanner": ModalityKind.TLS,
    "crypto_validator": ModalityKind.TLS,
    # Threat Intelligence Adapters
    "threat_collector": ModalityKind.THREAT_INTEL,
    "alienvault_otx": ModalityKind.THREAT_INTEL,
    "virustotal": ModalityKind.THREAT_INTEL,
    "urlhaus": ModalityKind.THREAT_INTEL,
    "phish_feed_alpha": ModalityKind.THREAT_INTEL,
    "reputable_feed": ModalityKind.THREAT_INTEL,
    # Community Adapters
    "community_service": ModalityKind.COMMUNITY,
    "community_reporter": ModalityKind.COMMUNITY,
}

KIND_PREFIX_MAP: Tuple[Tuple[str, ModalityKind], ...] = (
    ("dns_", ModalityKind.DNS),
    ("tls_", ModalityKind.TLS),
    ("ssl_", ModalityKind.TLS),
    ("cert_", ModalityKind.TLS),
    ("threat_", ModalityKind.THREAT_INTEL),
    ("reputation_", ModalityKind.THREAT_INTEL),
    ("community_", ModalityKind.COMMUNITY),
)


class ModalityClassifier:
    """Four-stage classifier for evidence records."""

    @classmethod
    def classify(cls, kind: Optional[str], source: Optional[str]) -> ModalityKind:
        clean_kind = (kind or "").strip().lower()
        clean_source = (source or "").strip().lower()

        # Stage 1: Exact kind match
        if clean_kind in EXACT_KIND_MAP:
            return EXACT_KIND_MAP[clean_kind]

        # Stage 2: Exact source match (for generic kinds)
        if clean_source in EXACT_SOURCE_MAP:
            return EXACT_SOURCE_MAP[clean_source]

        # Stage 3: Controlled prefix match
        for prefix, modality in KIND_PREFIX_MAP:
            if clean_kind.startswith(prefix):
                return modality

        # Stage 4: Unknown modality
        return ModalityKind.UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# 32-Subset Deterministic Status Aggregation & Gate
# ─────────────────────────────────────────────────────────────────────────────

STATUS_PRECEDENCE = {
    "observed": 5,
    "blocked": 4,
    "failed": 3,
    "unavailable": 2,
    "not_run": 1,
}


@dataclass
class GateResult:
    """Outcome of ModalityAvailabilityGate evaluation."""

    should_bypass: bool
    requires_inconclusive: bool
    reason: str
    diagnostics: List[DiagnosticCode] = field(default_factory=list)


class ModalityAvailabilityGate:
    """Aggregates evidence statuses and enforces multimodal gating."""

    @classmethod
    def aggregate_status(
        cls, raw_statuses: Iterable[str], has_warnings: bool = False
    ) -> Tuple[ModalityStatus, str]:
        """Map any subset of the 5 canonical statuses to deterministic ModalityStatus.

        Truth-table closed form across all 2^5 = 32 subsets:
        - If 'observed' is present:
            - If pure {'observed'} and has_warnings is False -> (OBSERVED_COMPLETE, "observed")
            - If pure {'observed'} and has_warnings is True -> (OBSERVED_PARTIAL, "observed")
            - If mixed ('observed' + any failure/blocked/unrun) -> (OBSERVED_PARTIAL, "observed")
        - If 'observed' is absent:
            - 'blocked' in set -> (BLOCKED, "blocked")
            - 'failed' in set -> (FAILED, "failed")
            - 'unavailable' in set -> (UNAVAILABLE, "unavailable")
            - set == {'not_run'} -> (NOT_RUN, "not_run")
            - set is empty -> (MISSING, "not_run")
        """
        status_set: Set[str] = {
            s.strip().lower() for s in raw_statuses if s and isinstance(s, str)
        }

        if not status_set:
            return ModalityStatus.MISSING, "not_run"

        if "observed" in status_set:
            if status_set == {"observed"} and not has_warnings:
                return ModalityStatus.OBSERVED_COMPLETE, "observed"
            return ModalityStatus.OBSERVED_PARTIAL, "observed"

        if "blocked" in status_set:
            return ModalityStatus.BLOCKED, "blocked"

        if "failed" in status_set:
            return ModalityStatus.FAILED, "failed"

        if "unavailable" in status_set:
            return ModalityStatus.UNAVAILABLE, "unavailable"

        if status_set == {"not_run"}:
            return ModalityStatus.NOT_RUN, "not_run"

        # Safe fallback for unexpected statuses
        return ModalityStatus.UNAVAILABLE, "unavailable"

    @classmethod
    def build_mask(
        cls,
        evidence_items: Sequence[Any],
        target: str,
        community_reports: Sequence[Any] = (),
    ) -> ModalityAvailabilityMask:
        """Construct full ModalityAvailabilityMask from raw evidence records."""
        scheme, hostname, port, is_valid = parse_and_validate_target(target)

        records_by_modality: Dict[ModalityKind, List[Dict[str, Any]]] = {
            k: [] for k in ModalityKind
        }
        unmapped_records: List[Dict[str, Any]] = []

        # Process evidence items
        for item in evidence_items:
            eid = getattr(item, "evidence_id", None) or (
                item.get("evidence_id") if isinstance(item, dict) else ""
            )
            kind = getattr(item, "kind", None) or (
                item.get("kind") if isinstance(item, dict) else ""
            )
            source = getattr(item, "source", None) or (
                item.get("source") if isinstance(item, dict) else ""
            )
            status = getattr(item, "status", None) or (
                item.get("status") if isinstance(item, dict) else "observed"
            )
            limitations = list(
                getattr(item, "limitations", ())
                or (item.get("limitations") if isinstance(item, dict) else ())
                or []
            )
            val = getattr(item, "value", None) or (
                item.get("value") if isinstance(item, dict) else {}
            )
            observed_at = getattr(item, "observed_at", None) or (
                item.get("observed_at") if isinstance(item, dict) else ""
            )

            modality = ModalityClassifier.classify(kind, source)
            record_info = {
                "evidence_id": eid,
                "kind": kind,
                "source": source,
                "status": status,
                "limitations": limitations,
                "value": val,
                "observed_at": observed_at,
            }

            records_by_modality[modality].append(record_info)
            if modality == ModalityKind.UNKNOWN:
                unmapped_records.append(record_info)

        # Process community reports into COMMUNITY modality
        for report in community_reports:
            rid = getattr(report, "report_id", None) or (
                report.get("report_id") if isinstance(report, dict) else ""
            )
            records_by_modality[ModalityKind.COMMUNITY].append(
                {
                    "evidence_id": rid,
                    "kind": "community_report",
                    "source": "community",
                    "status": "observed",
                    "limitations": [],
                    "value": {},
                    "observed_at": "",
                }
            )

        modalities: Dict[ModalityKind, ModalityProfile] = {}
        freshness_policy = FreshnessPolicy()

        for mod in (
            ModalityKind.DNS,
            ModalityKind.TLS,
            ModalityKind.THREAT_INTEL,
            ModalityKind.COMMUNITY,
        ):
            records = records_by_modality[mod]
            raw_statuses = [r["status"] for r in records]
            ev_ids = [r["evidence_id"] for r in records if r["evidence_id"]]
            src_ids = sorted(list({r["source"] for r in records if r["source"]}))
            lims: List[str] = []
            for r in records:
                lims.extend(r["limitations"])

            # Detect technical degradation warnings & staleness
            has_warnings = False
            stale_ev_ids: List[str] = []
            for r in records:
                v = r.get("value")
                if isinstance(v, dict):
                    if v.get("is_expired") is True or v.get("hostname_match") is False:
                        has_warnings = True
                    if v.get("error") or v.get("warning"):
                        has_warnings = True

                # Staleness check via FreshnessPolicy
                obs_at = r.get("observed_at")
                if obs_at and r.get("status") == "observed":
                    is_stale, _, _ = freshness_policy.evaluate_freshness(
                        r.get("kind") or mod.value, obs_at
                    )
                    if is_stale:
                        has_warnings = True
                        if r.get("evidence_id"):
                            stale_ev_ids.append(r["evidence_id"])

            status, primary_status = cls.aggregate_status(raw_statuses, has_warnings=has_warnings)

            modalities[mod] = ModalityProfile(
                kind=mod,
                status=status,
                primary_status=primary_status,
                evidence_ids=ev_ids,
                source_ids=src_ids,
                limitations=lims,
                observed_count=len([s for s in raw_statuses if s == "observed"]),
                has_warnings=has_warnings,
                raw_statuses=raw_statuses,
                stale_evidence_ids=stale_ev_ids,
            )

        return ModalityAvailabilityMask(
            modalities=modalities,
            unmapped_records=unmapped_records,
            target_scheme=scheme,
            target_hostname=hostname,
            target_port=port,
            is_target_valid=is_valid,
        )

    @classmethod
    def evaluate_gate(
        cls,
        mask: ModalityAvailabilityMask,
        has_positive_threat: bool = False,
    ) -> GateResult:
        """Enforce modality gating rules before permitting clean or scoped verdicts.

        Safety Invariants:
        1. Positive Threat Preservation: If verified positive threat is present, bypass gate.
        2. Target Validation: If target is malformed/empty/unsupported, reject immediately with INPUT_PARSE_ERROR.
        3. Mandatory DNS: Must be OBSERVED_COMPLETE. Partial DNS with failures cannot permit clean baseline.
        4. Mandatory Threat Intel: Must be OBSERVED_COMPLETE (or OBSERVED_PARTIAL without positive threat).
        5. Scheme-Aware TLS: If HTTPS, TLS must be OBSERVED_COMPLETE. If plain HTTP, TLS is non-applicable.
        """
        # Rule 1 Invariant: Positive threat evidence overrides missing modalities
        if has_positive_threat:
            return GateResult(
                should_bypass=True,
                requires_inconclusive=False,
                reason="Positive threat signal verified; missing modalities bypassed.",
            )

        diags: List[DiagnosticCode] = []

        # Target Validation
        if not mask.is_target_valid:
            diags.append(DiagnosticCode.INPUT_PARSE_ERROR)
            return GateResult(
                should_bypass=False,
                requires_inconclusive=True,
                reason="Target URL or hostname is malformed or unsupported.",
                diagnostics=diags,
            )

        # Unknown Evidence Preservation Flag
        if mask.unmapped_records:
            diags.append(DiagnosticCode.UNSUPPORTED_EVIDENCE_KIND)

        dns_prof = mask.modalities.get(ModalityKind.DNS)
        ti_prof = mask.modalities.get(ModalityKind.THREAT_INTEL)
        tls_prof = mask.modalities.get(ModalityKind.TLS)

        # DNS Missing or Degraded
        if dns_prof is None or dns_prof.status in (
            ModalityStatus.MISSING,
            ModalityStatus.FAILED,
            ModalityStatus.BLOCKED,
            ModalityStatus.UNAVAILABLE,
        ):
            diags.append(DiagnosticCode.COVERAGE_DEFICIT)
            return GateResult(
                should_bypass=False,
                requires_inconclusive=True,
                reason=f"Mandatory DNS modality unavailable ({dns_prof.status.value if dns_prof else 'missing'}).",
                diagnostics=diags,
            )

        # Partial DNS: OBSERVED_PARTIAL with failures cannot establish clean baseline
        if dns_prof.status == ModalityStatus.OBSERVED_PARTIAL:
            if "failed" in dns_prof.raw_statuses or "unavailable" in dns_prof.raw_statuses:
                diags.append(DiagnosticCode.COVERAGE_DEFICIT)
                return GateResult(
                    should_bypass=False,
                    requires_inconclusive=True,
                    reason="DNS modality has partial collector failures; clean verdict prohibited.",
                    diagnostics=diags,
                )

        # Threat Intelligence Missing or Blocked/Failed
        if ti_prof is None or ti_prof.status in (
            ModalityStatus.MISSING,
            ModalityStatus.FAILED,
            ModalityStatus.BLOCKED,
            ModalityStatus.UNAVAILABLE,
        ):
            diags.append(DiagnosticCode.COVERAGE_DEFICIT)
            return GateResult(
                should_bypass=False,
                requires_inconclusive=True,
                reason=f"Mandatory Threat Intelligence modality unavailable ({ti_prof.status.value if ti_prof else 'missing'}).",
                diagnostics=diags,
            )

        # Stale Threat Intelligence check
        if ti_prof and ti_prof.stale_evidence_ids:
            diags.append(DiagnosticCode.STALE_EVIDENCE_FLAGGED)
            return GateResult(
                should_bypass=False,
                requires_inconclusive=True,
                reason="Threat Intelligence observation is stale; clean verdict prohibited.",
                diagnostics=diags,
            )

        # TLS Applicability for HTTPS
        if mask.is_tls_applicable:
            if tls_prof is None or tls_prof.status in (
                ModalityStatus.MISSING,
                ModalityStatus.FAILED,
                ModalityStatus.BLOCKED,
                ModalityStatus.UNAVAILABLE,
            ):
                diags.append(DiagnosticCode.COVERAGE_DEFICIT)
                return GateResult(
                    should_bypass=False,
                    requires_inconclusive=True,
                    reason=f"Mandatory TLS modality unavailable on HTTPS target ({tls_prof.status.value if tls_prof else 'missing'}).",
                    diagnostics=diags,
                )

        return GateResult(
            should_bypass=False,
            requires_inconclusive=False,
            reason="Multimodal availability gate passed.",
            diagnostics=diags,
        )
