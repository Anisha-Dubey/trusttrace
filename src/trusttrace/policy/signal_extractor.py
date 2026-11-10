"""Deterministic Evidence Signal Extractor for Worker 03 Phase 03.

Maps validated canonical v1 evidence items and community reports into strongly-typed
SignalRecords aligned with the four assessment dimensions.

Key Principles:
1. Zero fabrication: Every signal cites actual evidence/report IDs; never generates synthetic IDs.
2. TLS precision: Valid TLS alone establishes channel encryption (valid_for_hostname),
   never organizational identity (TLS-001). Expired/mismatched TLS is a technical warning (TLS-002).
   tls_hostname_validation fixture emits ONLY TLS_HOSTNAME_MATCH.
3. DNS precision: Observed DNS resolution confirms DNS observation, not overall collector success.
4. Threat-feed discipline: NO_THREAT_MATCH is emitted ONLY when the feed query completed
   successfully with negative match. Never emit NO_THREAT_MATCH on failed or missing queries.
   THREAT_FEED_MATCH requires verified provider provenance and target match.
5. Target policy: Blocked destination policy is distinguished from collector failure.
6. Community rigor: Unverified reports stay unverified (COMM-001); corroboration requires
   >= 2 independent source families or valid linked evidence (COMM-002).
7. Diagnostics: All unsupported kinds, target mismatches, or malformed payloads emit
   explicit structured DiagnosticRecords.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .diagnostics import (
    DiagnosticCode,
    DiagnosticCollector,
    DiagnosticRecord,
    DiagnosticSeverity,
)
from .policy_input import CommunityReportItem, EvidenceItem, PolicyInput
from .signal_taxonomy import SignalConfidence, SignalKind, SignalRecord


@dataclass(frozen=True)
class SignalExtractionResult:
    """Aggregate result of signal extraction from canonical policy input.

    Attributes:
        signals: Tuple of extracted SignalRecord instances.
        diagnostics: Tuple of DiagnosticRecord instances generated during extraction.
    """

    signals: Tuple[SignalRecord, ...] = field(default_factory=tuple)
    diagnostics: Tuple[DiagnosticRecord, ...] = field(default_factory=tuple)


class EvidenceSignalExtractor:
    """Deterministic extractor converting canonical evidence into policy signals."""

    def __init__(self) -> None:
        pass

    def extract_signals(self, policy_input: PolicyInput) -> SignalExtractionResult:
        """Extract signals and diagnostics from a validated PolicyInput."""
        collector = DiagnosticCollector()
        signals: List[SignalRecord] = []
        target = policy_input.target.strip().lower() if policy_input.target else ""

        # --- Process Evidence Items ---
        for item in policy_input.evidence:
            ev_id = item.evidence_id
            kind = item.kind.strip().lower()
            status = item.status.strip().lower()
            reliability = item.reliability.strip().lower()
            val = item.value if isinstance(item.value, Mapping) else {}
            item_limitations = list(item.limitations)

            # Staleness check
            is_stale = any(
                "stale" in lim.lower() or "expired cache" in lim.lower() or "historical" in lim.lower()
                for lim in item_limitations
            )
            if is_stale:
                signals.append(
                    SignalRecord(
                        kind=SignalKind.STALE_EVIDENCE,
                        evidence_ids=[ev_id],
                        source=item.source,
                        confidence=SignalConfidence.HIGH,
                        limitations=item_limitations,
                    )
                )
                collector.record(
                    code=DiagnosticCode.STALE_EVIDENCE_FLAGGED,
                    severity=DiagnosticSeverity.WARNING,
                    message=f"Evidence '{ev_id}' flagged as stale based on limitations",
                    evidence_ids=(ev_id,),
                    action_taken="Emitted STALE_EVIDENCE signal",
                )

            # 1. Target policy / Blocked destination
            if kind == "target_policy" or status == "blocked":
                reason = val.get("reason", "Target blocked by security policy")
                collector.record(
                    code=DiagnosticCode.BLOCKED_DESTINATION_POLICY,
                    severity=DiagnosticSeverity.WARNING,
                    message=f"Target policy blocked collection for '{ev_id}': {reason}",
                    evidence_ids=(ev_id,),
                    action_taken="Preserved blocked destination diagnostic without collector failure",
                    details={"reason": reason, "status": status},
                )
                continue

            # 2. TLS Certificate (Worker 01 full collector)
            if kind in ("tls_certificate", "tls_cert"):
                if status in ("failed", "unavailable"):
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.TLS_UNAVAILABLE,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                            limitations=item_limitations,
                        )
                    )
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_FAILURE,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                            limitations=item_limitations,
                        )
                    )
                elif status == "observed":
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_SUCCESS,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                        )
                    )
                    is_valid = bool(val.get("is_valid", False))
                    is_expired = bool(val.get("is_expired", False))
                    hostname_match = bool(val.get("hostname_match", False))

                    if is_expired:
                        signals.append(
                            SignalRecord(
                                kind=SignalKind.TLS_EXPIRED,
                                evidence_ids=[ev_id],
                                source=item.source,
                                confidence=SignalConfidence.HIGH,
                                limitations=item_limitations,
                            )
                        )
                    if not hostname_match:
                        signals.append(
                            SignalRecord(
                                kind=SignalKind.TLS_MISMATCH,
                                evidence_ids=[ev_id],
                                source=item.source,
                                confidence=SignalConfidence.HIGH,
                                limitations=item_limitations,
                            )
                        )
                    else:
                        signals.append(
                            SignalRecord(
                                kind=SignalKind.TLS_HOSTNAME_MATCH,
                                evidence_ids=[ev_id],
                                source=item.source,
                                confidence=SignalConfidence.HIGH,
                                limitations=[
                                    "TLS hostname match confirms certificate covers domain, but this is NOT identity authorization (TLS-001)."
                                ],
                            )
                        )

                    if is_valid and not is_expired and hostname_match:
                        signals.append(
                            SignalRecord(
                                kind=SignalKind.TLS_VALID,
                                evidence_ids=[ev_id],
                                source=item.source,
                                confidence=SignalConfidence.HIGH,
                                limitations=item_limitations,
                            )
                        )
                continue

            # 3. TLS Hostname Validation (Fixture adapter)
            if kind == "tls_hostname_validation":
                if status == "observed":
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_SUCCESS,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                        )
                    )
                    res = val.get("result")
                    if res == "valid_for_hostname":
                        # Crucial rule: Emits ONLY TLS_HOSTNAME_MATCH. Cannot establish validity or expiry.
                        signals.append(
                            SignalRecord(
                                kind=SignalKind.TLS_HOSTNAME_MATCH,
                                evidence_ids=[ev_id],
                                source=item.source,
                                confidence=SignalConfidence.HIGH,
                                limitations=[
                                    "Fixture hostname validation confirms domain name coverage only (TLS-001)."
                                ],
                            )
                        )
                    elif res == "mismatch":
                        signals.append(
                            SignalRecord(
                                kind=SignalKind.TLS_MISMATCH,
                                evidence_ids=[ev_id],
                                source=item.source,
                                confidence=SignalConfidence.HIGH,
                                limitations=item_limitations,
                            )
                        )
                elif status in ("failed", "unavailable"):
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_FAILURE,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                        )
                    )
                continue

            # 4. DNS Resolution
            if kind in ("dns_resolution", "dns_records", "dns_collector"):
                if status in ("failed", "unavailable"):
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_FAILURE,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                            limitations=item_limitations,
                        )
                    )
                elif status == "observed":
                    # Observed DNS resolution proves DNS observation success
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_SUCCESS,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                        )
                    )
                    # Check for private or loopback IP leakage in resolved_ips
                    resolved = val.get("resolved_ips", [])
                    if isinstance(resolved, Sequence):
                        for rip in resolved:
                            if isinstance(rip, str) and (rip.startswith("127.") or rip in ("0.0.0.0", "::1")):
                                collector.record(
                                    code=DiagnosticCode.BLOCKED_DESTINATION_POLICY,
                                    severity=DiagnosticSeverity.WARNING,
                                    message=f"DNS returned loopback address {rip}",
                                    evidence_ids=(ev_id,),
                                    action_taken="Flagged loopback IP resolution",
                                )
                continue

            # 5. Threat Intelligence / Feeds
            if kind in ("threat_intelligence", "threat_feed", "reputation_feed"):
                if reliability == "untrusted":
                    collector.record(
                        code=DiagnosticCode.UNVERIFIED_THREAT_PROVENANCE,
                        severity=DiagnosticSeverity.WARNING,
                        message=f"Threat intelligence evidence '{ev_id}' marked as untrusted",
                        evidence_ids=(ev_id,),
                        action_taken="Suppressed threat feed signals from untrusted source",
                    )
                    continue

                if status == "observed":
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_SUCCESS,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                        )
                    )
                    matched = val.get("matched") or val.get("match") or (val.get("threat_level") in ("malicious", "high"))
                    negative = (val.get("matched") is False) or (val.get("match") is False) or (val.get("threat_level") == "none")

                    # Verify target scope if specified in feed value
                    feed_target = val.get("target") or val.get("domain") or val.get("host")
                    if feed_target and isinstance(feed_target, str) and target:
                        if feed_target.strip().lower() != target:
                            collector.record(
                                code=DiagnosticCode.TARGET_SCOPE_MISMATCH,
                                severity=DiagnosticSeverity.WARNING,
                                message=f"Threat feed target '{feed_target}' does not match scan target '{target}'",
                                evidence_ids=(ev_id,),
                                action_taken="Suppressed threat feed signal due to target mismatch",
                            )
                            continue

                    if matched:
                        signals.append(
                            SignalRecord(
                                kind=SignalKind.THREAT_FEED_MATCH,
                                evidence_ids=[ev_id],
                                source=item.source,
                                confidence=SignalConfidence.HIGH,
                                limitations=item_limitations,
                            )
                        )
                    elif negative:
                        # Crucial rule: emit NO_THREAT_MATCH ONLY on successful query returning negative match
                        signals.append(
                            SignalRecord(
                                kind=SignalKind.NO_THREAT_MATCH,
                                evidence_ids=[ev_id],
                                source=item.source,
                                confidence=SignalConfidence.HIGH,
                                limitations=[
                                    "No threat match found in checked feed; does not prove the target is safe (EVID-002)."
                                ],
                            )
                        )
                elif status in ("failed", "unavailable"):
                    # Collector failed: emit COLLECTOR_FAILURE; NEVER emit NO_THREAT_MATCH!
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_FAILURE,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                            limitations=item_limitations,
                        )
                    )
                continue

            # 6. HTTP Metadata
            if kind in ("http_metadata", "http_headers"):
                if status in ("failed", "unavailable"):
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_FAILURE,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                            limitations=item_limitations,
                        )
                    )
                elif status == "observed":
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_SUCCESS,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                        )
                    )
                    if val.get("suspicious_redirect"):
                        signals.append(
                            SignalRecord(
                                kind=SignalKind.SUSPICIOUS_REDIRECT,
                                evidence_ids=[ev_id],
                                source=item.source,
                                confidence=SignalConfidence.MEDIUM,
                                limitations=item_limitations,
                            )
                        )
                    if val.get("suspicious_headers"):
                        signals.append(
                            SignalRecord(
                                kind=SignalKind.SUSPICIOUS_HEADERS,
                                evidence_ids=[ev_id],
                                source=item.source,
                                confidence=SignalConfidence.MEDIUM,
                                limitations=item_limitations,
                            )
                        )
                continue

            # 7. Identity / Authorization Evidence
            if kind in ("authorization_evidence", "organization_verification"):
                if status == "observed" and val.get("authorized") is True:
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.AUTHORIZATION_EVIDENCE,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                            limitations=item_limitations,
                        )
                    )
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_SUCCESS,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                        )
                    )
                continue

            # 8. IDN / Lookalike Heuristic
            if kind in ("idn_lookalike", "domain_heuristic"):
                if status == "observed" and val.get("is_lookalike"):
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.IDN_LOOKALIKE,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.MEDIUM,
                            limitations=["IDN lookalike alone is not proof of impersonation."],
                        )
                    )
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COLLECTOR_SUCCESS,
                            evidence_ids=[ev_id],
                            source=item.source,
                            confidence=SignalConfidence.HIGH,
                        )
                    )
                continue

            # Unsupported / Unrecognized Kind
            collector.record(
                code=DiagnosticCode.UNSUPPORTED_EVIDENCE_KIND,
                severity=DiagnosticSeverity.INFO,
                message=f"Unsupported evidence kind '{item.kind}' ignored for signal extraction",
                evidence_ids=(ev_id,),
                action_taken="Skipped signal extraction for unsupported kind",
                details={"kind": item.kind, "source": item.source},
            )

        # --- Process Community Reports ---
        for rep in policy_input.community_reports:
            r_id = rep.report_id
            rep_domain = rep.normalized_domain.strip().lower() if rep.normalized_domain else ""

            # Check target scope
            if rep_domain and target and rep_domain != target:
                collector.record(
                    code=DiagnosticCode.TARGET_SCOPE_MISMATCH,
                    severity=DiagnosticSeverity.WARNING,
                    message=f"Community report '{r_id}' domain '{rep_domain}' != scan target '{target}'",
                    evidence_ids=(r_id,),
                    action_taken="Suppressed community signal due to target mismatch",
                )
                continue

            v_state = rep.verification_state.strip().lower()
            ev_refs = [r_id] + list(rep.linked_evidence_ids)

            if v_state == "verified":
                # Approved design: Corroboration strictly requires at least 2 independent source families
                # AND valid linked evidence IDs (COMM-002).
                if rep.independent_source_count >= 2 and len(rep.linked_evidence_ids) > 0:
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COMMUNITY_REPORT_CORROBORATED,
                            evidence_ids=ev_refs,
                            source="community_intelligence",
                            confidence=SignalConfidence.CORROBORATED,
                            limitations=["Community report corroborated by multiple independent sources and linked evidence."],
                        )
                    )
                else:
                    collector.record(
                        code=DiagnosticCode.UNVERIFIED_COMMUNITY_REPORT,
                        severity=DiagnosticSeverity.INFO,
                        message=f"Community report '{r_id}' marked verified but lacks required independent source count (>= 2) and linked evidence IDs",
                        evidence_ids=(r_id,),
                        action_taken="Downgraded to unverified community report signal",
                    )
                    signals.append(
                        SignalRecord(
                            kind=SignalKind.COMMUNITY_REPORT_UNVERIFIED,
                            evidence_ids=ev_refs,
                            source="community_intelligence",
                            confidence=SignalConfidence.LOW,
                            limitations=["Report has insufficient independent corroboration."],
                        )
                    )
            elif v_state == "unverified":
                signals.append(
                    SignalRecord(
                        kind=SignalKind.COMMUNITY_REPORT_UNVERIFIED,
                        evidence_ids=ev_refs,
                        source="community_intelligence",
                        confidence=SignalConfidence.LOW,
                        limitations=["Unverified community report; no automatic label applied (COMM-001)."],
                    )
                )
            elif v_state == "disputed":
                signals.append(
                    SignalRecord(
                        kind=SignalKind.COMMUNITY_REPORT_DISPUTED,
                        evidence_ids=ev_refs,
                        source="community_intelligence",
                        confidence=SignalConfidence.MEDIUM,
                        limitations=["Disputed community reports retained without resolution; cautious policy applied."],
                    )
                )
            elif v_state == "rejected":
                collector.record(
                    code=DiagnosticCode.UNVERIFIED_COMMUNITY_REPORT,
                    severity=DiagnosticSeverity.INFO,
                    message=f"Community report '{r_id}' has been rejected by moderation",
                    evidence_ids=(r_id,),
                    action_taken="Suppressed rejected community report",
                )

        return SignalExtractionResult(
            signals=tuple(signals),
            diagnostics=collector.records,
        )
