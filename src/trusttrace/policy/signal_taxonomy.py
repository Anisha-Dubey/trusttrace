"""Signal taxonomy for Worker 03 Phase 01.

Defines a typed signal classification system that separates identity,
certificate, behavior, and evidence-quality dimensions. Each signal maps
to exactly one dimension, carries provenance, and has explicit abstention
conditions.

Implements the conservative decision policy table from
.brain/.work/shared/decision_policy_table.md
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SignalKind(str, Enum):
    """Typed signal categories aligned with scan_report.schema.json dimensions."""

    # Identity signals
    TLS_HOSTNAME_MATCH = "tls_hostname_match"
    AUTHORIZATION_EVIDENCE = "authorization_evidence"
    IDN_LOOKALIKE = "idn_lookalike"

    # Certificate signals
    TLS_VALID = "tls_valid"
    TLS_EXPIRED = "tls_expired"
    TLS_MISMATCH = "tls_mismatch"
    TLS_UNAVAILABLE = "tls_unavailable"

    # Behavior signals
    THREAT_FEED_MATCH = "threat_feed_match"
    SUSPICIOUS_REDIRECT = "suspicious_redirect"
    SUSPICIOUS_HEADERS = "suspicious_headers"
    NO_THREAT_MATCH = "no_threat_match"

    # Evidence quality signals
    COLLECTOR_SUCCESS = "collector_success"
    COLLECTOR_FAILURE = "collector_failure"
    STALE_EVIDENCE = "stale_evidence"
    CONFLICTING_SIGNALS = "conflicting_signals"

    # Community signals
    COMMUNITY_REPORT_UNVERIFIED = "community_report_unverified"
    COMMUNITY_REPORT_CORROBORATED = "community_report_corroborated"
    COMMUNITY_REPORT_DISPUTED = "community_report_disputed"


class SignalDimension(str, Enum):
    """The four assessment dimensions from the schema."""

    IDENTITY = "identity"
    CERTIFICATE = "certificate"
    BEHAVIOR = "behavior"
    EVIDENCE_QUALITY = "evidence_quality"


# Map each signal kind to its primary dimension.
SIGNAL_DIMENSION_MAP: Dict[SignalKind, SignalDimension] = {
    SignalKind.TLS_HOSTNAME_MATCH: SignalDimension.IDENTITY,
    SignalKind.AUTHORIZATION_EVIDENCE: SignalDimension.IDENTITY,
    SignalKind.IDN_LOOKALIKE: SignalDimension.IDENTITY,
    SignalKind.TLS_VALID: SignalDimension.CERTIFICATE,
    SignalKind.TLS_EXPIRED: SignalDimension.CERTIFICATE,
    SignalKind.TLS_MISMATCH: SignalDimension.CERTIFICATE,
    SignalKind.TLS_UNAVAILABLE: SignalDimension.CERTIFICATE,
    SignalKind.THREAT_FEED_MATCH: SignalDimension.BEHAVIOR,
    SignalKind.SUSPICIOUS_REDIRECT: SignalDimension.BEHAVIOR,
    SignalKind.SUSPICIOUS_HEADERS: SignalDimension.BEHAVIOR,
    SignalKind.NO_THREAT_MATCH: SignalDimension.BEHAVIOR,
    SignalKind.COLLECTOR_SUCCESS: SignalDimension.EVIDENCE_QUALITY,
    SignalKind.COLLECTOR_FAILURE: SignalDimension.EVIDENCE_QUALITY,
    SignalKind.STALE_EVIDENCE: SignalDimension.EVIDENCE_QUALITY,
    SignalKind.CONFLICTING_SIGNALS: SignalDimension.EVIDENCE_QUALITY,
    SignalKind.COMMUNITY_REPORT_UNVERIFIED: SignalDimension.BEHAVIOR,
    SignalKind.COMMUNITY_REPORT_CORROBORATED: SignalDimension.BEHAVIOR,
    SignalKind.COMMUNITY_REPORT_DISPUTED: SignalDimension.BEHAVIOR,
}


@dataclass
class SignalRecord:
    """A single typed signal with provenance and evidence link.

    Attributes:
        kind: The classified signal type.
        evidence_ids: List of evidence IDs supporting this signal.
        source: Origin system or collector that produced the signal.
        confidence: Signal confidence (not a probability; purely ordinal).
        value: Optional raw value from the evidence.
        limitations: Explicit caveats about the signal's applicability.
    """

    kind: SignalKind
    evidence_ids: List[str]
    source: str
    confidence: str = "direct_observation"  # matches Reliability enum
    value: Optional[Any] = None
    limitations: List[str] = field(default_factory=list)

    @property
    def dimension(self) -> SignalDimension:
        """Return the primary dimension this signal contributes to."""
        return SIGNAL_DIMENSION_MAP[self.kind]


@dataclass
class DimensionAssessment:
    """Assessment for a single dimension with rationale chain.

    Attributes:
        dimension: Which of the four dimensions this covers.
        value: The schema-enum value assigned to this dimension.
        contributing_signals: Signal kinds that informed the value.
        rationale: Human-readable explanation of why this value was chosen.
        abstention_reason: If no assessment can be made, why not.
    """

    dimension: SignalDimension
    value: str
    contributing_signals: List[SignalKind] = field(default_factory=list)
    rationale: str = ""
    abstention_reason: Optional[str] = None
