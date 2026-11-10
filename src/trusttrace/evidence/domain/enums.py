"""Domain enums for Worker 02 matching TRUSTTRACE v1 contracts."""

from enum import Enum
from typing import Optional, Union


class EvidenceStatus(str, Enum):
    OBSERVED = "observed"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    NOT_RUN = "not_run"
    BLOCKED = "blocked"


class Reliability(str, Enum):
    PROVIDER_ASSERTION = "provider_assertion"
    DIRECT_OBSERVATION = "direct_observation"
    DERIVED_SIGNAL = "derived_signal"
    USER_REPORT = "user_report"
    UNKNOWN = "unknown"


def normalize_reliability(
    value: Optional[Union[str, Reliability]],
    default: Optional[Reliability] = None,
) -> Optional[Reliability]:
    """Normalize input strings or enums into canonical Reliability values.

    Handles canonical strings:
        - "direct_observation" -> Reliability.DIRECT_OBSERVATION
        - "provider_assertion" -> Reliability.PROVIDER_ASSERTION
        - "derived_signal"     -> Reliability.DERIVED_SIGNAL
        - "user_report"        -> Reliability.USER_REPORT
        - "unknown"            -> Reliability.UNKNOWN

    Handles tier aliases:
        - "high"   -> Reliability.DIRECT_OBSERVATION
        - "medium" -> Reliability.DERIVED_SIGNAL
        - "low"    -> Reliability.USER_REPORT

    Handles unmapped or unrecognized strings:
        - Returns Reliability.UNKNOWN (or default if explicitly provided).
    """
    if value is None:
        return default
    if isinstance(value, Reliability):
        return value

    val_str = str(value).strip().lower()
    if not val_str:
        return default

    # Canonical exact mappings
    canonical_map = {
        "direct_observation": Reliability.DIRECT_OBSERVATION,
        "provider_assertion": Reliability.PROVIDER_ASSERTION,
        "derived_signal": Reliability.DERIVED_SIGNAL,
        "user_report": Reliability.USER_REPORT,
        "unknown": Reliability.UNKNOWN,
    }
    if val_str in canonical_map:
        return canonical_map[val_str]

    # Tier aliases
    tier_map = {
        "high": Reliability.DIRECT_OBSERVATION,
        "medium": Reliability.DERIVED_SIGNAL,
        "low": Reliability.USER_REPORT,
        "direct": Reliability.DIRECT_OBSERVATION,
        "derived": Reliability.DERIVED_SIGNAL,
        "assertion": Reliability.PROVIDER_ASSERTION,
        "user": Reliability.USER_REPORT,
    }
    if val_str in tier_map:
        return tier_map[val_str]

    return Reliability.UNKNOWN



class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationState(str, Enum):
    UNVERIFIED = "unverified"
    CORROBORATED = "corroborated"
    DISPUTED = "disputed"
    REVIEWED = "reviewed"


class ClaimType(str, Enum):
    PHISHING = "phishing"
    IMPERSONATION = "impersonation"
    MALWARE_DELIVERY = "malware_delivery"
    SUSPICIOUS_REDIRECT = "suspicious_redirect"
    OTHER = "other"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    VALIDATING = "validating"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    REJECTED = "rejected"


class ScanDecision(str, Enum):
    HIGH_RISK = "high_risk"
    CAUTION = "caution"
    NO_THREAT_OBSERVED = "no_threat_observed"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"
    FAILED = "failed"


class IdentityDimension(str, Enum):
    SUPPORTED = "supported"
    UNVERIFIED = "unverified"
    CONTRADICTED = "contradicted"
    UNKNOWN = "unknown"


class CertificateDimension(str, Enum):
    VALID_FOR_HOSTNAME = "valid_for_hostname"
    INVALID_OR_EXPIRED = "invalid_or_expired"
    UNAVAILABLE = "unavailable"
    NOT_CHECKED = "not_checked"


class BehaviorDimension(str, Enum):
    SUSPICIOUS = "suspicious"
    NO_THREAT_OBSERVED = "no_threat_observed"
    MALICIOUS_EVIDENCE = "malicious_evidence"
    UNKNOWN = "unknown"


class EvidenceQualityDimension(str, Enum):
    STRONG = "strong"
    PARTIAL = "partial"
    WEAK = "weak"
    UNAVAILABLE = "unavailable"
