"""Deduplication and Source-Family Lineage Analyzer for Community Reports."""

from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Set
from datetime import datetime, timezone

from ..domain.enums import ClaimType, VerificationState
from ..persistence.models import CommunityReportEntity


class DeduplicationCategory(str, Enum):
    EXACT_DUPLICATE = "exact_duplicate"
    COPIED_SOURCE = "copied_source"
    INDEPENDENT_SOURCE = "independent_source"
    CONFLICTING_REPORT = "conflicting_report"
    NEW_REPORT = "new_report"


@dataclass
class DeduplicationResult:
    """Outcome of duplicate and source-family analysis."""
    category: DeduplicationCategory
    matched_report_id: Optional[str]
    source_family: str
    should_increment_independent: bool
    is_conflict: bool
    conflict_reason: Optional[str]
    explanation: str


class SourceFamilyAnalyzer:
    """Normalizes and maps threat-intelligence sources to canonical source families."""

    # Authoritative feed provider families that require authenticated provider status
    VERIFIED_PROVIDER_FAMILIES: Set[str] = {
        "phishtank",
        "openphish",
        "urlhaus",
        "virustotal",
        "cert_feed",
        "internal_collector",
    }

    # Known syndication / feed family aliases
    FAMILY_ALIASES: Dict[str, str] = {
        "phishtank": "phishtank",
        "phishtank_api": "phishtank",
        "phishtank_community": "phishtank",
        "openphish": "openphish",
        "openphish_feed": "openphish",
        "urlhaus": "urlhaus",
        "abuse_ch_urlhaus": "urlhaus",
        "virustotal": "virustotal",
        "vt_feed": "virustotal",
    }

    @classmethod
    def canonicalize_family(cls, raw_family: Optional[str]) -> str:
        """Map raw family or provider name to canonical root family."""
        if not raw_family:
            return "community_user"
        cleaned = raw_family.strip().lower()
        return cls.FAMILY_ALIASES.get(cleaned, cleaned)

    @classmethod
    def validate_and_canonicalize(
        cls,
        raw_family: Optional[str],
        is_authenticated_provider: bool = False,
    ) -> str:
        """Validate and map source family, rejecting unauthorized client claims of provider identities."""
        if not raw_family or raw_family.strip().lower() == "community_user":
            return "community_user"

        cleaned = raw_family.strip().lower()
        canonical = cls.FAMILY_ALIASES.get(cleaned, cleaned)

        # Untrusted client attempting to claim an authoritative feed provider
        if canonical in cls.VERIFIED_PROVIDER_FAMILIES and not is_authenticated_provider:
            raise ValueError(
                f"Unauthorized source family claim: '{raw_family}'. "
                f"Unauthenticated or public clients cannot claim verified provider identities."
            )
        return canonical


class ReportDeduplicator:
    """Evaluates incoming community reports for duplication, syndication, and conflict."""

    def __init__(self, dedup_window_seconds: int = 86400):
        self.dedup_window_seconds = dedup_window_seconds

    def analyze(
        self,
        new_domain: str,
        new_claim: ClaimType,
        new_reporter_hash: str,
        new_source_family: str,
        existing_reports: List[CommunityReportEntity],
        is_authenticated_provider: bool = False,
    ) -> DeduplicationResult:
        """Evaluate submission against existing reports for the same domain with source verification."""
        canonical_family = SourceFamilyAnalyzer.validate_and_canonicalize(
            new_source_family, is_authenticated_provider=is_authenticated_provider
        )

        if not existing_reports:
            return DeduplicationResult(
                category=DeduplicationCategory.NEW_REPORT,
                matched_report_id=None,
                source_family=canonical_family,
                should_increment_independent=True,
                is_conflict=False,
                conflict_reason=None,
                explanation="First community report for this domain.",
            )

        # 1. Check for Conflicting Report
        conflicting = None
        for rep in existing_reports:
            rep_claim = ClaimType(rep.claim_type)
            if self._is_contradictory_claim(rep_claim, new_claim):
                conflicting = rep
                break

        if conflicting:
            return DeduplicationResult(
                category=DeduplicationCategory.CONFLICTING_REPORT,
                matched_report_id=conflicting.report_id,
                source_family=canonical_family,
                should_increment_independent=False,
                is_conflict=True,
                conflict_reason=(
                    f"Contradictory claim '{new_claim.value}' filed against existing claim "
                    f"'{conflicting.claim_type}' on report '{conflicting.report_id}'."
                ),
                explanation="Conflicting community claims detected; domain marked as disputed.",
            )

        # 2. Check for Exact Duplicate
        for rep in existing_reports:
            if rep.claim_type == new_claim.value and rep.reporter_hash == new_reporter_hash:
                return DeduplicationResult(
                    category=DeduplicationCategory.EXACT_DUPLICATE,
                    matched_report_id=rep.report_id,
                    source_family=canonical_family,
                    should_increment_independent=False,
                    is_conflict=False,
                    conflict_reason=None,
                    explanation="Exact duplicate: same reporter submitted identical claim for this domain.",
                )

        # 3. Check for Copied/Shared Source
        for rep in existing_reports:
            rep_family = SourceFamilyAnalyzer.canonicalize_family(rep.source_family)
            if rep_family == canonical_family:
                return DeduplicationResult(
                    category=DeduplicationCategory.COPIED_SOURCE,
                    matched_report_id=rep.report_id,
                    source_family=canonical_family,
                    should_increment_independent=False,
                    is_conflict=False,
                    conflict_reason=None,
                    explanation=(
                        f"Copied or shared source: report shares common source family '{canonical_family}' "
                        f"with report '{rep.report_id}'; independent corroboration count not incremented."
                    ),
                )

        # 4. Independent Source
        return DeduplicationResult(
            category=DeduplicationCategory.INDEPENDENT_SOURCE,
            matched_report_id=None,
            source_family=canonical_family,
            should_increment_independent=True,
            is_conflict=False,
            conflict_reason=None,
            explanation=f"Independent source from family '{canonical_family}' corroborates existing report.",
        )

    @staticmethod
    def _is_contradictory_claim(claim_a: ClaimType, claim_b: ClaimType) -> bool:
        """Determine if two claims logically contradict each other."""
        severe_threats = {ClaimType.PHISHING, ClaimType.MALWARE_DELIVERY, ClaimType.IMPERSONATION}
        if (claim_a in severe_threats and claim_b == ClaimType.OTHER) or (
            claim_b in severe_threats and claim_a == ClaimType.OTHER
        ):
            return True
        return False
