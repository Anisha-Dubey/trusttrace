"""Provenance tracking and finding linkage engine for Worker 02."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy import select

from ..domain.models import EvidenceModel, FindingModel, utc_now_iso
from ..domain.enums import Reliability, EvidenceStatus, FindingSeverity
from ..persistence.database import DatabaseManager, default_db
from ..persistence.models import EvidenceEntity, FindingEntity, FindingEvidenceLinkEntity


class ReferentialIntegrityError(ValueError):
    """Raised when a finding references non-existent or mis-scoped evidence."""
    pass


@dataclass
class EvidenceProvenance:
    """Detailed provenance and freshness metadata for an evidence item."""
    evidence_id: str
    scan_id: str
    kind: str
    source: str
    source_type: str
    reliability: str
    observed_at: str
    ingested_at: str
    latency_seconds: float
    freshness_state: str  # fresh, stale, unknown
    is_fixture: bool
    limitations: List[str]


@dataclass
class FindingDetail:
    """Full finding model with hydrated supporting evidence provenance."""
    finding: FindingModel
    supporting_evidence: List[EvidenceModel]
    provenance_chain: List[EvidenceProvenance]
    integrity_verified: bool
    warnings: List[str] = field(default_factory=list)


class ProvenanceEngine:
    """Engine responsible for provenance verification, freshness analysis, and finding linkage."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or default_db

    def analyze_provenance(
        self,
        evidence: EvidenceModel,
        freshness_ttl_seconds: int = 86400,  # 24 hours
    ) -> EvidenceProvenance:
        """Compute provenance metadata, ingestion latency, and freshness state."""
        try:
            obs_dt = datetime.fromisoformat(evidence.observed_at.replace("Z", "+00:00"))
            ing_dt = datetime.fromisoformat((evidence.ingested_at or utc_now_iso()).replace("Z", "+00:00"))
            if obs_dt.tzinfo is None:
                obs_dt = obs_dt.replace(tzinfo=timezone.utc)
            if ing_dt.tzinfo is None:
                ing_dt = ing_dt.replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            latency = max(0.0, (ing_dt - obs_dt).total_seconds())
            age = (now_dt - obs_dt).total_seconds()
            freshness = "fresh" if age <= freshness_ttl_seconds else "stale"
        except Exception:
            latency = 0.0
            freshness = "unknown"

        is_fixture = (
            evidence.source == "fixture_adapter"
            or evidence.source_type == "fixture"
            or any("fixture" in lim.lower() for lim in evidence.limitations)
        )

        return EvidenceProvenance(
            evidence_id=evidence.evidence_id,
            scan_id=evidence.scan_id or "unknown",
            kind=evidence.kind,
            source=evidence.source,
            source_type=evidence.source_type or "internal_collector",
            reliability=evidence.reliability.value if evidence.reliability else Reliability.UNKNOWN.value,
            observed_at=evidence.observed_at,
            ingested_at=evidence.ingested_at or utc_now_iso(),
            latency_seconds=round(latency, 3),
            freshness_state=freshness,
            is_fixture=is_fixture,
            limitations=evidence.limitations,
        )

    def link_and_verify_finding(
        self,
        finding: FindingModel,
        scan_evidence: List[EvidenceModel],
    ) -> FindingDetail:
        """Enforce referential integrity and evidence sufficiency on a finding."""
        evidence_by_id = {e.evidence_id: e for e in scan_evidence}
        missing_ids = [eid for eid in finding.evidence_ids if eid not in evidence_by_id]

        if missing_ids:
            raise ReferentialIntegrityError(
                f"Finding '{finding.finding_id}' references missing evidence IDs: {missing_ids}. "
                f"Every finding must reference existing evidence within the scan."
            )

        supporting = [evidence_by_id[eid] for eid in finding.evidence_ids]
        provenances = [self.analyze_provenance(e) for e in supporting]

        warnings: List[str] = []

        # Claim guard: A finding must not claim more than its supporting evidence establishes
        # E.g., if all evidence is failed/unavailable, a critical severity finding is suspect
        all_failed_or_blocked = all(
            e.status in (EvidenceStatus.FAILED, EvidenceStatus.UNAVAILABLE, EvidenceStatus.BLOCKED)
            for e in supporting
        )
        if all_failed_or_blocked and finding.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL):
            warnings.append(
                f"Finding severity '{finding.severity.value}' is supported solely by failed/unavailable/blocked checks."
            )

        # Check for provider assertion treated as direct observation
        has_only_unverified_claims = all(
            e.reliability in (Reliability.PROVIDER_ASSERTION, Reliability.USER_REPORT, Reliability.UNKNOWN)
            for e in supporting
        )
        if has_only_unverified_claims and "confirmed" in finding.summary.lower():
            warnings.append("Finding asserts confirmed threat but is supported only by unverified claims/assertions.")

        return FindingDetail(
            finding=finding,
            supporting_evidence=supporting,
            provenance_chain=provenances,
            integrity_verified=True,
            warnings=warnings,
        )

    def get_scan_provenance_summary(self, scan_id: str) -> Dict[str, Any]:
        """Aggregate provenance metrics for all evidence in a scan."""
        with self.db.session_scope() as session:
            query = select(EvidenceEntity).where(EvidenceEntity.scan_id == scan_id)
            entities = session.execute(query).scalars().all()

            if not entities:
                return {
                    "scan_id": scan_id,
                    "evidence_count": 0,
                    "sources": [],
                    "reliability_breakdown": {},
                    "freshness_breakdown": {},
                }

            sources = list(set(e.source for e in entities))
            reliability_counts: Dict[str, int] = {}
            for e in entities:
                r = e.reliability or "unknown"
                reliability_counts[r] = reliability_counts.get(r, 0) + 1

            provenances = [
                self.analyze_provenance(
                    EvidenceModel(
                        evidence_id=e.evidence_id,
                        scan_id=e.scan_id,
                        kind=e.kind,
                        source=e.source,
                        source_type=e.source_type,
                        observed_at=e.observed_at,
                        ingested_at=e.ingested_at,
                        status=EvidenceStatus(e.status),
                        reliability=Reliability(e.reliability) if e.reliability else None,
                        limitations=json.loads(e.limitations_json) if e.limitations_json else [],
                    )
                )
                for e in entities
            ]

            freshness_counts: Dict[str, int] = {}
            for p in provenances:
                freshness_counts[p.freshness_state] = freshness_counts.get(p.freshness_state, 0) + 1

            return {
                "scan_id": scan_id,
                "evidence_count": len(entities),
                "sources": sources,
                "reliability_breakdown": reliability_counts,
                "freshness_breakdown": freshness_counts,
                "items": [
                    {
                        "evidence_id": p.evidence_id,
                        "kind": p.kind,
                        "source": p.source,
                        "reliability": p.reliability,
                        "observed_at": p.observed_at,
                        "ingested_at": p.ingested_at,
                        "latency_seconds": p.latency_seconds,
                        "freshness_state": p.freshness_state,
                        "is_fixture": p.is_fixture,
                    }
                    for p in provenances
                ],
            }
