"""Evidence Ingestion, Coverage, and Provenance Service for Worker 02."""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
import uuid

from ..domain.models import (
    EvidenceModel,
    FindingModel,
    CoverageModel,
    utc_now_iso,
)
from ..domain.enums import EvidenceStatus, Reliability, FindingSeverity
from ..adapters.base import EvidenceBatch
from ..persistence.repository import EvidenceRepository
from ..persistence.database import DatabaseManager, default_db


@dataclass
class IngestionResult:
    """Summary of an evidence ingestion run."""
    scan_id: str
    total_received: int
    inserted_count: int
    deduplicated_count: int
    items: List[EvidenceModel] = field(default_factory=list)
    coverage: Optional[CoverageModel] = None


class EvidenceService:
    """Service handling evidence ingestion pipeline, provenance tracking, and coverage."""

    def __init__(
        self,
        repository: Optional[EvidenceRepository] = None,
        db_manager: Optional[DatabaseManager] = None,
    ):
        self.db = db_manager or default_db
        self.repo = repository or EvidenceRepository(db_manager=self.db)
        self.repo.init_tables()

    def calculate_coverage(
        self,
        evidence_items: List[EvidenceModel],
        expected_total_checks: int = 4,
    ) -> CoverageModel:
        """Calculate coverage metrics enforcing the invariant: total = observed + failed + not_run.
        
        Mapping policy:
        - status == OBSERVED -> checks_observed += 1
        - status == FAILED -> checks_failed += 1
        - status in (NOT_RUN, UNAVAILABLE, BLOCKED) -> checks_not_run += 1
        
        If total known distinct collector checks is less than expected_total_checks (e.g. 4 for standard profile),
        the unexecuted remainder is accounted for in checks_not_run.
        """
        observed = sum(1 for e in evidence_items if e.status == EvidenceStatus.OBSERVED)
        failed = sum(1 for e in evidence_items if e.status == EvidenceStatus.FAILED)
        not_run = sum(
            1 for e in evidence_items
            if e.status in (EvidenceStatus.NOT_RUN, EvidenceStatus.UNAVAILABLE, EvidenceStatus.BLOCKED)
        )

        total_tracked = observed + failed + not_run
        if total_tracked < expected_total_checks:
            not_run += (expected_total_checks - total_tracked)
            total = expected_total_checks
        else:
            total = total_tracked

        return CoverageModel(
            checks_total=total,
            checks_observed=observed,
            checks_failed=failed,
            checks_not_run=not_run,
        )

    def ingest_batch(self, batch: EvidenceBatch) -> IngestionResult:
        """Execute the transactional evidence ingestion pipeline for a batch."""
        with self.db.session_scope() as session:
            # Step 1: Ensure scan record exists
            self.repo.ensure_scan(
                session,
                scan_id=batch.scan_id,
                submitted_url_redacted=batch.metadata.get("submitted_url_redacted", "https://unspecified.test/"),
                normalized_host=batch.metadata.get("normalized_host"),
                status=batch.metadata.get("status", "validating"),
                decision=batch.metadata.get("decision", "inconclusive"),
                policy_version=batch.metadata.get("policy_version", "1.0"),
                limitations=batch.limitations,
            )

            inserted = 0
            deduped = 0
            persisted_models: List[EvidenceModel] = []

            # Step 2-8: Validate and persist each evidence item idempotently
            for item in batch.items:
                model, was_created = self.repo.save_evidence(
                    session=session,
                    scan_id=batch.scan_id,
                    evidence=item,
                )
                persisted_models.append(model)
                if was_created:
                    inserted += 1
                else:
                    deduped += 1

            # Step 9: Recompute and update scan coverage
            coverage = batch.suggested_coverage or self.calculate_coverage(persisted_models)
            self.repo.update_scan(
                session,
                scan_id=batch.scan_id,
                coverage=coverage,
            )

            return IngestionResult(
                scan_id=batch.scan_id,
                total_received=len(batch.items),
                inserted_count=inserted,
                deduplicated_count=deduped,
                items=persisted_models,
                coverage=coverage,
            )

    def ingest_single_observation(
        self,
        scan_id: str,
        payload: Dict[str, Any],
    ) -> Tuple[EvidenceModel, bool]:
        """Ingest a single evidence record payload with validation."""
        schema_version = payload.get("schema_version", "1.0")
        if schema_version != "1.0":
            raise ValueError(f"Unsupported schema version: {schema_version}")

        ev_id = payload.get("evidence_id") or f"ev-{uuid.uuid4().hex[:8]}"
        observed_at = payload.get("observed_at") or utc_now_iso()
        
        status_val = payload.get("status")
        if not status_val:
            raise ValueError("Evidence status is required.")
        status = EvidenceStatus(status_val)

        rel_val = payload.get("reliability")
        reliability = Reliability(rel_val) if rel_val else None

        model = EvidenceModel(
            evidence_id=ev_id,
            scan_id=scan_id,
            kind=payload["kind"],
            value=payload.get("value"),
            source=payload["source"],
            source_type=payload.get("source_type", "internal_collector"),
            observed_at=observed_at,
            status=status,
            reliability=reliability,
            limitations=payload.get("limitations", []),
            schema_version=schema_version,
        )

        with self.db.session_scope() as session:
            persisted, was_created = self.repo.save_evidence(session, scan_id, model)
            
            # Recalculate coverage
            all_evidence = self.repo.get_evidence_by_scan(session, scan_id)
            cov = self.calculate_coverage(all_evidence)
            self.repo.update_scan(session, scan_id, coverage=cov)

            return persisted, was_created

    def add_finding(self, scan_id: str, finding_payload: Dict[str, Any]) -> FindingModel:
        """Create a finding referencing existing evidence records with referential validation."""
        finding = FindingModel(
            finding_id=finding_payload.get("finding_id") or f"f-{uuid.uuid4().hex[:8]}",
            scan_id=scan_id,
            kind=finding_payload["kind"],
            severity=FindingSeverity(finding_payload["severity"]),
            summary=finding_payload["summary"],
            evidence_ids=finding_payload["evidence_ids"],
            rule_id=finding_payload["rule_id"],
            rule_version=finding_payload["rule_version"],
            created_at=finding_payload.get("created_at") or utc_now_iso(),
            limitations=finding_payload.get("limitations", []),
        )

        with self.db.session_scope() as session:
            return self.repo.save_finding(session, scan_id, finding)

    def get_scan_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Assemble a complete report conforming to scan_report.schema.json."""
        with self.db.session_scope() as session:
            scan = self.repo.get_scan(session, scan_id)
            if not scan:
                return None

            evidence_items = self.repo.get_evidence_by_scan(session, scan_id)
            findings = self.repo.get_findings_by_scan(session, scan_id)

            coverage = CoverageModel(
                checks_total=scan.coverage_total,
                checks_observed=scan.coverage_observed,
                checks_failed=scan.coverage_failed,
                checks_not_run=scan.coverage_not_run,
            )

            # Determine dimension states or fallback
            has_failed = any(e.status == EvidenceStatus.FAILED for e in evidence_items)
            has_blocked = any(e.status == EvidenceStatus.BLOCKED for e in evidence_items)

            evidence_quality = "unavailable"
            if coverage.checks_observed > 0 and not has_failed:
                evidence_quality = "strong" if coverage.checks_not_run == 0 else "partial"
            elif coverage.checks_observed > 0 and has_failed:
                evidence_quality = "weak"

            certificate_dim = "not_checked"
            for ev in evidence_items:
                if ev.kind == "tls_hostname_validation":
                    certificate_dim = "valid_for_hostname" if ev.status == EvidenceStatus.OBSERVED else "invalid_or_expired"

            identity_dim = "unverified"
            if has_blocked:
                identity_dim = "unknown"

            behavior_dim = "unknown"
            if scan.decision == "no_threat_observed":
                behavior_dim = "no_threat_observed"
            elif scan.decision in ("high_risk", "caution"):
                behavior_dim = "suspicious"

            import json
            scan_limitations = json.loads(scan.limitations_json) if scan.limitations_json else []

            report = {
                "schema_version": "1.0",
                "scan_id": scan.scan_id,
                "submitted_url_redacted": scan.submitted_url_redacted,
                "normalized_host": scan.normalized_host,
                "status": scan.status,
                "decision": scan.decision,
                "created_at": scan.created_at,
                "completed_at": scan.completed_at,
                "policy_version": scan.policy_version,
                "dimensions": {
                    "identity": identity_dim,
                    "certificate": certificate_dim,
                    "behavior": behavior_dim,
                    "evidence_quality": evidence_quality,
                },
                "coverage": coverage.model_dump(),
                "evidence": [e.to_v1_contract_dict() for e in evidence_items],
                "findings": [f.to_v1_contract_dict() for f in findings],
                "limitations": scan_limitations,
            }
            return report
