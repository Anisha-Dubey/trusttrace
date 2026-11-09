"""Data access repository for Worker 02 evidence, findings, and community reports."""

import json
import hashlib
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, func, distinct, update
from sqlalchemy.exc import IntegrityError

from .database import DatabaseManager, default_db
from .models import (
    ScanEntity,
    EvidenceEntity,
    FindingEntity,
    FindingEvidenceLinkEntity,
    CommunityReportEntity,
    CommunityReportEvidenceLinkEntity,
    ReportAuditEntity,
    CommunityDomainSourceFamilyEntity,
    CommunityDomainCoordinationEntity,
)
from ..domain.models import (
    EvidenceModel,
    FindingModel,
    CoverageModel,
    CommunityReportModel,
    ReportAuditEntry,
    utc_now_iso,
)
from ..domain.enums import (
    EvidenceStatus,
    Reliability,
    FindingSeverity,
    VerificationState,
    ClaimType,
)


def compute_evidence_fingerprint(
    scan_id: str,
    kind: str,
    source: str,
    value: Any,
    observed_at: str,
    status: EvidenceStatus,
) -> str:
    """Hash an observation identity while preserving time- and status-distinct records."""
    serialized_val = json.dumps(value, sort_keys=True, default=str)
    status_str = status.value if hasattr(status, "value") else str(status)
    raw = (
        f"{scan_id}:{kind}:{source}:{observed_at}:"
        f"{status_str}:{serialized_val}"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class EvidenceRepository:
    """Repository handling all CRUD and transactional boundaries for Worker 02."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or default_db

    def init_tables(self):
        """Ensure all tables are created."""
        self.db.init_db()

    # --- Scan Methods ---

    def ensure_scan(
        self,
        session: Session,
        scan_id: str,
        submitted_url_redacted: str = "https://unspecified.test/",
        normalized_host: Optional[str] = None,
        status: str = "queued",
        decision: str = "inconclusive",
        policy_version: str = "1.0",
        limitations: Optional[List[str]] = None,
    ) -> ScanEntity:
        """Create a scan record if not exists, or return the existing one.
        
        Handles concurrent creation races safely using savepoints.
        """
        scan = session.get(ScanEntity, scan_id)
        if not scan:
            now = utc_now_iso()
            scan = ScanEntity(
                scan_id=scan_id,
                submitted_url_redacted=submitted_url_redacted,
                normalized_host=normalized_host,
                status=status,
                decision=decision,
                policy_version=policy_version,
                created_at=now,
                limitations_json=json.dumps(limitations or []),
            )
            try:
                with session.begin_nested():
                    session.add(scan)
                    session.flush()
            except IntegrityError:
                scan = session.get(ScanEntity, scan_id)
        return scan

    def update_scan(
        self,
        session: Session,
        scan_id: str,
        status: Optional[str] = None,
        decision: Optional[str] = None,
        completed_at: Optional[str] = None,
        coverage: Optional[CoverageModel] = None,
        limitations: Optional[List[str]] = None,
    ) -> Optional[ScanEntity]:
        """Update scan lifecycle fields and coverage metrics."""
        scan = session.get(ScanEntity, scan_id)
        if not scan:
            return None
        if status:
            scan.status = status
        if decision:
            scan.decision = decision
        if completed_at:
            scan.completed_at = completed_at
        if coverage:
            scan.coverage_total = coverage.checks_total
            scan.coverage_observed = coverage.checks_observed
            scan.coverage_failed = coverage.checks_failed
            scan.coverage_not_run = coverage.checks_not_run
        if limitations is not None:
            scan.limitations_json = json.dumps(limitations)
        session.flush()
        return scan

    def get_scan(self, session: Session, scan_id: str) -> Optional[ScanEntity]:
        """Retrieve a scan entity by ID."""
        return session.get(ScanEntity, scan_id)

    # --- Evidence Methods ---

    def save_evidence(
        self,
        session: Session,
        scan_id: str,
        evidence: EvidenceModel,
    ) -> Tuple[EvidenceModel, bool]:
        """Persist an evidence record with strict idempotency.
        
        Returns:
            Tuple[EvidenceModel, bool]: (evidence_model, was_created)
        """
        self.ensure_scan(session, scan_id)
        fingerprint = compute_evidence_fingerprint(
            scan_id=scan_id,
            kind=evidence.kind,
            source=evidence.source,
            value=evidence.value,
            observed_at=evidence.observed_at,
            status=evidence.status,
        )

        # Check for existing evidence by ID
        existing = session.get(EvidenceEntity, evidence.evidence_id)
        if existing:
            return self._entity_to_evidence_model(existing), False

        # Check for duplicate payload by fingerprint in this scan
        query = select(EvidenceEntity).where(
            and_(
                EvidenceEntity.scan_id == scan_id,
                EvidenceEntity.fingerprint == fingerprint,
            )
        )
        existing_fingerprint = session.execute(query).scalar_one_or_none()
        if existing_fingerprint:
            return self._entity_to_evidence_model(existing_fingerprint), False

        entity = EvidenceEntity(
            evidence_id=evidence.evidence_id,
            scan_id=scan_id,
            kind=evidence.kind,
            value_json=json.dumps(evidence.value) if evidence.value is not None else None,
            source=evidence.source,
            source_type=evidence.source_type or "internal_collector",
            observed_at=evidence.observed_at,
            ingested_at=evidence.ingested_at or utc_now_iso(),
            status=evidence.status.value if hasattr(evidence.status, "value") else str(evidence.status),
            reliability=evidence.reliability.value if hasattr(evidence.reliability, "value") else (str(evidence.reliability) if evidence.reliability else None),
            limitations_json=json.dumps(evidence.limitations or []),
            schema_version=evidence.schema_version,
            fingerprint=fingerprint,
        )
        try:
            with session.begin_nested():
                session.add(entity)
                session.flush()
        except IntegrityError:
            existing = session.get(EvidenceEntity, evidence.evidence_id)
            if existing is None:
                existing = session.execute(
                    select(EvidenceEntity).where(
                        and_(
                            EvidenceEntity.scan_id == scan_id,
                            EvidenceEntity.fingerprint == fingerprint,
                        )
                    )
                ).scalar_one_or_none()
            if existing is not None:
                return self._entity_to_evidence_model(existing), False
            raise
        return self._entity_to_evidence_model(entity), True

    def get_evidence_by_id(self, session: Session, evidence_id: str) -> Optional[EvidenceModel]:
        """Fetch a single evidence record by ID."""
        entity = session.get(EvidenceEntity, evidence_id)
        return self._entity_to_evidence_model(entity) if entity else None

    def get_evidence_by_scan(
        self,
        session: Session,
        scan_id: str,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[EvidenceModel]:
        """Fetch evidence records associated with a scan with optional database-level pagination."""
        query = select(EvidenceEntity).where(EvidenceEntity.scan_id == scan_id).order_by(EvidenceEntity.observed_at)
        if offset is not None:
            query = query.offset(offset)
        if limit is not None:
            query = query.limit(limit)
        entities = session.execute(query).scalars().all()
        return [self._entity_to_evidence_model(e) for e in entities]

    def count_evidence_by_scan(self, session: Session, scan_id: str) -> int:
        """Count total evidence records associated with a scan at database level."""
        return session.execute(
            select(func.count()).select_from(EvidenceEntity).where(EvidenceEntity.scan_id == scan_id)
        ).scalar() or 0

    # --- Finding Methods with Referential Integrity ---

    def save_finding(self, session: Session, scan_id: str, finding: FindingModel) -> FindingModel:
        """Persist a finding with strict referential integrity validation.
        
        Raises ValueError if any referenced evidence_id is missing or belongs to a different scan.
        """
        self.ensure_scan(session, scan_id)

        # Enforce referential integrity: All evidence_ids must exist and belong to this scan
        existing_evidence = self.get_evidence_by_scan(session, scan_id)
        existing_ids = {e.evidence_id for e in existing_evidence}

        dangling = set(finding.evidence_ids) - existing_ids
        if dangling:
            raise ValueError(
                f"Referential integrity violation: Finding '{finding.finding_id}' references "
                f"evidence IDs {list(dangling)} which do not exist for scan '{scan_id}'."
            )

        # Upsert finding
        finding_entity = session.get(FindingEntity, finding.finding_id)
        if not finding_entity:
            finding_entity = FindingEntity(
                finding_id=finding.finding_id,
                scan_id=scan_id,
                kind=finding.kind,
                severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                summary=finding.summary,
                rule_id=finding.rule_id,
                rule_version=finding.rule_version,
                created_at=finding.created_at,
                limitations_json=json.dumps(finding.limitations or []),
            )
            session.add(finding_entity)
            session.flush()

            # Insert links
            for ev_id in finding.evidence_ids:
                link = FindingEvidenceLinkEntity(
                    finding_id=finding.finding_id,
                    evidence_id=ev_id,
                )
                session.add(link)
            session.flush()

        return finding

    def get_findings_by_scan(self, session: Session, scan_id: str) -> List[FindingModel]:
        """Retrieve all findings for a scan, populating linked evidence IDs."""
        query = select(FindingEntity).where(FindingEntity.scan_id == scan_id)
        entities = session.execute(query).scalars().all()
        findings: List[FindingModel] = []
        for fe in entities:
            ev_links = session.execute(
                select(FindingEvidenceLinkEntity.evidence_id).where(
                    FindingEvidenceLinkEntity.finding_id == fe.finding_id
                )
            ).scalars().all()

            findings.append(
                FindingModel(
                    finding_id=fe.finding_id,
                    scan_id=fe.scan_id,
                    kind=fe.kind,
                    severity=FindingSeverity(fe.severity) if not isinstance(fe.severity, FindingSeverity) else fe.severity,
                    summary=fe.summary,
                    evidence_ids=list(ev_links),
                    rule_id=fe.rule_id,
                    rule_version=fe.rule_version,
                    created_at=fe.created_at,
                    limitations=json.loads(fe.limitations_json) if fe.limitations_json else [],
                )
            )
        return findings

    # --- Community Report Methods ---

    def save_community_report(
        self,
        session: Session,
        report: CommunityReportModel,
        source_family: str,
        reporter_hash: str,
    ) -> CommunityReportModel:
        """Persist a community report with validated evidence links.
        
        Strict referential integrity checks:
        1. Duplicate evidence references are rejected.
        2. Every referenced evidence record MUST exist.
        3. Linked evidence MUST belong to a scan matching the report's normalized domain context.
        4. Cross-record reference injection is rejected with zero partial writes.
        """
        # 1. Check duplicate evidence references
        if report.linked_evidence_ids:
            seen_ids = set()
            for ev_id in report.linked_evidence_ids:
                if ev_id in seen_ids:
                    raise ValueError(f"Duplicate linked evidence reference detected: '{ev_id}'.")
                seen_ids.add(ev_id)

            # 2. Validate existence and domain context for each evidence item
            report_domain = report.normalized_domain.strip().lower()
            for ev_id in report.linked_evidence_ids:
                ev = session.get(EvidenceEntity, ev_id)
                if not ev:
                    raise ValueError(f"Referenced evidence ID '{ev_id}' does not exist.")
                
                # Verify domain/host context matches report
                scan = session.get(ScanEntity, ev.scan_id)
                if scan and scan.normalized_host:
                    host = scan.normalized_host.strip().lower()
                    if host != report_domain and not host.endswith("." + report_domain) and not report_domain.endswith("." + host):
                        raise ValueError(
                            f"Cross-record context violation: Evidence '{ev_id}' is from scan '{scan.scan_id}' "
                            f"with host '{host}', which does not match report domain '{report_domain}'."
                        )

        entity = CommunityReportEntity(
            report_id=report.report_id,
            normalized_domain=report.normalized_domain,
            claim_type=report.claim_type.value if hasattr(report.claim_type, "value") else str(report.claim_type),
            note_redacted=report.note_redacted or "",
            submitted_at=report.submitted_at,
            verification_state=report.verification_state.value if hasattr(report.verification_state, "value") else str(report.verification_state),
            independent_source_count=report.independent_source_count,
            source_family=source_family,
            reporter_hash=reporter_hash,
            reviewed_at=report.reviewed_at,
        )
        session.add(entity)
        session.flush()

        # 3. Create junction links
        for ev_id in report.linked_evidence_ids:
            link = CommunityReportEvidenceLinkEntity(
                report_id=report.report_id,
                evidence_id=ev_id,
            )
            session.add(link)
        session.flush()
        return report

    def get_community_report(self, session: Session, report_id: str) -> Optional[CommunityReportModel]:
        """Retrieve a community report by ID."""
        entity = session.get(CommunityReportEntity, report_id)
        if not entity:
            return None
        ev_ids = session.execute(
            select(CommunityReportEvidenceLinkEntity.evidence_id).where(
                CommunityReportEvidenceLinkEntity.report_id == report_id
            )
        ).scalars().all()
        return CommunityReportModel(
            report_id=entity.report_id,
            normalized_domain=entity.normalized_domain,
            claim_type=ClaimType(entity.claim_type) if not isinstance(entity.claim_type, ClaimType) else entity.claim_type,
            note_redacted=entity.note_redacted or "",
            submitted_at=entity.submitted_at,
            verification_state=VerificationState(entity.verification_state) if not isinstance(entity.verification_state, VerificationState) else entity.verification_state,
            independent_source_count=entity.independent_source_count,
            linked_evidence_ids=list(ev_ids),
            reviewed_at=entity.reviewed_at,
        )

    def find_community_reports(
        self,
        session: Session,
        normalized_domain: Optional[str] = None,
        verification_state: Optional[VerificationState] = None,
        claim_type: Optional[ClaimType] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[CommunityReportEntity]:
        """Query community report entities with optional filters and database-level pagination."""
        query = select(CommunityReportEntity)
        conditions = []
        if normalized_domain:
            conditions.append(CommunityReportEntity.normalized_domain == normalized_domain)
        if verification_state:
            state_val = verification_state.value if hasattr(verification_state, "value") else str(verification_state)
            conditions.append(CommunityReportEntity.verification_state == state_val)
        if claim_type:
            claim_val = claim_type.value if hasattr(claim_type, "value") else str(claim_type)
            conditions.append(CommunityReportEntity.claim_type == claim_val)
        if conditions:
            query = query.where(and_(*conditions))
        if offset is not None:
            query = query.offset(offset)
        if limit is not None:
            query = query.limit(limit)
        return list(session.execute(query).scalars().all())

    def count_community_reports(
        self,
        session: Session,
        normalized_domain: Optional[str] = None,
        verification_state: Optional[VerificationState] = None,
        claim_type: Optional[ClaimType] = None,
    ) -> int:
        """Count community report entities matching filters at database level."""
        query = select(func.count()).select_from(CommunityReportEntity)
        conditions = []
        if normalized_domain:
            conditions.append(CommunityReportEntity.normalized_domain == normalized_domain)
        if verification_state:
            state_val = verification_state.value if hasattr(verification_state, "value") else str(verification_state)
            conditions.append(CommunityReportEntity.verification_state == state_val)
        if claim_type:
            claim_val = claim_type.value if hasattr(claim_type, "value") else str(claim_type)
            conditions.append(CommunityReportEntity.claim_type == claim_val)
        if conditions:
            query = query.where(and_(*conditions))
        return session.execute(query).scalar() or 0

    def update_community_report_state(
        self,
        session: Session,
        report_id: str,
        new_state: VerificationState,
        independent_count: Optional[int] = None,
        reviewed_at: Optional[str] = None,
    ) -> Optional[CommunityReportEntity]:
        """Update report verification state."""
        report = session.get(CommunityReportEntity, report_id)
        if not report:
            return None
        report.verification_state = new_state.value if hasattr(new_state, "value") else str(new_state)
        if independent_count is not None:
            report.independent_source_count = independent_count
        if reviewed_at is not None:
            report.reviewed_at = reviewed_at
        session.flush()
        return report

    # --- Multi-Process Coordination & Source Family Consistency (TASK 5) ---

    def acquire_domain_coordination(
        self,
        session: Session,
        normalized_domain: str,
        now_iso: str,
    ) -> CommunityDomainCoordinationEntity:
        """Acquire database-level coordination for a domain.
        
        Uses row-level locking (SELECT ... FOR UPDATE) on PostgreSQL to prevent race conditions
        across multiple worker processes. On SQLite, transactions provide database-level locking.
        """
        dialect_name = ""
        try:
            bind = session.get_bind()
            dialect_name = bind.dialect.name.lower() if bind else ""
        except Exception:
            pass
        supports_for_update = "postgres" in dialect_name

        query = select(CommunityDomainCoordinationEntity).where(
            CommunityDomainCoordinationEntity.normalized_domain == normalized_domain
        )
        if supports_for_update:
            query = query.with_for_update()

        coord = session.execute(query).scalar_one_or_none()
        if not coord:
            coord = CommunityDomainCoordinationEntity(
                normalized_domain=normalized_domain,
                active_claim=None,
                is_disputed=False,
                updated_at=now_iso,
            )
            try:
                with session.begin_nested():
                    session.add(coord)
                    session.flush()
            except IntegrityError:
                coord = session.execute(query).scalar_one_or_none()
                if not coord:
                    coord = session.get(CommunityDomainCoordinationEntity, normalized_domain)

        return coord

    def register_domain_source_family(
        self,
        session: Session,
        normalized_domain: str,
        source_family: str,
        report_id: str,
        created_at: str,
    ) -> bool:
        """Register a source family for a domain.
        
        Returns True if newly registered, False if this source family was already registered
        for this domain (enforced via database uniqueness constraint uq_domain_source_family).
        """
        entity = CommunityDomainSourceFamilyEntity(
            normalized_domain=normalized_domain,
            source_family=source_family,
            first_report_id=report_id,
            created_at=created_at,
        )
        try:
            with session.begin_nested():
                session.add(entity)
                session.flush()
            return True
        except IntegrityError:
            return False

    def count_distinct_source_families_for_domain(
        self,
        session: Session,
        normalized_domain: str,
    ) -> int:
        """Calculate authoritative count of distinct registered source families for a domain."""
        query = select(func.count(distinct(CommunityDomainSourceFamilyEntity.source_family))).where(
            CommunityDomainSourceFamilyEntity.normalized_domain == normalized_domain
        )
        return session.execute(query).scalar() or 0

    def get_registered_source_families_for_domain(
        self,
        session: Session,
        normalized_domain: str,
    ) -> List[str]:
        """Fetch all unique source families registered for a domain."""
        query = select(CommunityDomainSourceFamilyEntity.source_family).where(
            CommunityDomainSourceFamilyEntity.normalized_domain == normalized_domain
        )
        return list(session.execute(query).scalars().all())

    def update_all_reports_independent_count(
        self,
        session: Session,
        normalized_domain: str,
        independent_count: int,
    ) -> None:
        """Atomically synchronize independent_source_count across all reports for a domain."""
        session.execute(
            update(CommunityReportEntity)
            .where(CommunityReportEntity.normalized_domain == normalized_domain)
            .values(independent_source_count=independent_count)
        )
        session.flush()

    def save_audit_event(self, session: Session, event: ReportAuditEntry):
        """Append an audit event."""
        prev_state = None
        if event.previous_state is not None:
            prev_state = event.previous_state.value if hasattr(event.previous_state, "value") else str(event.previous_state)
        new_state = event.new_state.value if hasattr(event.new_state, "value") else str(event.new_state)

        entity = ReportAuditEntity(
            event_id=event.event_id,
            report_id=event.report_id,
            previous_state=prev_state,
            new_state=new_state,
            action=event.action,
            reason=event.reason,
            actor_ref=event.actor_ref,
            timestamp=event.timestamp,
        )
        session.add(entity)
        session.flush()

    def get_audit_events_for_report(self, session: Session, report_id: str) -> List[ReportAuditEntry]:
        """Retrieve chronological audit history for a report."""
        query = select(ReportAuditEntity).where(
            ReportAuditEntity.report_id == report_id
        ).order_by(ReportAuditEntity.timestamp)
        entities = session.execute(query).scalars().all()
        return [
            ReportAuditEntry(
                event_id=e.event_id,
                report_id=e.report_id,
                previous_state=VerificationState(e.previous_state) if e.previous_state else None,
                new_state=VerificationState(e.new_state) if not isinstance(e.new_state, VerificationState) else e.new_state,
                action=e.action,
                reason=e.reason,
                actor_ref=e.actor_ref,
                timestamp=e.timestamp,
            )
            for e in entities
        ]

    # --- Helper Serializers ---

    @staticmethod
    def _entity_to_evidence_model(entity: EvidenceEntity) -> EvidenceModel:
        return EvidenceModel(
            evidence_id=entity.evidence_id,
            scan_id=entity.scan_id,
            kind=entity.kind,
            value=json.loads(entity.value_json) if entity.value_json else None,
            source=entity.source,
            source_type=entity.source_type,
            observed_at=entity.observed_at,
            ingested_at=entity.ingested_at,
            status=EvidenceStatus(entity.status) if not isinstance(entity.status, EvidenceStatus) else entity.status,
            reliability=Reliability(entity.reliability) if entity.reliability else None,
            limitations=json.loads(entity.limitations_json) if entity.limitations_json else [],
            schema_version=entity.schema_version,
        )
