"""Community intelligence intake, moderation, deduplication, and lifecycle service for Worker 02."""

import uuid
import threading
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, timezone

from .sanitizer import sanitize_text, hash_reporter_identity
from .state_machine import validate_transition, InvalidStateTransitionError
from .deduplicator import (
    ReportDeduplicator,
    SourceFamilyAnalyzer,
    DeduplicationCategory,
    DeduplicationResult,
)
from ..domain.models import CommunityReportModel, ReportAuditEntry, utc_now_iso
from ..domain.enums import VerificationState, ClaimType
from ..persistence.database import DatabaseManager, default_db
from ..persistence.repository import EvidenceRepository
from ..persistence.models import CommunityReportEntity


class CommunityIntelligenceService:
    """Manages the full trustworthy lifecycle of community reports with deduplication and corroboration."""

    def __init__(
        self,
        repository: Optional[EvidenceRepository] = None,
        db_manager: Optional[DatabaseManager] = None,
        deduplicator: Optional[ReportDeduplicator] = None,
    ):
        self.db = db_manager or default_db
        self.repo = repository or EvidenceRepository(db_manager=self.db)
        self.repo.init_tables()
        self.deduplicator = deduplicator or ReportDeduplicator()
        self._lock = threading.RLock()

    def submit_report(
        self,
        normalized_domain: str,
        claim_type: str,
        note: Optional[str] = "",
        raw_reporter_identifier: str = "anonymous",
        source_family: Optional[str] = None,
        linked_evidence_ids: Optional[List[str]] = None,
        is_authenticated_provider: bool = False,
        permitted_families: Optional[Set[str]] = None,
    ) -> Tuple[CommunityReportModel, DeduplicationResult]:
        """Intake a community report safely with deduplication, source-family validation,
        and multi-process database coordination (TASK 4 & TASK 5).
        
        Returns:
            Tuple[CommunityReportModel, DeduplicationResult]
        """
        with self._lock:
            clean_domain = normalized_domain.strip().lower()
            if clean_domain.endswith("."):
                clean_domain = clean_domain[:-1]
            clean_note = sanitize_text(note, max_length=1000)
            reporter_hash = hash_reporter_identity(raw_reporter_identifier)
            family = SourceFamilyAnalyzer.validate_and_canonicalize(
                source_family,
                is_authenticated_provider=is_authenticated_provider,
                permitted_families=permitted_families,
            )
            claim = ClaimType(claim_type)
            now = utc_now_iso()

            with self.db.session_scope() as session:
                # 1. Database-level coordination lock (TASK 5)
                # Acquires row-level lock on PostgreSQL (SELECT ... FOR UPDATE)
                # or database-level transaction lock on SQLite.
                coord = self.repo.acquire_domain_coordination(session, clean_domain, now)

                # 2. Fetch existing reports for this domain under coordination lock
                existing_entities = self.repo.find_community_reports(session, normalized_domain=clean_domain)

                # 3. Run deduplication and source lineage analysis
                dedup_res = self.deduplicator.analyze(
                    new_domain=clean_domain,
                    new_claim=claim,
                    new_reporter_hash=reporter_hash,
                    new_source_family=family,
                    existing_reports=existing_entities,
                    is_authenticated_provider=is_authenticated_provider,
                    permitted_families=permitted_families,
                )

                # Case A: Exact duplicate submission
                if dedup_res.category == DeduplicationCategory.EXACT_DUPLICATE:
                    assert dedup_res.matched_report_id is not None
                    existing_model = self.repo.get_community_report(session, dedup_res.matched_report_id)
                    assert existing_model is not None

                    # Log duplicate submission event for audit without inflating count
                    audit_event = ReportAuditEntry(
                        event_id=f"audit-{uuid.uuid4().hex[:10]}",
                        report_id=existing_model.report_id,
                        previous_state=existing_model.verification_state,
                        new_state=existing_model.verification_state,
                        action="duplicate_submission_absorbed",
                        reason=dedup_res.explanation,
                        actor_ref=f"reporter_hash:{reporter_hash[:12]}",
                        timestamp=now,
                    )
                    self.repo.save_audit_event(session, audit_event)
                    return existing_model, dedup_res

                # Determine initial state and handle conflicts
                initial_state = VerificationState.UNVERIFIED
                is_conflict = (
                    coord.is_disputed
                    or dedup_res.category == DeduplicationCategory.CONFLICTING_REPORT
                    or (coord.active_claim is not None and coord.active_claim != claim.value)
                )

                if is_conflict:
                    initial_state = VerificationState.DISPUTED
                    coord.is_disputed = True
                    for r_ent in existing_entities:
                        if r_ent.verification_state != VerificationState.DISPUTED.value:
                            self.repo.update_community_report_state(
                                session=session,
                                report_id=str(r_ent.report_id),
                                new_state=VerificationState.DISPUTED,
                                reviewed_at=now,
                            )
                            self.repo.save_audit_event(
                                session,
                                ReportAuditEntry(
                                    event_id=f"audit-{uuid.uuid4().hex[:10]}",
                                    report_id=str(r_ent.report_id),
                                    previous_state=VerificationState(r_ent.verification_state),
                                    new_state=VerificationState.DISPUTED,
                                    action="transition_to_disputed",
                                    reason=dedup_res.conflict_reason or f"Conflicting claim '{claim.value}' filed against domain",
                                    actor_ref="system_deduplicator",
                                    timestamp=now,
                                ),
                            )
                else:
                    if coord.active_claim is None:
                        coord.active_claim = claim.value

                # Persist new community report
                report_id = f"cr-{uuid.uuid4().hex[:10]}"
                report_model = CommunityReportModel(
                    report_id=report_id,
                    normalized_domain=clean_domain,
                    claim_type=claim,
                    note_redacted=clean_note,
                    submitted_at=now,
                    verification_state=initial_state,
                    independent_source_count=1,
                    linked_evidence_ids=linked_evidence_ids or [],
                    reviewed_at=now if initial_state == VerificationState.DISPUTED else None,
                )

                persisted = self.repo.save_community_report(
                    session=session,
                    report=report_model,
                    source_family=family,
                    reporter_hash=reporter_hash,
                )

                # Register distinct source family under database uniqueness constraint (TASK 5)
                # Guarantees identical source families never inflate counts across concurrent processes
                self.repo.register_domain_source_family(
                    session=session,
                    normalized_domain=clean_domain,
                    source_family=family,
                    report_id=report_id,
                    created_at=now,
                )

                # Authoritative calculation of distinct source families across domain
                distinct_family_count = max(
                    1, self.repo.count_distinct_source_families_for_domain(session, clean_domain)
                )

                # Synchronize authoritative independent_source_count across all reports for this domain
                self.repo.update_all_reports_independent_count(session, clean_domain, distinct_family_count)
                persisted.independent_source_count = distinct_family_count

                # Audit event for submission
                audit_event = ReportAuditEntry(
                    event_id=f"audit-{uuid.uuid4().hex[:10]}",
                    report_id=report_id,
                    previous_state=None,
                    new_state=initial_state,
                    action="submitted",
                    reason=dedup_res.explanation,
                    actor_ref=f"reporter_hash:{reporter_hash[:12]}",
                    timestamp=now,
                )
                self.repo.save_audit_event(session, audit_event)

                coord.updated_at = now
                return persisted, dedup_res

    def get_report(self, report_id: str) -> Optional[CommunityReportModel]:
        """Fetch community report by ID."""
        with self.db.session_scope() as session:
            return self.repo.get_community_report(session, report_id)

    def list_reports_for_domain(self, normalized_domain: str) -> List[CommunityReportModel]:
        """List all reports filed for a given domain."""
        clean_domain = normalized_domain.strip().lower()
        if clean_domain.endswith("."):
            clean_domain = clean_domain[:-1]
        with self.db.session_scope() as session:
            entities = self.repo.find_community_reports(session, normalized_domain=clean_domain)
            reports = []
            for e in entities:
                rep = self.repo.get_community_report(session, e.report_id)
                if rep:
                    reports.append(rep)
            return reports

    def transition_report_state(
        self,
        report_id: str,
        target_state: VerificationState,
        reason: str,
        actor_ref: str,
    ) -> CommunityReportModel:
        """Execute a validated state transition with an append-only audit event.
        
        Independent corroboration counts are strictly computed server-side
        from distinct verified source families. Client overrides are completely prohibited.
        """
        with self._lock:
            with self.db.session_scope() as session:
                current = self.repo.get_community_report(session, report_id)
                if not current:
                    raise KeyError(f"Community report '{report_id}' not found.")

                # Validate state transition rules
                validate_transition(current.verification_state, target_state)

                now = utc_now_iso()

                # Server-side derivation of independent source count using normalized registry
                reg_count = self.repo.count_distinct_source_families_for_domain(session, current.normalized_domain)
                if reg_count > 0:
                    derived_count = reg_count
                else:
                    entities = self.repo.find_community_reports(session, normalized_domain=current.normalized_domain)
                    distinct_families = {
                        SourceFamilyAnalyzer.canonicalize_family(e.source_family)
                        for e in entities
                        if (
                            e.verification_state != VerificationState.DISPUTED.value
                            and e.source_family is not None
                        )
                    }
                    derived_count = max(1, len(distinct_families))

                self.repo.update_community_report_state(
                    session=session,
                    report_id=report_id,
                    new_state=target_state,
                    independent_count=derived_count,
                    reviewed_at=now,
                )

                # Record audit event
                audit_event = ReportAuditEntry(
                    event_id=f"audit-{uuid.uuid4().hex[:10]}",
                    report_id=report_id,
                    previous_state=current.verification_state,
                    new_state=target_state,
                    action=f"transition_to_{target_state.value}",
                    reason=reason,
                    actor_ref=actor_ref,
                    timestamp=now,
                )
                self.repo.save_audit_event(session, audit_event)

                updated = self.repo.get_community_report(session, report_id)
                assert updated is not None
                return updated

    def get_audit_history(self, report_id: str) -> List[ReportAuditEntry]:
        """Retrieve chronological audit trail for a report."""
        with self.db.session_scope() as session:
            return self.repo.get_audit_events_for_report(session, report_id)
