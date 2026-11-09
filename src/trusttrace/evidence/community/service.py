"""Community intelligence intake, moderation, deduplication, and lifecycle service for Worker 02."""

import uuid
import threading
from typing import Dict, Any, List, Optional, Tuple
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
    ) -> Tuple[CommunityReportModel, DeduplicationResult]:
        """Intake a community report safely with deduplication and source-family validation.
        
        Returns:
            Tuple[CommunityReportModel, DeduplicationResult]
        """
        with self._lock:
            clean_domain = normalized_domain.strip().lower()
            clean_note = sanitize_text(note, max_length=1000)
            reporter_hash = hash_reporter_identity(raw_reporter_identifier)
            family = SourceFamilyAnalyzer.validate_and_canonicalize(
                source_family, is_authenticated_provider=is_authenticated_provider
            )
            claim = ClaimType(claim_type)
            now = utc_now_iso()

            with self.db.session_scope() as session:
                # 1. Fetch existing reports for this domain
                existing_entities = self.repo.find_community_reports(session, normalized_domain=clean_domain)

                # 2. Run deduplication and source lineage analysis
                dedup_res = self.deduplicator.analyze(
                    new_domain=clean_domain,
                    new_claim=claim,
                    new_reporter_hash=reporter_hash,
                    new_source_family=family,
                    existing_reports=existing_entities,
                    is_authenticated_provider=is_authenticated_provider,
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

                # Case B: Conflicting Report -> Marks both as DISPUTED
                initial_state = VerificationState.UNVERIFIED
                independent_count = 1

                if dedup_res.category == DeduplicationCategory.CONFLICTING_REPORT:
                    initial_state = VerificationState.DISPUTED
                    matched_id = dedup_res.matched_report_id
                    if matched_id:
                        matched_report = self.repo.get_community_report(session, matched_id)
                        if matched_report and matched_report.verification_state != VerificationState.DISPUTED:
                            self.repo.update_community_report_state(
                                session=session,
                                report_id=matched_id,
                                new_state=VerificationState.DISPUTED,
                                reviewed_at=now,
                            )
                            self.repo.save_audit_event(
                                session,
                                ReportAuditEntry(
                                    event_id=f"audit-{uuid.uuid4().hex[:10]}",
                                    report_id=matched_id,
                                    previous_state=matched_report.verification_state,
                                    new_state=VerificationState.DISPUTED,
                                    action="transition_to_disputed",
                                    reason=dedup_res.conflict_reason or "Conflicting claim filed",
                                    actor_ref="system_deduplicator",
                                    timestamp=now,
                                ),
                            )

                # Case C: Copied/Shared Source -> Does NOT increment independent count
                elif dedup_res.category == DeduplicationCategory.COPIED_SOURCE:
                    if existing_entities:
                        independent_count = int(existing_entities[0].independent_source_count)

                # Case D: Independent Source -> Increments independent count across domain reports
                elif dedup_res.category == DeduplicationCategory.INDEPENDENT_SOURCE:
                    # Calculate authoritative distinct canonical source families
                    existing_domain_entities = self.repo.find_community_reports(session, normalized_domain=clean_domain)
                    existing_families = {
                        SourceFamilyAnalyzer.canonicalize_family(str(e.source_family) if e.source_family is not None else None)
                        for e in existing_domain_entities
                    }
                    existing_families.add(family)
                    independent_count = len(existing_families)

                    # Update existing reports with authoritative independent count
                    for e in existing_domain_entities:
                        self.repo.update_community_report_state(
                            session=session,
                            report_id=str(e.report_id),
                            new_state=VerificationState(str(e.verification_state)),
                            independent_count=independent_count,
                        )

                # Persist new community report
                report_id = f"cr-{uuid.uuid4().hex[:10]}"
                report_model = CommunityReportModel(
                    report_id=report_id,
                    normalized_domain=clean_domain,
                    claim_type=claim,
                    note_redacted=clean_note,
                    submitted_at=now,
                    verification_state=initial_state,
                    independent_source_count=independent_count,
                    linked_evidence_ids=linked_evidence_ids or [],
                    reviewed_at=now if initial_state == VerificationState.DISPUTED else None,
                )

                persisted = self.repo.save_community_report(
                    session=session,
                    report=report_model,
                    source_family=family,
                    reporter_hash=reporter_hash,
                )

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

                return persisted, dedup_res

    def get_report(self, report_id: str) -> Optional[CommunityReportModel]:
        """Fetch community report by ID."""
        with self.db.session_scope() as session:
            return self.repo.get_community_report(session, report_id)

    def list_reports_for_domain(self, normalized_domain: str) -> List[CommunityReportModel]:
        """List all reports filed for a given domain."""
        clean_domain = normalized_domain.strip().lower()
        with self.db.session_scope() as session:
            entities = self.repo.find_community_reports(session, normalized_domain=clean_domain)
            reports = []
            for e in entities:
                rep = self.repo.get_community_report(session, str(e.report_id))
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

                # Server-side derivation of independent source count
                entities = self.repo.find_community_reports(session, normalized_domain=current.normalized_domain)
                distinct_families = {
                    SourceFamilyAnalyzer.canonicalize_family(str(e.source_family) if e.source_family is not None else None)
                    for e in entities
                    if str(e.verification_state) != VerificationState.DISPUTED.value
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
