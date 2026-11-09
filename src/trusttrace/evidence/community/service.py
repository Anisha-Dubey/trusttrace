"""Community intelligence intake, moderation, and lifecycle service for Worker 02."""

import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from .sanitizer import sanitize_text, hash_reporter_identity
from .state_machine import validate_transition, InvalidStateTransitionError
from ..domain.models import CommunityReportModel, ReportAuditEntry, utc_now_iso
from ..domain.enums import VerificationState, ClaimType
from ..persistence.database import DatabaseManager, default_db
from ..persistence.repository import EvidenceRepository
from ..persistence.models import CommunityReportEntity


class CommunityIntelligenceService:
    """Manages the full trustworthy lifecycle of community reports."""

    def __init__(
        self,
        repository: Optional[EvidenceRepository] = None,
        db_manager: Optional[DatabaseManager] = None,
    ):
        self.db = db_manager or default_db
        self.repo = repository or EvidenceRepository(db_manager=self.db)
        self.repo.init_tables()

    def submit_report(
        self,
        normalized_domain: str,
        claim_type: str,
        note: Optional[str] = "",
        raw_reporter_identifier: str = "anonymous",
        source_family: Optional[str] = None,
        linked_evidence_ids: Optional[List[str]] = None,
    ) -> CommunityReportModel:
        """Intake a community report safely.
        
        Enforces:
        - Sanitization against XSS/HTML injections (COMM-004)
        - Salted hashing of reporter ID (DATA-002)
        - Initial verification_state strictly defaults to UNVERIFIED
        - Independent source count defaults to 1
        """
        clean_domain = normalized_domain.strip().lower()
        clean_note = sanitize_text(note, max_length=1000)
        reporter_hash = hash_reporter_identity(raw_reporter_identifier)
        family = source_family.strip().lower() if source_family else "community_user"
        claim = ClaimType(claim_type)

        report_id = f"cr-{uuid.uuid4().hex[:10]}"
        now = utc_now_iso()

        report_model = CommunityReportModel(
            report_id=report_id,
            normalized_domain=clean_domain,
            claim_type=claim,
            note_redacted=clean_note,
            submitted_at=now,
            verification_state=VerificationState.UNVERIFIED,
            independent_source_count=1,
            linked_evidence_ids=linked_evidence_ids or [],
            reviewed_at=None,
        )

        with self.db.session_scope() as session:
            # Persist report
            persisted = self.repo.save_community_report(
                session=session,
                report=report_model,
                source_family=family,
                reporter_hash=reporter_hash,
            )

            # Record creation audit event
            audit_event = ReportAuditEntry(
                event_id=f"audit-{uuid.uuid4().hex[:10]}",
                report_id=report_id,
                previous_state=None,
                new_state=VerificationState.UNVERIFIED,
                action="submitted",
                reason="Initial community report submission",
                actor_ref=f"reporter_hash:{reporter_hash[:12]}",
                timestamp=now,
            )
            self.repo.save_audit_event(session, audit_event)

            return persisted

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
        independent_count: Optional[int] = None,
    ) -> CommunityReportModel:
        """Execute a validated state transition with an append-only audit event."""
        with self.db.session_scope() as session:
            current = self.repo.get_community_report(session, report_id)
            if not current:
                raise KeyError(f"Community report '{report_id}' not found.")

            # Validate state transition rules
            validate_transition(current.verification_state, target_state)

            now = utc_now_iso()
            self.repo.update_community_report_state(
                session=session,
                report_id=report_id,
                new_state=target_state,
                independent_count=independent_count,
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
