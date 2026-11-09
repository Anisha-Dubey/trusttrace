"""Moderation workflows and audit trail querying for Community Intelligence."""

import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy import select

from .state_machine import validate_transition
from .service import CommunityIntelligenceService
from ..domain.models import CommunityReportModel, ReportAuditEntry, utc_now_iso
from ..domain.enums import VerificationState
from ..persistence.database import DatabaseManager, default_db
from ..persistence.models import ReportAuditEntity, CommunityReportEntity


class ModerationService:
    """Provides privileged moderation actions and audit trail inspection."""

    def __init__(
        self,
        community_service: Optional[CommunityIntelligenceService] = None,
        db_manager: Optional[DatabaseManager] = None,
    ):
        self.db = db_manager or default_db
        self.community_service = community_service or CommunityIntelligenceService(db_manager=self.db)

    def review_report(
        self,
        report_id: str,
        target_state: VerificationState,
        reason: str,
        moderator_ref: str,
    ) -> CommunityReportModel:
        """Execute a formal moderator review action with audit logging.
        
        The independent corroboration count is strictly derived from server-side evidence
        and source identities; client overrides are completely prohibited.
        """
        if not reason or len(reason.strip()) < 5:
            raise ValueError("A formal moderation action requires an explanatory reason of at least 5 characters.")

        # Sanitize actor reference (prevent PII leakage)
        actor_name = moderator_ref.strip() if moderator_ref and moderator_ref.strip() else "system_moderator"
        safe_actor = f"moderator:{actor_name}"

        return self.community_service.transition_report_state(
            report_id=report_id,
            target_state=target_state,
            reason=reason.strip(),
            actor_ref=safe_actor,
        )

    def resolve_dispute(
        self,
        report_id: str,
        final_state: VerificationState,
        resolution_notes: str,
        moderator_ref: str,
    ) -> CommunityReportModel:
        """Resolve a report currently in DISPUTED state."""
        with self.db.session_scope() as session:
            current = self.community_service.repo.get_community_report(session, report_id)
            if not current:
                raise KeyError(f"Community report '{report_id}' not found.")
            if current.verification_state != VerificationState.DISPUTED:
                raise ValueError(f"Report '{report_id}' is in state '{current.verification_state.value}', not 'disputed'.")

        return self.review_report(
            report_id=report_id,
            target_state=final_state,
            reason=f"Dispute resolved: {resolution_notes}",
            moderator_ref=moderator_ref,
        )

    def get_audit_trail(self, report_id: str) -> List[ReportAuditEntry]:
        """Fetch the full chronological audit history for a single report."""
        return self.community_service.get_audit_history(report_id)

    def get_domain_audit_history(self, normalized_domain: str) -> List[ReportAuditEntry]:
        """Fetch all audit events associated with any report filed for the given domain."""
        clean_domain = normalized_domain.strip().lower()
        with self.db.session_scope() as session:
            report_ids = session.execute(
                select(CommunityReportEntity.report_id).where(
                    CommunityReportEntity.normalized_domain == clean_domain
                )
            ).scalars().all()

            if not report_ids:
                return []

            query = select(ReportAuditEntity).where(
                ReportAuditEntity.report_id.in_(report_ids)
            ).order_by(ReportAuditEntity.timestamp)
            entities = session.execute(query).scalars().all()

            return [
                ReportAuditEntry(
                    event_id=e.event_id,
                    report_id=e.report_id,
                    previous_state=VerificationState(e.previous_state) if e.previous_state else None,
                    new_state=VerificationState(e.new_state),
                    action=e.action,
                    reason=e.reason,
                    actor_ref=e.actor_ref,
                    timestamp=e.timestamp,
                )
                for e in entities
            ]
