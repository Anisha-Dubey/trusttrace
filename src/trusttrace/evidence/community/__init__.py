"""Community intelligence module exports."""

from .sanitizer import sanitize_text, hash_reporter_identity
from .state_machine import validate_transition, InvalidStateTransitionError, ALLOWED_TRANSITIONS
from .deduplicator import (
    ReportDeduplicator,
    SourceFamilyAnalyzer,
    DeduplicationCategory,
    DeduplicationResult,
)
from .service import CommunityIntelligenceService
from .moderation import ModerationService

__all__ = [
    "sanitize_text",
    "hash_reporter_identity",
    "validate_transition",
    "InvalidStateTransitionError",
    "ALLOWED_TRANSITIONS",
    "ReportDeduplicator",
    "SourceFamilyAnalyzer",
    "DeduplicationCategory",
    "DeduplicationResult",
    "CommunityIntelligenceService",
    "ModerationService",
]
