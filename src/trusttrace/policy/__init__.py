"""Worker 03 — Explainable triage policy, evidence bridge, and controlled evaluation.

Modules:
- policy_input: Canonical v1 evidence, coverage, and policy input DTOs
- input_validation: Structural and contract validation prior to triage
- diagnostics: Structured diagnostic records and policy suppression auditing
- signal_taxonomy: Typed signal classification, dimensions, and ordinal confidence
- signal_extractor: Deterministic evidence-to-signal extraction pipeline
- triage_engine: Conservative deterministic policy engine and evidence triage
- decision_log: Versioned decision audit trail
- evaluation: Controlled evaluation set and claim audit
"""

from .decision_log import DecisionLog, DecisionLogEntry
from .diagnostics import (
    DiagnosticCode,
    DiagnosticCollector,
    DiagnosticRecord,
    DiagnosticSeverity,
)
from .input_validation import EvidenceValidator, ValidationIssue, ValidationResult
from .policy_input import (
    CommunityReportItem,
    CoverageSummary,
    EvidenceItem,
    ParseIssue,
    PolicyInput,
    PolicyInputParseError,
)
from .signal_extractor import EvidenceSignalExtractor, SignalExtractionResult
from .signal_taxonomy import (
    DimensionAssessment,
    SIGNAL_DIMENSION_MAP,
    SignalConfidence,
    SignalDimension,
    SignalKind,
    SignalRecord,
    normalize_signal_confidence,
)
from .triage_engine import (
    POLICY_VERSION,
    RuleResult,
    TriageEngine,
    TriageResult,
    generate_deterministic_finding_id,
)

__all__ = [
    # Signal Taxonomy
    "SignalKind",
    "SignalRecord",
    "SignalConfidence",
    "SignalDimension",
    "DimensionAssessment",
    "SIGNAL_DIMENSION_MAP",
    "normalize_signal_confidence",
    # Policy Input DTOs
    "PolicyInput",
    "EvidenceItem",
    "CoverageSummary",
    "CommunityReportItem",
    "ParseIssue",
    "PolicyInputParseError",
    # Input Validation
    "EvidenceValidator",
    "ValidationResult",
    "ValidationIssue",
    # Diagnostics
    "DiagnosticCode",
    "DiagnosticSeverity",
    "DiagnosticRecord",
    "DiagnosticCollector",
    # Signal Extraction
    "EvidenceSignalExtractor",
    "SignalExtractionResult",
    # Triage Engine
    "TriageEngine",
    "TriageResult",
    "RuleResult",
    "POLICY_VERSION",
    "generate_deterministic_finding_id",
    # Decision Log
    "DecisionLogEntry",
    "DecisionLog",
]
