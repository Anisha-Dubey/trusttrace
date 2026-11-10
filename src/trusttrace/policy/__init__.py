"""Worker 03 — Explainable triage policy, evidence bridge, uncertainty, and report integrity.

Modules:
- policy_input: Canonical v1 evidence, coverage, and policy input DTOs
- input_validation: Structural and contract validation prior to triage
- diagnostics: Structured diagnostic records and policy suppression auditing
- signal_taxonomy: Typed signal classification, dimensions, and ordinal confidence
- signal_extractor: Deterministic evidence-to-signal extraction pipeline
- triage_engine: Conservative deterministic policy engine and evidence triage
- uncertainty: Uncertainty taxonomy, ordinal confidence bands, freshness, and abstention
- integrity_auditor: Automated report invariant auditor and anti-marketing guard
- decision_log: Versioned decision audit trail and serializable audit records
- evaluation: Controlled evaluation set, versioned suites, and claim audit
- regression: Deterministic policy-version regression runner and diff reporting
"""

from .decision_log import DecisionAuditRecord, DecisionLog, DecisionLogEntry
from .diagnostics import (
    DiagnosticCode,
    DiagnosticCollector,
    DiagnosticRecord,
    DiagnosticSeverity,
)
from .evaluation import (
    FIXTURES_V1,
    FIXTURES_V2,
    ClaimAuditEntry,
    ClaimAuditor,
    ClaimCategory,
    ClaimVerdict,
    ControlledEvaluationSet,
    EvaluationFixture,
    EvaluationResult,
    EvaluationSummary,
    FixtureLabel,
    build_eval_v1_set,
    build_eval_v2_set,
)
from .input_validation import EvidenceValidator, ValidationIssue, ValidationResult
from .integrity_auditor import (
    AuditIssue,
    AuditRuleId,
    AuditSeverity,
    ReportAuditResult,
    ReportIntegrityAuditor,
)
from .policy_input import (
    CommunityReportItem,
    CoverageSummary,
    EvidenceItem,
    ParseIssue,
    PolicyInput,
    PolicyInputParseError,
)
from .regression import PolicyRegressionRunner, RegressionDiffReport
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
from .uncertainty import (
    DEFAULT_FRESHNESS_WINDOWS,
    AbstentionNotice,
    ConfidenceBand,
    FreshnessPolicy,
    UncertaintyAssessment,
    UncertaintyEngine,
    UncertaintyRecord,
    UncertaintyType,
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
    # Uncertainty & Abstention (Phase 04)
    "UncertaintyType",
    "ConfidenceBand",
    "FreshnessPolicy",
    "DEFAULT_FRESHNESS_WINDOWS",
    "UncertaintyRecord",
    "AbstentionNotice",
    "UncertaintyAssessment",
    "UncertaintyEngine",
    # Integrity Auditor (Phase 04)
    "AuditSeverity",
    "AuditRuleId",
    "AuditIssue",
    "ReportAuditResult",
    "ReportIntegrityAuditor",
    # Decision Log & Audit Records
    "DecisionLogEntry",
    "DecisionLog",
    "DecisionAuditRecord",
    # Evaluation Suites & Claim Audit (Phase 02 & Phase 05)
    "EvaluationFixture",
    "EvaluationResult",
    "EvaluationSummary",
    "ControlledEvaluationSet",
    "ClaimAuditor",
    "ClaimAuditEntry",
    "ClaimCategory",
    "ClaimVerdict",
    "FixtureLabel",
    "FIXTURES_V1",
    "FIXTURES_V2",
    "build_eval_v1_set",
    "build_eval_v2_set",
    # Policy Regression (Phase 05)
    "PolicyRegressionRunner",
    "RegressionDiffReport",
]
