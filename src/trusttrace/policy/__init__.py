"""Worker 03 — Explainable triage policy and controlled evaluation.

Modules:
- signal_taxonomy: Signal classification and dimension mapping
- triage_engine: Conservative deterministic policy engine
- decision_log: Versioned decision audit trail
- evaluation: Controlled evaluation set and claim audit
"""

from .signal_taxonomy import SignalKind, SignalRecord, DimensionAssessment
from .triage_engine import TriageEngine, TriageResult
from .decision_log import DecisionLogEntry, DecisionLog

__all__ = [
    "SignalKind",
    "SignalRecord",
    "DimensionAssessment",
    "TriageEngine",
    "TriageResult",
    "DecisionLogEntry",
    "DecisionLog",
]
