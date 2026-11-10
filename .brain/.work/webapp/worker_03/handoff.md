# worker_03 handoff

**Status: PHASES 01, 02, 03 & 04 COMPLETED — READY FOR INTEGRATION.**

## Branch & Permitted Scope
- Branch: `main`
- Modules in `src/trusttrace/policy/`:
  - `policy_input.py` (canonical v1 evidence DTOs, MappingProxyType immutability)
  - `input_validation.py` (contract & scope validation)
  - `diagnostics.py` (structured diagnostic audit records)
  - `signal_taxonomy.py` (18 typed signals across 4 dimensions, 6-value SignalConfidence)
  - `signal_extractor.py` (deterministic evidence-to-signal extraction)
  - `triage_engine.py` (deterministic rule composition, evaluate_evidence, deterministic finding IDs)
  - `uncertainty.py` (UncertaintyType, ConfidenceBand, FreshnessPolicy, AbstentionNotice, UncertaintyEngine)
  - `integrity_auditor.py` (ReportIntegrityAuditor enforcing rules 1-6 and anti-marketing guard)
  - `__init__.py` (public exports)
  - `tests/test_triage_policy.py` (94 tests passing in 0.010s)

## Contract Version
- Policy version: `w03-v1.0`
- Schema: `scan_report.schema.json` v1.0 (strict `additionalProperties: false`)
- Evidence schema: canonical v1 contracts from Worker 02

## Test Results
```
Worker 03 Tests: Ran 94 tests in 0.010s — OK (zero regressions, zero errors)
Full Repository: Ran 220 tests in 14.332s — OK (skipped=1)
All 8 schema/negative/cross-record fixture checks passed
```

## Worker 03 Public Interfaces & Integration Points

### 1. Canonical Evidence Evaluation (Primary Entrypoint for Worker 02 / Worker 04)
```python
from trusttrace.policy import PolicyInput, TriageEngine, TriageResult

# Parse canonical v1 dictionary (from Worker 02 or orchestrator)
policy_input = PolicyInput.from_v1_dict(raw_scan_dict, strict=True)

# Run full validation, signal extraction, triage evaluation, and uncertainty quantification
engine = TriageEngine()
triage_result: TriageResult = engine.evaluate_evidence(policy_input)

# Extract report fragment mergeable into scan_report.schema.json
report_fragment = triage_result.to_report_fragment()
# Output structure:
# {
#     "decision": "high_risk" | "caution" | "no_threat_observed" | "inconclusive" | "failed",
#     "policy_version": "w03-v1.0",
#     "dimensions": {"identity": ..., "certificate": ..., "behavior": ..., "evidence_quality": ...},
#     "findings": [...],
#     "limitations": [...]
# }
```

### 2. Uncertainty & Abstention Rationales
```python
# Access structured uncertainty assessment
uncertainty = triage_result.uncertainty
print(uncertainty.confidence_band)  # ConfidenceBand.SUFFICIENT_FOR_SCOPED_OBSERVATION, LIMITED_OBSERVATION, etc.
if uncertainty.abstention_notice:
    print(uncertainty.abstention_notice.reason_code)       # e.g. ABSTAIN_COLLECTION_FAILURE
    print(uncertainty.abstention_notice.is_rescan_recommended)  # True/False
    print(uncertainty.abstention_notice.explanation)
```

### 3. Automated Report Integrity Audit (Pre-Publication Gate)
```python
from trusttrace.policy import ReportIntegrityAuditor

auditor = ReportIntegrityAuditor()
# Audits candidate scan report dict against TLS-001, EVID-002, COV-001, CLAIM-001, FINDING-001, COV-002:
audit_result = auditor.audit_report(report_dict)
if not audit_result.is_valid:
    for issue in audit_result.issues:
        print(issue.rule_id, issue.severity, issue.affected_field, issue.explanation)
```

### 4. Diagnostics & Auditability
```python
diagnostics = triage_result.diagnostics
for diag in diagnostics:
    print(diag.code, diag.severity, diag.message, diag.evidence_ids, diag.action_taken)
```

## Cross-Worker Coordination Requirements

### For Worker 02 (Evidence & Persistence):
- **Pre-Publication Integrity Audit**: Run `ReportIntegrityAuditor().audit_report(report)` before saving or publishing completed scan reports to prevent contract violations or marketing claim breaches.
- **Stable Finding IDs**: Findings returned in `triage_result.findings` use stable SHA-256 deterministic IDs (`finding-{hash}`).
- **Orphan Prevention**: Findings strictly reference valid input evidence IDs.

### For Worker 04 (UI & Presentation):
- **Transparent Dimension Breakdown**: Render `dimensions` dictionary (identity, certificate, behavior, evidence_quality) and `rule_trace` rationale parts.
- **Diagnostic Limitations & Abstentions**: Display `limitations` prominently to explain conservative ceilings, coverage deficits, or explicit abstention reasons.
- **Ordinal Confidence Display**: Display qualitative `ConfidenceBand` badge (never fabricate a percentage score or probability).

## Known Limitations
- The engine uses conservative deterministic rule trees; it does not compute statistical ML probabilities.
- Coverage completeness is evaluated at aggregate record level; Worker 02 does not currently expose named per-check metadata.
