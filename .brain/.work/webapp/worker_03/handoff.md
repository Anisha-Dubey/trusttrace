# worker_03 handoff

**Status: PHASE 03 COMPLETED — READY FOR INTEGRATION.**

## Branch & Permitted Scope
- Branch: `worker-03/phase-03-evidence-bridge`
- Files changed/created in Phase 03:
  - `src/trusttrace/policy/policy_input.py` (new)
  - `src/trusttrace/policy/input_validation.py` (new)
  - `src/trusttrace/policy/diagnostics.py` (new)
  - `src/trusttrace/policy/signal_taxonomy.py` (enhanced)
  - `src/trusttrace/policy/signal_extractor.py` (new)
  - `src/trusttrace/policy/triage_engine.py` (enhanced)
  - `src/trusttrace/policy/__init__.py` (updated)
  - `tests/test_triage_policy.py` (extended with 40 new tests)
  - `.brain/.work/webapp/worker_03/phases/phase_03.md` (new)
  - `.brain/.report/worker_03_phase_03_report.md` (new)
  - `.brain/.work/webapp/worker_03/status.md` (updated)
  - `.brain/.work/webapp/worker_03/handoff.md` (updated)

## Contract Version
- Policy version: `w03-v1.0`
- Schema: `scan_report.schema.json` v1.0
- Evidence schema: canonical v1 contracts from Worker 02

## Test Results
```
Ran 69 tests in 0.007s — OK (zero regressions, zero errors)
```

## Worker 03 Public Interfaces & Integration Points

### 1. Canonical Evidence Evaluation (Primary Entrypoint for Worker 02 / Worker 04)
```python
from trusttrace.policy import PolicyInput, TriageEngine, TriageResult

# Parse canonical v1 dictionary (from Worker 02 or orchestrator)
policy_input = PolicyInput.from_v1_dict(raw_scan_dict, strict=True)

# Run full validation, signal extraction, and triage evaluation
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

### 2. Diagnostics & Auditability
```python
# Access structured diagnostics generated during validation, extraction, or suppression
diagnostics = triage_result.diagnostics
for diag in diagnostics:
    print(diag.code, diag.severity, diag.message, diag.evidence_ids, diag.action_taken)
```

### 3. Direct Signal Evaluation (Legacy / Worker 01 / Unit Testing Entrypoint)
```python
# Existing evaluate(signals) remains 100% backward-compatible:
result = engine.evaluate(signals, scan_id=scan_id)
```

## Cross-Worker Coordination Requirements

### For Worker 02 (Evidence & Persistence):
- **Input formatting**: Worker 02 can pass canonical dictionaries containing `scan_id`, `target` (or `normalized_host`), `evidence` (list of canonical evidence dicts), `coverage` (dict with `checks_total`, `checks_observed`, `checks_failed`, `checks_not_run`), and optional `community_reports`.
- **Finding IDs**: Findings returned in `triage_result.findings` use stable SHA-256 deterministic IDs (`finding-{hash}`). They are ready for database insertion via Worker 02 repository without ID generation conflicts.
- **Orphan Prevention**: Findings strictly reference valid input evidence IDs.

### For Worker 04 (UI & Presentation):
- **Transparent Dimension Breakdown**: Render `dimensions` dictionary (identity, certificate, behavior, evidence_quality) and `rule_trace` rationale parts.
- **Diagnostic Limitations**: Display `limitations` prominently to explain conservative ceilings, coverage deficits, or unverified community reports.
- **Explainability**: No hidden probabilities or opaque scores; all decisions cite named rules and evidence IDs.

## Known Limitations
- The engine uses conservative deterministic rule trees; it does not compute statistical ML probabilities.
- Coverage completeness is evaluated at aggregate record level; Worker 02 does not currently expose named per-check metadata.
