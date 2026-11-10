# worker_03 handoff

**Status: PHASES 01, 02, 03, 04 & CROSS-WORKER POLICY INTEGRATION COMPLETED.**

## Branch & Permitted Scope
- Branch: `main`
- Modules in `src/trusttrace/policy/`:
  - `policy_input.py` (canonical v1 evidence DTOs, Worker 02 Pydantic model support, `from_components()`)
  - `input_validation.py` (contract & scope validation)
  - `diagnostics.py` (structured diagnostic audit records)
  - `signal_taxonomy.py` (18 typed signals across 4 dimensions, `SignalRecord.create()` factory)
  - `signal_extractor.py` (deterministic evidence-to-signal extraction)
  - `triage_engine.py` (multi-type `evaluate_evidence()`, deterministic finding IDs, orphan suppression)
  - `uncertainty.py` (UncertaintyType, ConfidenceBand, FreshnessPolicy, AbstentionNotice, UncertaintyEngine)
  - `integrity_auditor.py` (ReportIntegrityAuditor enforcing rules 1-6 and anti-marketing guard)
  - `__init__.py` (public exports)
  - `tests/test_triage_policy.py` (107 tests passing)

## Contract Version
- Policy version: `w03-v1.0`
- Schema: `scan_report.schema.json` v1.0 (strict `additionalProperties: false`)
- Evidence schema: canonical v1 contracts from Worker 02

## Test Results
```
Worker 03 Tests: Ran 107 tests in 0.090s — OK (zero regressions, zero errors)
Full Repository: Ran 233 tests in 15.910s — OK (skipped=1)
All 8 schema/negative/cross-record fixture checks passed
```

## Worker 03 Public Interfaces & Integration Points

### 1. Canonical Evidence Evaluation (Primary Entrypoint for Worker 02 / Worker 04)
```python
from trusttrace.policy import PolicyInput, TriageEngine, TriageResult

# Option A: From dictionary (Worker 01 orchestrator output or JSON)
policy_input = PolicyInput.from_v1_dict(raw_scan_dict, strict=True)

# Option B: From Worker 02 Pydantic models (EvidenceModel list + CoverageModel)
policy_input = PolicyInput.from_components(
    scan_id="scan-001",
    target="example.com",
    evidence=[evidence_model_1, evidence_model_2],
    coverage=coverage_model,
)

# Run full validation, signal extraction, triage evaluation, and uncertainty quantification
engine = TriageEngine()
triage_result: TriageResult = engine.evaluate_evidence(policy_input)  # Also accepts raw dict directly!

# Extract report fragment mergeable into scan_report.schema.json
report_fragment = triage_result.to_report_fragment()
```

### 2. Signal Construction (Safe Callsites)
```python
from trusttrace.policy import SignalRecord, SignalKind

# Option A: Keyword arguments (Recommended to prevent positional transposition)
sig = SignalRecord(
    kind=SignalKind.TLS_VALID,
    evidence_ids=["ev-demo-01"],
    source="tls_collector",
    value="Valid DV Cert",
)

# Option B: Named factory helper
sig = SignalRecord.create(
    kind=SignalKind.TLS_VALID,
    source="tls_collector",
    evidence_ids=["ev-demo-01"],  # Accepts single string or list of strings
    value="Valid DV Cert",
)
```

### 3. Uncertainty & Abstention Rationales
```python
# Access structured uncertainty assessment
uncertainty = triage_result.uncertainty
print(uncertainty.confidence_band)  # e.g. ConfidenceBand.SUFFICIENT_FOR_SCOPED_OBSERVATION, LIMITED_OBSERVATION
if uncertainty.abstention_notice:
    print(uncertainty.abstention_notice.reason_code)       # e.g. ABSTAIN_COLLECTION_FAILURE
    print(uncertainty.abstention_notice.is_rescan_recommended)  # True/False
    print(uncertainty.abstention_notice.explanation)
```

### 4. Automated Report Integrity Audit (Pre-Publication Gate for Worker 02)
```python
from trusttrace.policy import ReportIntegrityAuditor

auditor = ReportIntegrityAuditor()
audit_result = auditor.audit_report(report_dict)
if not audit_result.is_valid:
    for issue in audit_result.issues:
        print(issue.rule_id, issue.severity, issue.affected_field, issue.explanation)
```

## Cross-Worker Remediation Requirements (Action Items for other workers)

### For Worker 04 (Web Frontend & Presentation):
- **DEF-01 (CRITICAL):** Update `SignalRecord` callsites in `src/trusttrace/web/routes.py` lines 42–45, 103–104, 152–155 to use keyword arguments or `SignalRecord.create()`.
- **DEF-02 (HIGH):** Create `tests/test_web_routes.py` to provide automated test coverage for web endpoints.
- **DEF-03 (HIGH):** Connect custom URL evaluation in `routes.py` to the real `ScanOrchestrator` and `TriageEngine` rather than hardcoding fake signals.
- **DEF-05 (LOW):** Include `result.uncertainty.to_dict()` in the JSON response and render the confidence band badge and abstention notice banner in HTML templates.

### For Worker 02 (Evidence & Persistence):
- **DEF-04 (MEDIUM):** Hook `ReportIntegrityAuditor().audit_report(report)` into `EvidenceService` before finalizing or publishing report dictionaries.
