# Worker 03 — Cross-Worker Policy Integration Specification

**Status:** COMPLETED & VERIFIED  
**Workstream:** Worker 03 (Risk Policy, Evidence Interpretation, Uncertainty & Claim Discipline)  
**Latest Git Commit:** `7817d74` (merged directly to `main`, pushed to `origin/main`)  
**Associated Reports:**  
- Full Audit: [`.brain/.report/worker_03_integration_audit.md`](file:///c:/Users/parin/Downloads/hacker%20matrix%20adamas/trusttrace/.brain/.report/worker_03_integration_audit.md)  
- Remediation Plan: [`.brain/.report/worker_03_integration_remediation_plan.md`](file:///c:/Users/parin/Downloads/hacker%20matrix%20adamas/trusttrace/.brain/.report/worker_03_integration_remediation_plan.md)  
- Completion Report: [`.brain/.report/worker_03_integration_completion_report.md`](file:///c:/Users/parin/Downloads/hacker%20matrix%20adamas/trusttrace/.brain/.report/worker_03_integration_completion_report.md)  

---

## 1. Objectives & Scope

This specification records all architectural interfaces, model bridges, error protections, and handoff contracts implemented by Worker 03 to enable clean, crash-free interoperability with Worker 01, Worker 02, and Worker 04.

---

## 2. Implemented Worker 03 Enhancements

### 2.1 Worker 02 Model Acceptance in `PolicyInput`
- **File:** `src/trusttrace/policy/policy_input.py`
- **Capability:** `PolicyInput.from_v1_dict()`, `EvidenceItem.from_dict()`, `CoverageSummary.from_dict()`, and `CommunityReportItem.from_dict()` automatically inspect and unwrap Worker 02 Pydantic models (`EvidenceModel`, `CoverageModel`, `CommunityReportModel`) by detecting `.to_v1_contract_dict()`, `.model_dump()`, or `.dict()`.
- **Factory:** Added `PolicyInput.from_components(scan_id, target, evidence, coverage, community_reports, scan_profile, strict)` allowing callers to pass heterogeneous lists of models or dictionaries directly.

### 2.2 Callsite Error Diagnostic & Factory in `SignalRecord`
- **File:** `src/trusttrace/policy/signal_taxonomy.py`
- **Diagnostic:** `SignalRecord.__post_init__()` provides clear, actionable guidance if a bare string is passed to `evidence_ids`:
  ```
  TypeError: evidence_ids must be a sequence of strings, not a bare string. Got bare string '...'.
  If calling positionally, the argument order is (kind, evidence_ids, source, ...).
  ```
- **Factory:** Added `SignalRecord.create(kind, source, evidence_ids, confidence, value, limitations)` enabling named-parameter construction that accepts either a single string ID or a sequence of IDs.

### 2.3 Multi-Type Ingestion in `TriageEngine`
- **File:** `src/trusttrace/policy/triage_engine.py`
- **Capability:** `TriageEngine.evaluate_evidence()` accepts a `PolicyInput`, a raw Python `dict`, or any model exporting `.model_dump()` / `.to_v1_contract_dict()`, routing it safely through validation, signal extraction, triage rules, uncertainty quantification, and report formatting.

### 2.4 Report Integrity Auditor
- **File:** `src/trusttrace/policy/integrity_auditor.py`
- **Capability:** Evaluates candidate reports against rules 1–6 (`INV-TLS-001`, `INV-EVID-002`, `INV-COV-001`, `INV-CLAIM-001`, `INV-FINDING-001`, `INV-COV-002`).

---

## 3. External Dependencies & Cross-Worker Handoffs

Worker 03 does NOT modify files owned by other workers. The required consumer fixes are:

### For Worker 04 (Web Presentation):
1. **DEF-01 (CRITICAL):** In `src/trusttrace/web/routes.py` (lines 42–45, 103–104, 152–155), correct `SignalRecord` callsites to pass keyword arguments or use `SignalRecord.create()`.
2. **DEF-02 (HIGH):** Create `tests/test_web_routes.py` covering `/api/v1/triage/demo` endpoints.
3. **DEF-03 (HIGH):** Connect custom URLs to `ScanOrchestrator` and `TriageEngine`.
4. **DEF-05 (LOW):** Expose `result.uncertainty` (confidence band and abstention notice) in UI responses.

### For Worker 02 (Evidence Persistence):
1. **DEF-04 (MEDIUM):** Hook `ReportIntegrityAuditor.audit_report()` into `EvidenceService` before finalizing or publishing report dictionaries.

---

## 4. Verification & Metrics

- **Unit Tests:** `tests/test_triage_policy.py` — **107 tests passing** (includes 10 dedicated integration tests in `Worker03IntegrationRemediationTests`).
- **Repository Runner:** `python run_tests.py` — **233 tests passing, 1 skipped, 0 failures**.
- **Worker Boundaries:** `python scripts/check_worker_boundaries.py --worker worker_03` — **PASS**.
- **Fixtures:** `python .brain/.work/contracts/v1/validate_fixtures.py` — **PASS**.
- **Git Diff Hygiene:** `git diff --check` — **PASS**.
