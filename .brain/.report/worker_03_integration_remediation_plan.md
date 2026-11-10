# TRUSTTRACE — CROSS-WORKER INTEGRATION REMEDIATION PLAN

**Date:** 2026-11-10
**Author:** Worker 03 (Risk Policy, Evidence Interpretation, Uncertainty & Claim Discipline)
**Status:** In Progress / Partially Remediated (Worker 03 side completed; Worker 02 and Worker 04 handoffs defined)
**Target Repository:** `C:\Users\parin\Downloads\hacker matrix adamas\trusttrace`
**Current Commit:** `3a3c2e5` (with Worker 03 local boundary-compliant enhancements)

---

## 1. Overview and Defect Inventory

The Cross-Worker Integration Audit identified 5 system-wide integration defects across Worker 02, Worker 03, and Worker 04. In accordance with strict worker boundary isolation, Worker 03 has completed all internal API strengthening and regression testing, and prepared explicit implementation handoffs for Worker 02 and Worker 04.

| Defect ID | Severity | Owner | Target Component / File | Current Status |
| :--- | :--- | :--- | :--- | :--- |
| **DEF-01** | **CRITICAL** | **Worker 04** | `src/trusttrace/web/routes.py` (lines 42–45, 103–104, 152–155) | **BLOCKED on Worker 04** (Handoff prepared; Worker 03 reinforced error messaging and added `SignalRecord.create()`) |
| **DEF-02** | **HIGH** | **Worker 04** | `tests/test_web_routes.py` (missing test suite) | **BLOCKED on Worker 04** (Handoff prepared) |
| **DEF-03** | **HIGH** | **Worker 04** | `src/trusttrace/web/routes.py` (demo vs real pipeline) | **BLOCKED on Worker 04** (Handoff prepared) |
| **DEF-04** | **MEDIUM** | **Worker 02** | `src/trusttrace/evidence/services/evidence_service.py` | **BLOCKED on Worker 02** (Handoff prepared; Worker 03 verified auditor integration) |
| **DEF-05** | **LOW** | **Worker 04** | `src/trusttrace/web/routes.py` & templates | **BLOCKED on Worker 04** (Handoff prepared) |

---

## 2. Worker 03 Remediation Actions Completed

To eliminate integration friction and prevent downstream crashes, Worker 03 has completed the following enhancements within `src/trusttrace/policy/`:

1. **Worker 02 Model Acceptance in `PolicyInput`:**
   - Modified `EvidenceItem.from_dict()`, `CoverageSummary.from_dict()`, `CommunityReportItem.from_dict()`, and `PolicyInput.from_v1_dict()` to natively unwrap Pydantic models (via `.to_v1_contract_dict()`, `.model_dump()`, or `.dict()`).
   - Added classmethod `PolicyInput.from_components(scan_id, target, evidence, coverage, community_reports, scan_profile, strict)` allowing callers to pass heterogeneous lists of `EvidenceModel` or dicts without manual conversion.
2. **Helpful Callsite Diagnostics in `SignalRecord`:**
   - Updated `SignalRecord.__post_init__()` to explicitly diagnose bare-string `evidence_ids`:
     ```
     TypeError: evidence_ids must be a sequence of strings, not a bare string. Got bare string '...'.
     If calling positionally, the argument order is (kind, evidence_ids, source, ...).
     ```
   - Added `SignalRecord.create(kind, source, evidence_ids, confidence, value, limitations)` convenience factory.
3. **Multi-Type Acceptance in `TriageEngine.evaluate_evidence()`:**
   - Enhanced `evaluate_evidence()` to accept a `PolicyInput`, a raw `Mapping[str, Any]`, or any Pydantic model with `.model_dump()` / `.to_v1_contract_dict()`.
4. **Regression Verification:**
   - Added `Worker03IntegrationRemediationTests` in `tests/test_triage_policy.py` (5 new integration tests).
   - Test suite expanded from 97 to 102 tests in `test_triage_policy.py` (all passing).
   - Full repository test runner: 228 passing tests (0 failures, 1 skipped).

---

## 3. Cross-Worker Defect Specifications and Handoffs

### 3.1 DEF-01: Positional Argument Transposition in Web Consumer
- **Owner:** Worker 04 (Web Frontend & Presentation)
- **Target File:** `src/trusttrace/web/routes.py`
- **Target Functions:** `triage_demo_endpoint` (lines 42–45, 103–104, 152–155)
- **Root Cause:**
  Worker 04 invokes `SignalRecord` with three positional arguments:
  ```python
  # BROKEN:
  SignalRecord(SignalKind.TLS_VALID, "tls_collector", "Valid DV Cert by Let's Encrypt")
  ```
  Positional parameter 2 in `SignalRecord` is `evidence_ids: List[str]`, and parameter 3 is `source: str`. Passing string `"tls_collector"` triggers `TypeError: evidence_ids must be a sequence of strings, not a bare string` during `__post_init__` validation.
- **Required Correction:**
  Invoke `SignalRecord` using explicit keyword arguments or the `SignalRecord.create()` factory:
  ```python
  # Option A: Keyword arguments (Recommended)
  SignalRecord(
      kind=SignalKind.TLS_VALID,
      evidence_ids=["ev-demo-tls-001"],
      source="tls_collector",
      value="Valid DV Cert by Let's Encrypt",
  )

  # Option B: Factory helper
  SignalRecord.create(
      kind=SignalKind.TLS_VALID,
      source="tls_collector",
      evidence_ids=["ev-demo-tls-001"],
      value="Valid DV Cert by Let's Encrypt",
  )
  ```
- **Acceptance Criteria:**
  - POST requests to `/api/v1/triage/demo` with `scenario="phishing_lookalike"`, `scenario="expired_tls"`, and custom URL succeed with HTTP 200 without raising `TypeError`.
- **Dependencies:** None. Worker 03 interface is ready.

### 3.2 DEF-02: Missing Web Route Test Coverage
- **Owner:** Worker 04 (Web Frontend & Presentation)
- **Target File:** `tests/test_web_routes.py` (to be created)
- **Root Cause:**
  `tests/` contains no test files exercising `src/trusttrace/web/routes.py`. As a result, critical runtime exceptions like DEF-01 went undetected by CI/automated runners.
- **Required Correction:**
  Create `tests/test_web_routes.py` using `fastapi.testclient.TestClient`.
- **Suggested Test Cases:**
  1. `test_demo_scenario_legitimate`: POST `scenario="legitimate"` returns HTTP 200 and matches fixture.
  2. `test_demo_scenario_phishing_lookalike`: POST `scenario="phishing_lookalike"` returns HTTP 200, decision=`caution`, and valid findings.
  3. `test_demo_scenario_expired_tls`: POST `scenario="expired_tls"` returns HTTP 200, decision=`inconclusive` or `caution`.
  4. `test_demo_scenario_conflicting`: POST `scenario="conflicting"` returns HTTP 200.
  5. `test_demo_custom_url_validation`: POST with custom valid URL returns HTTP 200.
  6. `test_demo_custom_url_ssrf_rejection`: POST with loopback IP returns canonical rejection report.
- **Acceptance Criteria:**
  - `python -m unittest tests.test_web_routes -v` passes completely.
- **Dependencies:** DEF-01 must be fixed first.

### 3.3 DEF-03: Web UI Disconnected from Real Backend Pipeline
- **Owner:** Worker 04 (in coordination with Worker 01 and Worker 02)
- **Target File:** `src/trusttrace/web/routes.py` (custom URL triage endpoint)
- **Root Cause:**
  When evaluating custom URLs, Worker 04 checks `IntakeBoundary.evaluate_url()`, but if valid, synthesizes four hardcoded mock signals rather than triggering Worker 01 collectors and Worker 02 persistence.
- **Required Correction:**
  Wire the custom URL triage path through the existing orchestrator and service:
  ```python
  orchestrator = ScanOrchestrator()
  scan_report = orchestrator.run_scan(scan_id=scan_id, raw_url=url)
  policy_input = PolicyInput.from_v1_dict(scan_report, strict=False)
  triage_result = TriageEngine().evaluate_evidence(policy_input)
  ```
- **Acceptance Criteria:**
  - Live scans run passive bounded collectors (DNS, TLS, HTTP) safely under `IntakeBoundary`.
  - Live observations are translated into real policy signals rather than fabricated static strings.
- **Dependencies:** DEF-01, Worker 01 `ScanOrchestrator`, Worker 03 `TriageEngine`.

### 3.4 DEF-04: Worker 02 Pre-Publication Integrity Audit Hook
- **Owner:** Worker 02 (Evidence Ingestion & Persistence)
- **Target File:** `src/trusttrace/evidence/services/evidence_service.py`
- **Target Function:** `EvidenceService.ingest_batch()` / `EvidenceService.get_scan_report()`
- **Root Cause:**
  Worker 02 persists evidence and computes coverage, but does not invoke `ReportIntegrityAuditor.audit_report()` prior to report finalization or publication via `/api/v1/scans/{scan_id}`.
- **Required Correction:**
  In `EvidenceService`, import `ReportIntegrityAuditor` from `trusttrace.policy.integrity_auditor` and audit candidate report dictionaries prior to publication:
  ```python
  from trusttrace.policy.integrity_auditor import ReportIntegrityAuditor

  auditor = ReportIntegrityAuditor()
  audit_result = auditor.audit_report(candidate_report_dict)
  if not audit_result.is_valid:
      logger.warning(f"Scan {scan_id} failed integrity audit: {audit_result.issues}")
  ```
- **Acceptance Criteria:**
  - Reports published by Worker 02 pass all AUDIT-001 through AUDIT-010 invariant rules.
- **Dependencies:** None. `ReportIntegrityAuditor` is fully tested and ready in Worker 03.

### 3.5 DEF-05: Expose Uncertainty and Abstention in Web UI
- **Owner:** Worker 04 (Web Frontend & Presentation)
- **Target Files:** `src/trusttrace/web/routes.py` and template HTML files
- **Root Cause:**
  Worker 03's Phase 04 added `TriageResult.uncertainty` (containing `confidence_band`, `epistemic_reasons`, and `abstention_notice`). Worker 04 currently discards this field and returns only `decision`, `dimensions`, and `findings`.
- **Required Correction:**
  In `routes.py`, include `result.uncertainty.to_dict()` in the JSON response:
  ```python
  response_payload["uncertainty"] = {
      "confidence_band": result.uncertainty.confidence_band.value,
      "summary": result.uncertainty.summary,
      "abstention_notice": (
          result.uncertainty.abstention_notice.to_dict()
          if result.uncertainty.abstention_notice else None
      ),
  }
  ```
- **Acceptance Criteria:**
  - Frontend dashboard visually renders the confidence band badge and human-readable abstention warning banner when present.
- **Dependencies:** DEF-01.

---

## 4. Definition of Done & Release Gate Criteria

The TrustTrace application will be declared **Ready for Release** only when all of the following conditions are satisfied:
1. [x] **Worker 03 Policy Hardening:** `PolicyInput`, `SignalRecord`, `TriageEngine`, `UncertaintyEngine`, and `ReportIntegrityAuditor` pass 100% of unit and integration tests (102/102 PASS).
2. [ ] **Worker 04 Defect DEF-01 Resolved:** All `SignalRecord` callsites in `routes.py` fixed; `/api/v1/triage/demo` returns HTTP 200 across all scenarios.
3. [ ] **Worker 04 Test Suite DEF-02 Implemented:** Comprehensive test suite in `tests/test_web_routes.py` passing in `run_tests.py`.
4. [ ] **Worker 02 Audit DEF-04 Integrated:** Pre-publication integrity audit integrated into `EvidenceService`.
5. [ ] **Release Gate Passes:** `python scripts/check_worker_boundaries.py` and `python run_tests.py` pass with zero failures.
