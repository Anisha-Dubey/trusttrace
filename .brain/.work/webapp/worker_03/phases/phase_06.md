# Worker 03 Phase 06 — Cross-Worker Integration, Release Validation & Formal Handoff

## Phase Summary
Phase 06 establishes formal verification of the end-to-end evidence-to-policy-to-report pipeline, confirms public policy interface compatibility for Worker 02 and Worker 04 consumers, enforces strict v1 schema compliance for scan report generation, and delivers a fully verified, regression-free Worker 03 deliverable package with complete boundary preservation.

---

## 1. Frozen Public Policy Interfaces

Worker 03 exposes a stable, frozen public policy interface via `src/trusttrace/policy/`:

```
                                  +-----------------------------+
                                  |         Worker 02           |
                                  | EvidenceModel/CoverageModel |
                                  +-----------------------------+
                                                 |
                                                 v
+-------------------------+       +-----------------------------+       +-------------------------+
|        Worker 04        | ----> |     PolicyInput (v1 DTO)    | <---- |     Worker 01 / Dict    |
|   Web Routes / Demos    |       +-----------------------------+       |    Orchestrator Output  |
+-------------------------+                      |                      +-------------------------+
             |                                   v
             |                    +-----------------------------+
             |                    |   EvidenceValidator (v1)    |
             |                    +-----------------------------+
             |                                   |
             |                                   v
             |                    +-----------------------------+
             |                    |   EvidenceSignalExtractor   |
             |                    +-----------------------------+
             |                                   |
             |                                   v
             +------------------> |     TriageEngine (v1.0)     |
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |      UncertaintyEngine      |
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |    ReportIntegrityAuditor   |
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |   TriageResult / Fragment   |
                                  +-----------------------------+
```

### 1.1 Core Classes & Methods

1. **`PolicyInput` (`policy_input.py`)**:
   - Immutable data transfer object (`MappingProxyType`, `tuple`).
   - `PolicyInput.from_v1_dict(d: Mapping[str, Any], strict: bool = False) -> PolicyInput`
   - `PolicyInput.from_components(scan_id, target, evidence, coverage, community_reports, scan_profile) -> PolicyInput`
   - Ingests Worker 02 Pydantic models (`EvidenceModel`, `CoverageModel`) automatically via `to_v1_contract_dict()`, `model_dump()`, or `dict()`.
   - Structural & semantic validity checks (`input.is_valid`, `input.parse_issues`).

2. **`SignalRecord` (`signal_taxonomy.py`)**:
   - Immutable signal representation with 18 strongly-typed `SignalKind` values across 4 dimensions.
   - `SignalRecord(kind, evidence_ids, source, confidence, value, limitations)` (keyword-argument constructor).
   - `SignalRecord.create(kind, source, evidence_ids, ...)` (safe factory accepting bare strings or lists).
   - Enforces non-empty `evidence_ids` to preserve zero-fabrication and provenance tracing.

3. **`TriageEngine` (`triage_engine.py`)**:
   - `engine.evaluate_evidence(policy_input: Union[PolicyInput, Mapping[str, Any], Any]) -> TriageResult`:
     - Primary multi-type entry point.
     - Performs 9-step pipeline: parse gate → contract validation → deterministic signal extraction → rule execution → orphan finding suppression → deterministic SHA-256 finding ID generation → positive threat preservation → coverage deficit limitations merger → uncertainty quantification & abstention notice generation.
   - `engine.evaluate(signals: List[SignalRecord], scan_id: Optional[str] = None) -> TriageResult`:
     - Low-level signal evaluation for unit tests and custom rule evaluation.
   - `engine.audit_triage_result(result, policy_input) -> ReportAuditResult`:
     - Pre-publication integrity audit gate.

4. **`TriageResult` (`triage_engine.py`)**:
   - Attributes: `decision`, `dimensions`, `findings`, `rule_trace`, `policy_version`, `limitations`, `rationale_summary`, `diagnostics`, `uncertainty`.
   - Method `to_report_fragment() -> Dict[str, Any]`:
     - Produces the policy-owned subset: `{"decision": ..., "policy_version": ..., "dimensions": ..., "findings": ..., "limitations": ...}`.
     - Strictly complies with `scan_report.schema.json` without introducing undeclared fields (`additionalProperties: false`).

5. **`UncertaintyEngine` (`uncertainty.py`)**:
   - Taxonomizes 5 uncertainty types: `DATA_ABSENCE`, `COLLECTION_FAILURE`, `UNCHECKED_COVERAGE`, `TEMPORAL_STALENESS`, `EVIDENCE_CONFLICT`.
   - Derives 4 qualitative ordinal confidence bands: `SUFFICIENT_FOR_SCOPED_OBSERVATION`, `LIMITED_OBSERVATION`, `INSUFFICIENT_EVIDENCE`, `CONTRADICTORY_EVIDENCE`.
   - Calibrates freshness windows (`FreshnessPolicy`): DNS 24h, TLS 7d, threat intelligence 12h.
   - Formulates honest plain-language `AbstentionNotice` with reason codes (`ABSTAIN_COLLECTION_FAILURE`, `ABSTAIN_UNCHECKED_COVERAGE`, `ABSTAIN_EVIDENCE_CONFLICT`, `ABSTAIN_INSUFFICIENT_EVIDENCE`) and explicit rescan recommendations.

6. **`ReportIntegrityAuditor` (`integrity_auditor.py`)**:
   - Enforces 6 core invariants prior to report publication:
     - `INV-TLS-001`: Valid TLS without separate authorization evidence cannot support organizational identity.
     - `INV-EVID-002`: Missing threat intelligence matches cannot produce `safe` or `clean` verdicts.
     - `INV-COV-001`: Checks failed or unrun cannot produce `completed` status with `no_threat_observed`.
     - `INV-CLAIM-001`: Reports must not assert absolute safety, perfection, or 0% false positives.
     - `INV-FINDING-001`: Every finding must reference valid evidence IDs in the report (zero orphan findings).
     - `INV-COV-002`: Coverage arithmetic must be consistent (`total == observed + failed + not_run`).

---

## 2. Worker 02 Contract Integration

### 2.1 Implemented & Verified Capabilities in Worker 03
- **Pydantic Model Ingestion**: `PolicyInput` natively digests Worker 02 Pydantic models (`EvidenceModel`, `CoverageModel`) via `PolicyInput.from_components()`.
- **Zero Database Coupling**: Worker 03 remains completely decoupled from Worker 02 database tables, SQLAlchemy models, Alembic migrations, and persistence logic.
- **Contract Schema Alignment**: Worker 03 consumes canonical evidence fields (`evidence_id`, `kind`, `source`, `observed_at`, `status`, `reliability`, `value`, `limitations`) and coverage arithmetic without mutation or re-interpretation.

### 2.2 Cross-Worker Integration Confirmed on main
- Worker 02's cross-worker integration changes were successfully merged into `main` via PR #5 (commit `c328cc2`).
- Worker 02's `EvidenceService` incorporates `TriageEngine` into `ingest_batch()` and `ReportIntegrityAuditor` into `get_scan_report()`.
- **Status**: Full cross-worker end-to-end integration is **CONFIRMED & VERIFIED** on `main` (all 11 tests in `tests/test_worker02_cross_worker_integration.py` pass).

---

## 3. Worker 04 Consumer Compatibility

### 3.1 Verification of Worker 04 Implementation
Worker 04's implementation has been merged into `main` (commit `4cfc0b4`). All 12 conflicts identified in the Worker 04 Conflict Register (`CONFL-01` through `CONFL-12`) have been verified resolved:
1. `src/trusttrace/web/routes.py` now invokes `TriageEngine().evaluate_evidence(policy_input)` and `SignalRecord.create()` with explicit named parameters.
2. The web interface renders `triage_result.uncertainty` and ordinal confidence bands in both HTML (`index.html`) and JSON responses.
3. All 10 web interface regression tests in `tests/test_web_interface.py` pass cleanly.

---

## 4. Five Canonical End-to-End Scenarios

Worker 03 implements and verifies all five canonical architectural scenarios defined in the Master Blueprint:

### Scenario 1: Canonical Clean Observation
- **Input**: Valid TLS certificate for hostname, observed DNS resolution, clean threat feed match (`matched: False`, `threat_level: "none"`), 0 failed checks, 0 unrun checks.
- **Signals**: `COLLECTOR_SUCCESS`, `TLS_HOSTNAME_MATCH`, `TLS_VALID`, `NO_THREAT_MATCH`.
- **Output**:
  - `decision`: `"no_threat_observed"`
  - `dimensions`: `{"identity": "unverified", "certificate": "valid_for_hostname", "behavior": "no_threat_observed", "evidence_quality": "strong"}`
  - `uncertainty.confidence_band`: `SUFFICIENT_FOR_SCOPED_OBSERVATION`
  - `findings`: `[]` (0 findings)
  - `abstention_notice`: `None`
  - Schema-valid report envelope conforming to `scan_report.schema.json`.

### Scenario 2: Partial Coverage with Collector Failure
- **Input**: DNS resolution succeeds (`observed`), TLS collector fails (`status: "failed"`, `error: "handshake_timeout"`).
- **Signals**: `COLLECTOR_SUCCESS`, `TLS_UNAVAILABLE`, `COLLECTOR_FAILURE`.
- **Output**:
  - `decision`: `"inconclusive"`
  - `dimensions`: `{"evidence_quality": "partial", "behavior": "unknown", ...}`
  - `uncertainty.confidence_band`: `LIMITED_OBSERVATION`
  - `abstention_notice`: `reason_code="ABSTAIN_COLLECTION_FAILURE"`, `is_rescan_recommended=True`.
  - Limitations note detailing coverage deficit and collector timeout.

### Scenario 3: All Collector Failure
- **Input**: Both DNS and TLS collectors fail (`status: "failed"`).
- **Signals**: `COLLECTOR_FAILURE`, `TLS_UNAVAILABLE`.
- **Output**:
  - `decision`: `"inconclusive"`
  - `dimensions`: `{"evidence_quality": "unavailable", ...}`
  - `uncertainty.confidence_band`: `INSUFFICIENT_EVIDENCE`
  - `abstention_notice`: `reason_code="ABSTAIN_COLLECTION_FAILURE"`, `is_rescan_recommended=True`.
  - Schema-valid envelope with status `failed`.

### Scenario 4: Blocked Private Destination
- **Input**: Target is loopback/private IP (`127.0.0.1`), blocked by SSRF/safety guard (`kind: "target_policy"`, `status: "blocked"`).
- **Signals**: Preserved blocked destination diagnostic without synthetic signals.
- **Output**:
  - `decision`: `"inconclusive"`
  - `dimensions`: `{"evidence_quality": "unavailable", ...}`
  - `uncertainty.confidence_band`: `LIMITED_OBSERVATION` / `UNCHECKED_COVERAGE`
  - `abstention_notice`: `reason_code="ABSTAIN_UNCHECKED_COVERAGE"`, `is_rescan_recommended=False`.
  - Invariant strictly upheld: Never produces `safe`, `clean`, `benign`, or `no_threat_observed`.

### Scenario 5: Contemporaneous Conflicting Threat Feeds
- **Input**: Feed Alpha reports active malicious match (`matched: True`), Feed Beta reports clean (`matched: False`) for the same domain and time window.
- **Signals**: `THREAT_FEED_MATCH`, `NO_THREAT_MATCH`, `COLLECTOR_SUCCESS`.
- **Output**:
  - `decision`: `"inconclusive"`
  - `dimensions`: `{"behavior": "malicious_evidence", "evidence_quality": "partial", ...}`
  - `uncertainty.confidence_band`: `CONTRADICTORY_EVIDENCE`
  - `abstention_notice`: `reason_code="ABSTAIN_EVIDENCE_CONFLICT"`, `is_rescan_recommended=True`.
  - Provenance integrity: Both feed evidence IDs retained and cited; 0 orphan findings.

---

## 5. End-to-End Test Suite Verification

The end-to-end contract and regression tests are implemented in `tests/test_triage_policy.py` under `TestPhase06EndToEndIntegration`:
1. `test_e2e_canonical_clean_observation`: Validates Scenario 1 and full v1 JSON schema validation.
2. `test_e2e_partial_coverage_with_failure`: Validates Scenario 2 and honest abstention with rescan advice.
3. `test_e2e_all_collector_failure`: Validates Scenario 3 and schema-valid inconclusive envelope.
4. `test_e2e_blocked_private_destination`: Validates Scenario 4, safety policy blocks, and claim discipline.
5. `test_e2e_contemporaneous_conflicting_feeds`: Validates Scenario 5, multi-provider conflict retention, and zero orphan findings.
6. `test_e2e_report_envelope_v1_schema_validation`: Validates complete report envelope against `scan_report.schema.json` with strict `additionalProperties: false`.
7. `test_e2e_finding_referential_integrity`: Validates that all finding evidence IDs strictly resolve to evidence in the same input batch.

---

## 6. Acceptance Criteria Verification

| Requirement | Acceptance Criteria | Status | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **AC-01** | Public policy interface frozen & documented | **PASSED** | Section 1 of `phase_06.md`, `__init__.py` exports |
| **AC-02** | Worker 02 contract integration compatibility | **PASSED** | `PolicyInput.from_components()`, Pydantic ingestion tests pass |
| **AC-02-CONF** | Worker 02 cross-worker confirmation | **PASSED** | Merged in PR #5 (`c328cc2`), 11/11 tests pass |
| **AC-03** | Worker 04 consumer integration verified | **PASSED** | Commit `4cfc0b4` on `main`, 10/10 web tests pass |
| **AC-04** | 5 canonical scenarios pass E2E tests | **PASSED** | `TestPhase06EndToEndIntegration` (7/7 tests pass) |
| **AC-05** | Finding referential integrity enforced | **PASSED** | `test_e2e_finding_referential_integrity` passes |
| **AC-06** | Strict v1 scan report schema compliance | **PASSED** | `test_e2e_report_envelope_v1_schema_validation` passes |
| **AC-07** | Worker 03 unit & property test suite passes | **PASSED** | 129/129 tests pass in `test_triage_policy.py` (0.107s) |
| **AC-08** | Full repository test runner passes | **PASSED** | 291 tests discovered (290 passed, 1 skipped, 0 failures), 8 fixture checks pass; PostgreSQL 15 integration: 11/11 passed |
| **AC-09** | Worker boundary enforcement passes | **PASSED** | `check_worker_boundaries.py` reports 1 file in [worker_03] |
