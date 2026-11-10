# TRUSTTRACE Worker 02 — Full Integration Audit Report

**Date:** 2026-11-10  
**Component:** Worker 02 — Evidence Intelligence, Provenance, Persistence & Collaborative Threat Intelligence  
**Branch:** `fix/worker02-cross-worker-integration`  
**Base Commit:** `7354365058f101e5ada2af34e7ccb0eb2309dbc2`  
**Auditor / Lead:** Senior Backend Architect & Cross-Worker Integration Lead  

---

## 1. Executive Summary

TRUSTTRACE is a multi-worker web threat detection and digital trust intelligence platform consisting of four bounded subsystems:
1. **Worker 01 (Intake & Collectors):** URL validation, IDNA canonicalization, SSRF protection, bounded DNS/TLS/HTTP collectors.
2. **Worker 02 (Evidence & Persistence):** Evidence normalization, provenance tracking, coverage metrics, finding linkage, community threat intelligence, database persistence, REST API.
3. **Worker 03 (Policy & Triage):** Conservative deterministic rule engine, signal extraction, uncertainty assessment, report integrity auditor.
4. **Worker 04 (Web UI & Workflow):** Interactive Evidence Passport dashboard, user scan workflows, community feed presentation.

This comprehensive integration audit evaluated the cross-worker integration points, contracts, data transfer objects, and execution boundaries between Worker 02 and adjacent workers (Worker 01, Worker 03, and Worker 04).

The audit identified six critical integration gaps (designated Issues A through F) that previously prevented clean end-to-end execution, allowed unpersisted triage workflows, caused 500 crashes in web demo routes, and risked publishing un-audited scan reports.

---

## 2. Cross-Worker Architectural Boundary Matrix

| Worker Domain | Primary Responsibilities | Strict Architectural Boundaries | Integration Touchpoints with Worker 02 |
|---|---|---|---|
| **Worker 01** | URL policy, SSRF isolation, socket collection, timeout budgets | Zero database writes; zero policy triage rules; produces raw `CollectorResult` payloads conforming to v1 contract | Consumed via `Worker01EvidenceAdapter.adapt_payload()`; zero internal socket/network imports permitted |
| **Worker 02** | Evidence normalization, provenance fingerprints, database persistence, coverage metrics, REST API | Never performs external networking or SSRF checks; never invents ad-hoc policy rules; stores immutable evidence and links findings | Ingests batches from W01, runs W03 `TriageEngine.evaluate_evidence()`, audits via `ReportIntegrityAuditor`, exposes REST endpoints |
| **Worker 03** | Pure-Python deterministic triage rules, signal extraction, uncertainty quantification, report integrity auditing | Zero network calls; zero direct database queries; operates strictly on immutable `PolicyInput` DTOs | Invoked in `EvidenceService.ingest_batch()` and `EvidenceService.get_scan_report()` |
| **Worker 04** | Web presentation, dashboard templates, demo endpoints, user scan submissions | Zero direct database mutations; routes all scans through canonical backend services | Submits scans via `/api/v1/triage/demo` and consumes canonical audited scan reports |

---

## 3. Detailed Audit of the Six Critical Integration Issues

### Issue A: Worker 03 `TriageEngine` Integration Gap in `EvidenceService.ingest_batch()`
- **Severity:** HIGH
- **Location:** `src/trusttrace/evidence/services/evidence_service.py` (`ingest_batch`)
- **Finding:**
  Previously, `EvidenceService.ingest_batch()` received an `EvidenceBatch`, persisted the individual evidence records to `evidence_records`, and recomputed scan coverage. However, it completely halted at that point: it never invoked Worker 03's `TriageEngine.evaluate_evidence()`. As a result:
  1. The scan record in the database remained in state `status="validating"`, `decision="inconclusive"`.
  2. Deterministic findings derived by Worker 03 rules were never created or persisted in `findings` and `finding_evidence_links`.
  3. Decisions, policy versions, dimensions, and limitations produced by the policy table were lost.
- **Root Cause:**
  `EvidenceService` lacked dependency injection of `TriageEngine` and did not construct canonical `PolicyInput.from_components()`.

### Issue B: DEF-04 Report Integrity Pre-Publication Audit Gap
- **Severity:** CRITICAL (Safety & Claim Discipline)
- **Location:** `src/trusttrace/evidence/services/evidence_service.py` (`get_scan_report`)
- **Finding:**
  Worker 03 implemented `ReportIntegrityAuditor` in Phase 04 to enforce six vital invariants (`INV-TLS-001`, `INV-EVID-002`, `INV-COV-001`, `INV-CLAIM-001`, `INV-FINDING-001`, `INV-COV-002`). However, `EvidenceService.get_scan_report()` assembled the dictionary and returned it directly to callers without executing `integrity_auditor.audit_report(candidate_report)`.
- **Impact:**
  Reports containing disallowed absolute marketing claims ("100% safe"), un-disclosed partial coverage with `no_threat_observed` decisions, or orphan finding references could be published to external consumers without automated safety gates.

### Issue C: Reliability Enum Compatibility Mismatches
- **Severity:** MEDIUM
- **Location:** `src/trusttrace/evidence/domain/enums.py`, `src/trusttrace/evidence/adapters/worker01_adapter.py`
- **Finding:**
  Worker 02 defined canonical enum values for `Reliability`: `provider_assertion`, `direct_observation`, `derived_signal`, `user_report`, `unknown`. However, legacy collectors, fixture payloads, and Worker 04 routes frequently supplied shorthand tier strings: `"high"`, `"medium"`, `"low"`.
- **Impact:**
  When `Worker01EvidenceAdapter` or `EvidenceService.ingest_single_observation()` encountered `"high"` or `"medium"`, calling `Reliability(val)` raised `ValueError` and coerced the reliability to `Reliability.UNKNOWN`. This corrupted provenance tracking and signal confidence in downstream triage.

### Issue D: Named Collector Coverage vs Raw Evidence Record Count
- **Severity:** HIGH (Contract & Metric Accuracy)
- **Location:** `src/trusttrace/evidence/services/evidence_service.py` (`calculate_coverage`)
- **Finding:**
  `EvidenceService.calculate_coverage()` previously computed `checks_observed = sum(1 for e in evidence_items if e.status == EvidenceStatus.OBSERVED)`. If the TLS collector produced 3 separate evidence records (`tls_certificate`, `tls_hostname_validation`, `tls_cipher`), the coverage algorithm counted 3 checks observed instead of 1 named collector check.
- **Impact:**
  Raw evidence record counts inflated the aggregate coverage metrics, misrepresenting partial scans as complete and violating the distinction between evidence-record counts and named check families (`url_intake`, `dns_resolution`, `tls_certificate`, `http_headers`, `redirect_chain`).

### Issue E: End-to-End Scan Persistence & Web Demo Route Defects (DEF-01 & DEF-05)
- **Severity:** CRITICAL
- **Location:** `src/trusttrace/web/routes.py`
- **Finding:**
  1. **DEF-01 (TypeError Crash):** Lines 42–45, 103–104, and 152–155 called `SignalRecord(SignalKind.TLS_VALID, "tls_collector", "Valid DV...")`. `SignalRecord.__init__` expects `(kind, evidence_ids: List[str], source: str, ...)`. Passing a bare string as argument 2 caused `SignalRecord.__post_init__` to raise `TypeError`, causing 100% reproducible HTTP 500 errors on `/api/v1/triage/demo` for `phishing_lookalike`, `expired_tls`, and custom URL scenarios.
  2. **DEF-05 (Uncertainty Discard):** Worker 03's uncertainty assessment was discarded by the web route and omitted from the JSON response and frontend dashboard.
  3. **Volatile In-Memory Bypass:** Submissions to `/api/v1/triage/demo` generated ephemeral JSON objects in memory without persisting scans, evidence, or findings to the database via `EvidenceService`.

### Issue F: Pydantic v2 / PolicyInput Serialization & Contract Compatibility
- **Severity:** MEDIUM
- **Location:** `src/trusttrace/evidence/domain/models.py`, `src/trusttrace/policy/policy_input.py`
- **Finding:**
  Worker 02 models (`EvidenceModel`, `CoverageModel`, `DimensionsModel`) used Pydantic v2. `EvidenceModel.to_v1_contract_dict()` previously omitted `"reliability"` if `self.reliability is None`. Worker 03's `PolicyInput.from_dict()` strictly requires a non-empty string for `reliability`. Furthermore, `CoverageModel` lacked `to_v1_contract_dict()`.

---

## 4. Remediation Priority & Audit Conclusion

| Issue | Target Subsystem | Remediation Complexity | Risk Level | Validation Requirement |
|---|---|---|---|---|
| **A** | `EvidenceService.ingest_batch` | Medium | High | Automated unit & integration tests for triage evaluation and finding idempotency |
| **B** | `EvidenceService.get_scan_report` | Low | Critical | Automated tests proving invalid reports are withheld and audited |
| **C** | `enums.py` / `models.py` / `adapter.py` | Low | Medium | Automated tests verifying `"high"`, `"medium"`, `"low"` normalizations |
| **D** | `EvidenceService.calculate_coverage` | Medium | High | Deduplication tests verifying checks total/observed/failed/not-run arithmetic |
| **E** | `web/routes.py` | Medium | Critical | TestClient tests verifying HTTP 200 and DB persistence across all demo scenarios |
| **F** | `models.py` / `policy_input.py` | Low | Medium | Roundtrip model conversion tests through `PolicyInput.from_components` |

All six issues have been addressed and validated in the remediation phase.
