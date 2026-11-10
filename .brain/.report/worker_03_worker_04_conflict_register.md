# TRUSTTRACE — WORKER 03: COMPLETE WORKER 04 CONFLICT REGISTER

**Audit Author:** Worker 03 (Risk Policy, Evidence Interpretation, Uncertainty & Claim Discipline)  
**Target Consumer:** Worker 04 (Web Interface, Evidence Passport Presentation & Stage Demos)  
**Target Codebase:** `src/trusttrace/web/routes.py`, `src/trusttrace/web/`, frontend templates, and test harnesses  
**Audit Baseline Commit:** `7354365058f101e5ada2af34e7ccb0eb2309dbc2` (HEAD -> main, origin/main)  
**Date:** 2026-11-10  
**Status:** COMPLETED & VERIFIED  

---

## 1. Executive Summary

As part of the cross-worker integration audit, Worker 03 conducted an exhaustive, line-by-line inspection of Worker 04's implementation (`src/trusttrace/web/routes.py`, UI templates, and API integrations). 

The audit compared Worker 04's callsites, data structures, and assumptions against the actual public interfaces, invariant rules, and data contracts of Worker 03 (`src/trusttrace/policy/`).

### Summary of Audit Findings:
- **Total Conflicts Identified:** 12
- **Critical Severity:** 3 (CONFL-01, CONFL-09, CONFL-12)
- **High Severity:** 5 (CONFL-02, CONFL-03, CONFL-05, CONFL-07, CONFL-11)
- **Medium Severity:** 3 (CONFL-04, CONFL-06, CONFL-08)
- **Low Severity:** 1 (CONFL-10)
- **Release Gate Status:** **BLOCKED** until Critical and High conflicts are remediated by Worker 04.

---

## 2. Master Conflict Table

| Conflict ID | Severity | File & Location | Summary | Status |
| :--- | :--- | :--- | :--- | :--- |
| **CONFL-01 (DEF-01)** | **CRITICAL** | `src/trusttrace/web/routes.py:42-45, 103-104, 152-155` | Positional argument transposition in `SignalRecord(...)` raising fatal `TypeError` | **CONFIRMED** |
| **CONFL-02** | **HIGH** | `src/trusttrace/web/routes.py:42-45` | Misunderstanding of `SignalRecord` parameters and `SignalKind` mapping | **CONFIRMED** |
| **CONFL-03** | **HIGH** | `src/trusttrace/web/routes.py:40, 101, 150` | Total bypass of `PolicyInput` contract and input validation gates | **CONFIRMED** |
| **CONFL-04** | **MEDIUM** | `src/trusttrace/web/routes.py:56-61, 115, 167-172` | Hardcoded coverage arithmetic bypassing Worker 02 / Policy computation | **CONFIRMED** |
| **CONFL-05** | **HIGH** | `src/trusttrace/web/routes.py:47, 106, 157` | Misuse of low-level `evaluate()` instead of consumer-facing `evaluate_evidence()` | **CONFIRMED** |
| **CONFL-06** | **MEDIUM** | `src/trusttrace/web/routes.py:48-97, 158-190` | Incomplete report assembly using `to_report_fragment()` bypassing v1 schema | **CONFIRMED** |
| **CONFL-07 (DEF-05)** | **HIGH** | `src/trusttrace/web/routes.py:48-97` & UI templates | Omission of Uncertainty Assessment, Confidence Bands, and Abstention Notices | **CONFIRMED** |
| **CONFL-08** | **MEDIUM** | `src/trusttrace/web/routes.py:26-191` | Missing `ReportIntegrityAuditor` pre-publication verification gate | **CONFIRMED** |
| **CONFL-09 (DEF-03A)**| **CRITICAL** | `src/trusttrace/web/routes.py:154` | Fabrication of `NO_THREAT_MATCH` without feed query (EVID-002 Invariant Violation) | **CONFIRMED** |
| **CONFL-10** | **LOW** | `src/trusttrace/web/routes.py:712-718` (Template JS) | Community report submission payload mismatch (`reporter_id` & domain syntax) | **CONFIRMED** |
| **CONFL-11 (DEF-02)** | **HIGH** | `tests/` | Complete absence of automated web route and dashboard regression tests | **CONFIRMED** |
| **CONFL-12 (DEF-03B)**| **CRITICAL** | `src/trusttrace/web/routes.py:138-190` | Architectural disconnection between Worker 01 collectors, Worker 02 DB, and Worker 03 | **CONFIRMED** |

---

## 3. Comprehensive Conflict Breakdown

### CONFL-01 (DEF-01): Positional Argument Transposition in `SignalRecord`
1. **Conflict ID:** `CONFL-01`
2. **Severity:** `CRITICAL`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py`
4. **Exact Location:** `triage_demo_endpoint()`, lines 42–45, 103–104, 152–155.
5. **Current Worker 04 Implementation:**
   ```python
   signals = [
       SignalRecord(SignalKind.TLS_VALID, "tls_collector", "Valid DV Cert by Let's Encrypt"),
       SignalRecord(SignalKind.TLS_HOSTNAME_MATCH, "tls_collector", "Certificate matches domain"),
       SignalRecord(SignalKind.IDN_LOOKALIKE, "url_policy", "Cyrillic homoglyph lookalike character in domain name"),
       SignalRecord(SignalKind.COLLECTOR_SUCCESS, "intake_boundary", "Metadata checks complete; active browser execution blocked"),
   ]
   ```
6. **Actual Worker 03 Contract (`src/trusttrace/policy/signal_taxonomy.py`):**
   ```python
   @dataclass
   class SignalRecord:
       kind: SignalKind                                                    # Arg 1
       evidence_ids: List[str]                                             # Arg 2 (MUST be a Sequence of strings)
       source: str                                                         # Arg 3 (String collector/source)
       confidence: Union[SignalConfidence, str] = SignalConfidence.OBSERVED# Arg 4
       value: Optional[Any] = None                                         # Arg 5
       limitations: List[str] = field(default_factory=list)                # Arg 6
   ```
7. **Why They Conflict:**
   Worker 04 calls `SignalRecord(kind, source_str, value_str)`. In Python positional calling, `"tls_collector"` is bound to `evidence_ids`. In `SignalRecord.__post_init__()`, a bare string is explicitly rejected with `TypeError`.
8. **Runtime or Functional Impact:**
   Every call to `POST /api/v1/triage/demo` with `scenario="phishing_lookalike"`, `scenario="expired_tls"`, or custom URLs crashes immediately with HTTP 500:
   ```
   TypeError: evidence_ids must be a sequence of strings, not a bare string. Got bare string 'tls_collector'.
   ```
9. **Exact Recommended Correction:**
   Use named parameters or the dedicated `SignalRecord.create()` factory method provided by Worker 03.
10. **Correct Code Example:**
    ```python
    # Option A: Using SignalRecord.create() factory
    SignalRecord.create(
        kind=SignalKind.TLS_VALID,
        source="tls_collector",
        evidence_ids=["ev-tls-001"],
        value="Valid DV Cert by Let's Encrypt",
    )
    
    # Option B: Named parameters
    SignalRecord(
        kind=SignalKind.TLS_VALID,
        evidence_ids=["ev-tls-001"],
        source="tls_collector",
        value="Valid DV Cert by Let's Encrypt",
    )
    ```
11. **Required Regression Test:**
    Test `POST /api/v1/triage/demo` with `phishing_lookalike`, `expired_tls`, and custom URLs; assert HTTP 200 response with no `TypeError`.
12. **Acceptance Criteria:**
    All calls to `/api/v1/triage/demo` execute successfully and return a valid response without unhandled exceptions.
13. **Verification Status:** **CONFIRMED** (100% reproducible via `TestClient`).

---

### CONFL-02: Misunderstanding of `SignalRecord` Parameters & Taxonomy
1. **Conflict ID:** `CONFL-02`
2. **Severity:** `HIGH`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py`
4. **Exact Location:** `triage_demo_endpoint()`, lines 42–45, 152–155.
5. **Current Worker 04 Implementation:**
   Worker 04 assumed that `SignalRecord` took `(kind, source, description)`. It passed descriptive human-readable strings as the 3rd positional argument, assuming it was a display description.
6. **Actual Worker 03 Contract (`src/trusttrace/policy/signal_taxonomy.py`):**
   `SignalRecord` does not have a `description` field. Its fields are `source` (provenance origin), `confidence` (calibrated ordinal confidence), `value` (raw evidence payload), and `limitations` (caveats). Display summaries are generated deterministically by `TriageEngine` rules when composing `findings`.
7. **Why They Conflict:**
   Freeform text passed as `source` contaminates provenance metadata used by `UncertaintyEngine` to determine freshness and collector reliability.
8. **Runtime or Functional Impact:**
   Degrades telemetry provenance; prevents `UncertaintyEngine` from looking up source-specific freshness windows in `DEFAULT_FRESHNESS_WINDOWS` (which expects normalized names like `"tls_collector"`, `"dns_collector"`, `"reputation"`).
9. **Exact Recommended Correction:**
   Pass the exact collector/source identifier as `source` (e.g. `"tls_collector"`, `"url_policy"`, `"intake_boundary"`), pass raw values to `value`, and pass caveats to `limitations`.
10. **Correct Code Example:**
    ```python
    SignalRecord.create(
        kind=SignalKind.TLS_HOSTNAME_MATCH,
        source="tls_collector",
        evidence_ids=["ev-tls-001"],
        value={"hostname_matched": True},
        limitations=["Valid DV TLS proves transport encryption only."],
    )
    ```
11. **Required Regression Test:**
    Verify `sig.source` matches canonical collector identifiers and `sig.dimension` maps correctly to `SignalDimension.CERTIFICATE`.
12. **Acceptance Criteria:**
    `SignalRecord.source` contains genuine collector identifiers; provenance is preserved through triage.
13. **Verification Status:** **CONFIRMED**.

---

### CONFL-03: Total Bypass of `PolicyInput` Contract and Input Validation Gates
1. **Conflict ID:** `CONFL-03`
2. **Severity:** `HIGH`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py`
4. **Exact Location:** `triage_demo_endpoint()`, lines 40–47, 101–106, 150–157.
5. **Current Worker 04 Implementation:**
   Worker 04 directly creates a bare Python list of `SignalRecord`s and passes them straight to `TriageEngine.evaluate(signals)`.
6. **Actual Worker 03 Contract (`src/trusttrace/policy/policy_input.py`):**
   Worker 03 defines `PolicyInput`, an immutable, deeply frozen DTO that validates input schemas, isolates unparsed fields, ensures non-empty strings, and models coverage and community reports.
7. **Why They Conflict:**
   By skipping `PolicyInput`, Worker 04 bypasses:
   - Input validation pre-flight checks (`EvidenceValidator`).
   - Deep freezing into immutable `MappingProxyType`s.
   - Parse issue reporting (`PolicyInput.parse_issues`).
   - Automated conversion from Worker 02 Pydantic models.
8. **Runtime or Functional Impact:**
   The presentation layer is decoupled from the canonical data model. If invalid evidence data enters the system, Worker 03's quarantine and diagnostic mechanisms are never engaged.
9. **Exact Recommended Correction:**
   Assemble evidence dictionaries or Worker 02 models, then instantiate `PolicyInput.from_components()` or pass the canonical dictionary directly to `TriageEngine.evaluate_evidence()`.
10. **Correct Code Example:**
    ```python
    from trusttrace.policy.policy_input import PolicyInput
    from trusttrace.policy.triage_engine import TriageEngine
    
    policy_input = PolicyInput.from_components(
        scan_id="scan-demo-phish-001",
        target="bank-secure-lоgin.com",
        evidence=[
            {
                "evidence_id": "ev-tls-001",
                "kind": "tls_certificate",
                "source": "tls_collector",
                "observed_at": "2026-11-10T00:30:00Z",
                "status": "observed",
                "reliability": "high",
                "value": {"is_valid": True, "hostname_match": True},
                "limitations": ["DV cert only."],
            }
        ],
        coverage={"checks_total": 4, "checks_observed": 4, "checks_failed": 0, "checks_not_run": 0},
    )
    engine = TriageEngine()
    result = engine.evaluate_evidence(policy_input)
    ```
11. **Required Regression Test:**
    Pass a `PolicyInput` instance to `TriageEngine.evaluate_evidence()`; assert result is generated with full diagnostic and uncertainty assessment.
12. **Acceptance Criteria:**
    All triage evaluations pass through `PolicyInput` or canonical v1 dictionaries.
13. **Verification Status:** **CONFIRMED**.

---

### CONFL-04: Hardcoded Coverage Arithmetic Bypassing Policy Computation
1. **Conflict ID:** `CONFL-04`
2. **Severity:** `MEDIUM`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py`
4. **Exact Location:** Lines 56–61, 115, 167–172.
5. **Current Worker 04 Implementation:**
   Worker 04 hardcodes static coverage numbers in its return payload:
   ```python
   "coverage": {
       "checks_total": 5,
       "checks_observed": 4,
       "checks_failed": 0,
       "checks_not_run": 1,
   }
   ```
6. **Actual Worker 03 Contract (`src/trusttrace/policy/policy_input.py` & `integrity_auditor.py`):**
   `CoverageSummary` and `ReportIntegrityAuditor` enforce invariant **INV-COV-002**:
   `checks_total == checks_observed + checks_failed + checks_not_run`.
   Furthermore, Worker 02 calculates real coverage based on executed checks (`calculate_coverage()`).
7. **Why They Conflict:**
   If Worker 04's hardcoded numbers disagree with actual evidence counts or violate the arithmetic sum, `ReportIntegrityAuditor` rejects the report with an `AuditSeverity.ERROR`.
8. **Runtime or Functional Impact:**
   In custom scans, Worker 04 claims 4 checks observed even when 0 network collectors were executed (since Worker 04 bypassed collectors).
9. **Exact Recommended Correction:**
   Compute coverage from the actual evidence items using Worker 02's `calculate_coverage(evidence)` or `CoverageSummary.from_dict()`.
10. **Correct Code Example:**
    ```python
    from trusttrace.evidence.services.coverage_calculator import calculate_coverage
    coverage_dict = calculate_coverage(evidence_models_or_dicts)
    ```
11. **Required Regression Test:**
    Verify `coverage.checks_total == coverage.checks_observed + coverage.checks_failed + coverage.checks_not_run` for all dynamic and custom scans.
12. **Acceptance Criteria:**
    Coverage metrics accurately reflect executed collector checks without hardcoded fabrications.
13. **Verification Status:** **CONFIRMED**.

---

### CONFL-05: Misuse of Low-Level `evaluate()` instead of `evaluate_evidence()`
1. **Conflict ID:** `CONFL-05`
2. **Severity:** `HIGH`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py`
4. **Exact Location:** Lines 47, 106, 157.
5. **Current Worker 04 Implementation:**
   `result = engine.evaluate(signals)`
6. **Actual Worker 03 Contract (`src/trusttrace/policy/triage_engine.py`):**
   - `TriageEngine.evaluate(signals, scan_id)` is a low-level internal primitive.
   - `TriageEngine.evaluate_evidence(policy_input)` is the complete public pipeline. It performs:
     1. Parse issue rejection gate.
     2. Evidence validation.
     3. Signal extraction via `EvidenceSignalExtractor`.
     4. Triage rule execution.
     5. Referential integrity enforcement (suppressing orphan findings).
     6. Deterministic finding ID generation via full SHA-256.
     7. Threat preservation across collector failures.
     8. Uncertainty quantification via `UncertaintyEngine`.
7. **Why They Conflict:**
   Calling `evaluate(signals)` directly produces a `TriageResult` where `result.uncertainty` is `None`, deterministic finding hashing is incomplete, and referential integrity is unvalidated.
8. **Runtime or Functional Impact:**
   The output lacks uncertainty modeling, confidence bands, abstention notices, and structured diagnostics.
9. **Exact Recommended Correction:**
   Migrate all callsites to `engine.evaluate_evidence(policy_input)`.
10. **Correct Code Example:**
    ```python
    result = engine.evaluate_evidence(policy_input)
    # result.decision, result.dimensions, result.findings, result.uncertainty are all populated
    ```
11. **Required Regression Test:**
    Execute `evaluate_evidence()`; assert `result.uncertainty is not None` and `result.uncertainty.confidence_band` is a valid `ConfidenceBand`.
12. **Acceptance Criteria:**
    `evaluate_evidence()` is the sole entry point for triage in web routes.
13. **Verification Status:** **CONFIRMED**.

---

### CONFL-06: Incomplete Report Assembly Using `to_report_fragment()`
1. **Conflict ID:** `CONFL-06`
2. **Severity:** `MEDIUM`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py`
4. **Exact Location:** Lines 48–97, 107–130, 158–190.
5. **Current Worker 04 Implementation:**
   Worker 04 calls `fragment = result.to_report_fragment()` and then manually constructs a dictionary containing `scan_id`, `submitted_url_redacted`, `normalized_host`, `status`, `coverage`, and `evidence`.
6. **Actual Worker 03 Contract (`src/trusttrace/policy/triage_engine.py`):**
   `to_report_fragment()` is specifically designed for merging triage results into an existing report dictionary that already contains `scan_id`, `created_at`, `evidence`, etc.
7. **Why They Conflict:**
   Worker 04's manual dictionary assembly omits canonical schema fields required by `scan_report.schema.json`:
   - `schema_version: "1.0"`
   - `created_at` (ISO-8601 UTC timestamp)
   - `completed_at` (ISO-8601 UTC timestamp)
   - `uncertainty` object
8. **Runtime or Functional Impact:**
   Candidate reports constructed in `routes.py` fail full JSON schema validation against `.brain/.work/contracts/v1/scan_report.schema.json`.
9. **Exact Recommended Correction:**
   Build candidate reports adhering strictly to `scan_report.schema.json`, including `schema_version`, timestamps, and uncertainty fields.
10. **Correct Code Example:**
    ```python
    from datetime import datetime, timezone
    
    now_iso = datetime.now(timezone.utc).isoformat()
    candidate_report = {
        "schema_version": "1.0",
        "scan_id": policy_input.scan_id,
        "submitted_url_redacted": url,
        "normalized_host": policy_input.target,
        "status": "completed",
        "created_at": now_iso,
        "completed_at": now_iso,
        "decision": result.decision,
        "policy_version": result.policy_version,
        "dimensions": result.dimensions,
        "coverage": policy_input.coverage.to_dict() if policy_input.coverage else None,
        "findings": result.findings,
        "evidence": [e.to_dict() for e in policy_input.evidence],
        "uncertainty": result.uncertainty.to_dict() if result.uncertainty else None,
        "limitations": result.limitations,
    }
    ```
11. **Required Regression Test:**
    Validate candidate report dictionary with `jsonschema.validate(instance=report, schema=scan_report_schema)`.
12. **Acceptance Criteria:**
    Reports returned by Worker 04 pass 100% schema validation with `additionalProperties: false`.
13. **Verification Status:** **CONFIRMED**.

---

### CONFL-07 (DEF-05): Omission of Uncertainty Assessment & Abstention Notices in UI
1. **Conflict ID:** `CONFL-07`
2. **Severity:** `HIGH`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py` & UI templates (`index.html`)
4. **Exact Location:** `routes.py` lines 49–97, 360–424, 574–606.
5. **Current Worker 04 Implementation:**
   Worker 04 exposes only `decision`, `dimensions`, `coverage`, `findings`, and `evidence`. The HTML dashboard presents a 4-dimension card layout and a decision badge, but has **zero visual elements for Confidence Bands or Abstention Notices**.
6. **Actual Worker 03 Contract (`src/trusttrace/policy/uncertainty.py`):**
   Worker 03 Phase 04 defines:
   - `ConfidenceBand`: `sufficient_for_scoped_observation`, `limited_observation`, `insufficient_evidence`, `contradictory_evidence`.
   - `AbstentionNotice`: `reason_code`, `affected_dimensions`, `missing_or_failed_checks`, `is_rescan_recommended`, `explanation`.
   - Explicit mandate: Users MUST be informed when policy abstains or caps confidence.
7. **Why They Conflict:**
   When a scan encounters collector timeouts or conflicting signals, `TriageEngine` caps decision at `inconclusive` or `caution` and issues an `AbstentionNotice`. Worker 04 completely hides this notice from the user.
8. **Runtime or Functional Impact:**
   Users see an `inconclusive` badge without knowing *why* the policy abstained, whether a rescan is recommended, or which collectors failed.
9. **Exact Recommended Correction:**
   1. Include `uncertainty: result.uncertainty.to_dict()` in the API response.
   2. Add a Confidence Band Pill badge and an Abstention Banner in the HTML dashboard when `abstention_notice` is present.
10. **Correct Code Example:**
    ```html
    <!-- In UI: Abstention Banner -->
    <div id="abstentionBanner" class="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
      <div class="font-bold text-amber-400">Policy Abstention Notice (<span id="abstentionCode"></span>)</div>
      <p id="abstentionExplanation" class="text-xs text-slate-300"></p>
      <div id="rescanRecommendedBadge" class="text-[10px] text-amber-500 font-mono mt-1"></div>
    </div>
    ```
11. **Required Regression Test:**
    Trigger `expired_tls` and `conflicting` scenarios; verify the API response contains `uncertainty.abstention_notice` and `uncertainty.confidence_band`.
12. **Acceptance Criteria:**
    Confidence band and abstention notice are rendered prominently in the Evidence Passport UI.
13. **Verification Status:** **CONFIRMED**.

---

### CONFL-08: Missing `ReportIntegrityAuditor` Pre-Publication Verification Gate
1. **Conflict ID:** `CONFL-08`
2. **Severity:** `MEDIUM`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py`
4. **Exact Location:** `triage_demo_endpoint()`, lines 26–191.
5. **Current Worker 04 Implementation:**
   Worker 04 constructs a report dictionary and immediately returns it to the client without running an integrity audit.
6. **Actual Worker 03 Contract (`src/trusttrace/policy/integrity_auditor.py`):**
   `ReportIntegrityAuditor.audit_report(report)` verifies 6 mandatory invariant rules before publication:
   - `INV-TLS-001`: Identity not supported without explicit authorization.
   - `INV-EVID-002`: No affirmative global safety claims ("safe", "clean").
   - `INV-COV-001`: Scoped limitations when coverage is partial.
   - `INV-CLAIM-001`: Anti-marketing assertions ("100% safe", "bulletproof").
   - `INV-FINDING-001`: Finding referential integrity (no orphan findings).
   - `INV-COV-002`: Coverage arithmetic sum integrity.
7. **Why They Conflict:**
   If Worker 04 returns reports without auditing, any invariant violation introduced by custom URLs or hardcoded fixtures reaches users unchecked.
8. **Runtime or Functional Impact:**
   Violations of core hackathon theses (e.g. claims of "safe" or orphan finding IDs) could be published.
9. **Exact Recommended Correction:**
   Pass the candidate report through `TriageEngine.audit_report(candidate_report)`. If `audit_res.is_valid` is `False`, reject or log an error before returning.
10. **Correct Code Example:**
    ```python
    audit_res = engine.audit_report(candidate_report)
    if not audit_res.is_valid:
        raise HTTPException(
            status_code=500,
            detail=f"Report failed integrity audit: {[i.explanation for i in audit_res.issues]}"
        )
    ```
11. **Required Regression Test:**
    Submit a malformed report with `checks_total=10` but `observed=1`; verify auditor catches `INV-COV-002`.
12. **Acceptance Criteria:**
    Every report returned by Worker 04 passes `ReportIntegrityAuditor` with 0 `AuditSeverity.ERROR` issues.
13. **Verification Status:** **CONFIRMED**.

---

### CONFL-09 (DEF-03A): Fabrication of `NO_THREAT_MATCH` (EVID-002 Violation)
1. **Conflict ID:** `CONFL-09`
2. **Severity:** `CRITICAL`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py`
4. **Exact Location:** Custom URL evaluation, line 154:
   ```python
   SignalRecord(SignalKind.NO_THREAT_MATCH, "reputation_feed", "No negative blacklist entry observed")
   ```
5. **Current Worker 04 Implementation:**
   When a user submits a custom URL, Worker 04 verifies intake safety with `IntakeBoundary`, and then immediately fabricates a `SignalKind.NO_THREAT_MATCH` signal without querying any threat intelligence provider.
6. **Actual Worker 03 Contract (`src/trusttrace/policy/signal_extractor.py` & Invariant EVID-002):**
   Invariant **EVID-002** states:
   *`NO_THREAT_MATCH` is emitted ONLY when the feed query completed successfully with a verified negative match (`match=False`, `status="observed"`). Never emit `NO_THREAT_MATCH` on unexecuted, missing, or failed queries.*
7. **Why They Conflict:**
   Worker 04 manufactures a positive reputation observation out of thin air. In reality, no threat feed was queried.
8. **Runtime or Functional Impact:**
   A malicious target URL that exists on public blacklists would receive an artificial `NO_THREAT_MATCH` signal, biasing the triage engine toward a benign verdict. This is an egregious security policy breach.
9. **Exact Recommended Correction:**
   Remove the fabricated `NO_THREAT_MATCH` signal. If threat feeds were not queried, emit `COLLECTOR_FAILURE` or omit the signal entirely, allowing `UncertaintyEngine` to truthfully report `UNCHECKED_COVERAGE`.
10. **Correct Code Example:**
    ```python
    # Do NOT emit NO_THREAT_MATCH unless real feed collector executed:
    signals = [
        SignalRecord.create(
            kind=SignalKind.COLLECTOR_SUCCESS,
            source="intake_boundary",
            evidence_ids=["ev-intake-001"],
            value={"url_safe": True},
        )
    ]
    # In the absence of reputation checks, evidence_quality will truthfully evaluate to partial/incomplete.
    ```
11. **Required Regression Test:**
    Submit an un-scanned custom URL; assert `SignalKind.NO_THREAT_MATCH` is NOT in the extracted signal trace unless an actual reputation feed collector ran.
12. **Acceptance Criteria:**
    Zero fabricated threat intelligence signals in custom URL triage.
13. **Verification Status:** **CONFIRMED**.

---

### CONFL-10: Community Report Submission Schema & Domain Syntax Mismatch
1. **Conflict ID:** `CONFL-10`
2. **Severity:** `LOW`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py` (HTML template JS, lines 712–718)
4. **Exact Location:** `submitCommunityReport()` JavaScript function.
5. **Current Worker 04 Implementation:**
   ```javascript
   body: JSON.stringify({
     normalized_domain: domain,
     claim_type: claimType,
     reporter_id: 'analyst-ui-demo',
     note: note,
   })
   ```
6. **Actual Worker 02 / API Contract (`src/trusttrace/api/schemas.py`):**
   `SubmitCommunityReportRequest` defines:
   - `normalized_domain: str` (validated via `validate_domain_name()`: must be a bare hostname, rejecting `http://`, `https://`, `/`, queries).
   - `claim_type: ClaimType`
   - `note: Optional[str] = ""`
   - `source_family: Optional[str] = "community_user"`
   - `linked_evidence_ids: List[str] = []`
   - `reporter_id` is NOT an accepted client field (reporter identity is pseudonymized server-side).
7. **Why They Conflict:**
   - Sending `reporter_id` passes an undocumented parameter.
   - If a user pastes a full URL into the domain box (e.g. `https://bad.com/path`), the server rejects it with HTTP 422 because `validate_domain_name()` prohibits protocols and slashes.
8. **Runtime or Functional Impact:**
   User community submissions fail with HTTP 422 if URLs are entered instead of clean hostnames.
9. **Exact Recommended Correction:**
   Strip protocol and path client-side: `domain.replace(/^https?:\/\//, '').split('/')[0]`, and remove `reporter_id` from the payload.
10. **Correct Code Example:**
    ```javascript
    const cleanDomain = domainInput.value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const payload = {
      normalized_domain: cleanDomain,
      claim_type: claimType,
      note: noteInput.value.trim(),
    };
    ```
11. **Required Regression Test:**
    Submit community report with `https://example.com/test` entered; verify frontend normalizes to `example.com` and receives HTTP 201 Created.
12. **Acceptance Criteria:**
    Community reports submit cleanly without 422 validation errors.
13. **Verification Status:** **CONFIRMED**.

---

### CONFL-11 (DEF-02): Zero Automated Web Route Regression Test Coverage
1. **Conflict ID:** `CONFL-11`
2. **Severity:** `HIGH`
3. **Worker 04 File Path:** `tests/`
4. **Exact Location:** Repository test suite configuration (`run_tests.py`).
5. **Current Worker 04 Implementation:**
   In `origin/main` commit `7354365`, there is no test file covering `src/trusttrace/web/routes.py`.
6. **Actual Worker 03 / Repository Standard:**
   All subsystem routes and policy engines are guarded by comprehensive automated unit and integration tests (Worker 03 has 107 passing tests in `tests/test_triage_policy.py`).
7. **Why They Conflict:**
   Because Worker 04 has 0 tests in `main`, critical defects like CONFL-01 (`TypeError` on `SignalRecord`) pass CI without triggering a single test failure.
8. **Runtime or Functional Impact:**
   Fatal regressions in web routes can be merged to `main` without detection.
9. **Exact Recommended Correction:**
   Create `tests/test_web_interface.py` using FastAPI `TestClient`, covering:
   - `GET /` (dashboard returns 200 and HTML).
   - `POST /api/v1/triage/demo` with `legitimate`.
   - `POST /api/v1/triage/demo` with `phishing_lookalike`.
   - `POST /api/v1/triage/demo` with `expired_tls`.
   - `POST /api/v1/triage/demo` with `conflicting`.
   - `POST /api/v1/triage/demo` with custom safe URL.
   - `POST /api/v1/triage/demo` with custom SSRF URL (blocked).
   - `POST /api/v1/triage/demo` with credentials URL (rejected).
10. **Correct Code Example:**
    ```python
    from fastapi.testclient import TestClient
    from trusttrace.api.app import create_app
    
    app = create_app()
    client = TestClient(app)
    
    def test_phishing_lookalike_scenario():
        res = client.post("/api/v1/triage/demo", json={"url": "https://bank.com", "scenario": "phishing_lookalike"})
        assert res.status_code == 200
        assert res.json()["decision"] == "caution"
    ```
11. **Required Regression Test:**
    Run `python -m unittest tests/test_web_interface.py`; all 8 tests must pass.
12. **Acceptance Criteria:**
    `test_web_interface.py` exists in `tests/` and executes as part of `python run_tests.py`.
13. **Verification Status:** **CONFIRMED**.

---

### CONFL-12 (DEF-03B): Architectural Disconnection Between Collectors, DB, and Policy
1. **Conflict ID:** `CONFL-12`
2. **Severity:** `CRITICAL`
3. **Worker 04 File Path:** `src/trusttrace/web/routes.py`
4. **Exact Location:** `triage_demo_endpoint()`, lines 138–190.
5. **Current Worker 04 Implementation:**
   When a user enters a custom URL, Worker 04 calls `IntakeBoundary.evaluate_url()`. If valid, it fabricates mock signals in memory and calls `TriageEngine.evaluate(signals)`. It **never runs collectors, never calls Worker 02 adapters, and never persists scans**.
6. **Actual Intended Architecture:**
   ```
   User submits URL
         │
         ▼
   Worker 01: IntakeBoundary (SSRF/Cred check)
         │
         ▼
   Worker 01: ScanOrchestrator (DNS, TLS, HTTP collectors)
         │ (CollectorResult items)
         ▼
   Worker 02: Worker01EvidenceAdapter -> EvidenceService (DB persistence)
         │ (EvidenceModel, CoverageModel)
         ▼
   Worker 03: PolicyInput -> TriageEngine.evaluate_evidence() -> IntegrityAuditor
         │ (Audited Report)
         ▼
   Worker 04: Visual Presentation
   ```
7. **Why They Conflict:**
   Worker 04 operates as a standalone mockup rather than the presentation tier of the real backend pipeline.
8. **Runtime or Functional Impact:**
   Live URL triage does not inspect the real destination DNS, TLS certificate, or headers. It returns fabricated placeholder observations.
9. **Exact Recommended Correction:**
   Provide a real scan coordinator or fallback pipeline that invokes:
   `IntakeBoundary` -> `ScanOrchestrator.scan()` -> `Worker01EvidenceAdapter.convert_batch()` -> `PolicyInput.from_components()` -> `TriageEngine.evaluate_evidence()` -> `ReportIntegrityAuditor.audit_report()`.
10. **Correct Code Example:**
    ```python
    from trusttrace.intake.boundary import IntakeBoundary
    from trusttrace.collectors.orchestrator import ScanOrchestrator
    from trusttrace.evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
    from trusttrace.policy.policy_input import PolicyInput
    from trusttrace.policy.triage_engine import TriageEngine
    
    # 1. Intake
    is_safe, code, msg, rej_report = boundary.evaluate_url(url, scan_id)
    if not is_safe:
        return rej_report
        
    # 2. Collect
    orchestrator = ScanOrchestrator()
    collect_results = orchestrator.execute_scan(url)
    
    # 3. Adapt
    adapter = Worker01EvidenceAdapter()
    evidence_batch = adapter.to_evidence_items(collect_results, scan_id)
    
    # 4. Policy Triage
    policy_input = PolicyInput.from_components(
        scan_id=scan_id,
        target=url,
        evidence=evidence_batch,
    )
    engine = TriageEngine()
    result = engine.evaluate_evidence(policy_input)
    candidate_report = build_canonical_report(policy_input, result)
    
    # 5. Audit
    audit_res = engine.audit_report(candidate_report)
    return candidate_report
    ```
11. **Required Regression Test:**
    Execute an integrated scan against a safe fixture target; assert real collector observations are persisted and evaluated by `TriageEngine`.
12. **Acceptance Criteria:**
    Custom URL scans invoke the real pipeline or a truthfully disclosed offline fallback.
13. **Verification Status:** **CONFIRMED**.

---

## 4. Prioritization Matrix

```
┌─────────────────────────────────────────────────────────────┐
│ CRITICAL: Blockers to Runtime Execution & Policy Integrity │
├─────────────────────────────────────────────────────────────┤
│ • CONFL-01: Positional argument transposition (TypeError)   │
│ • CONFL-09: Unverified NO_THREAT_MATCH signal fabrication   │
│ • CONFL-12: End-to-end pipeline disconnection               │
├─────────────────────────────────────────────────────────────┤
│ HIGH: Contract Violations & Omissions                       │
├─────────────────────────────────────────────────────────────┤
│ • CONFL-02: SignalRecord parameter misunderstanding         │
│ • CONFL-03: PolicyInput contract bypass                     │
│ • CONFL-05: evaluate() vs evaluate_evidence() misuse        │
│ • CONFL-07: Uncertainty assessment & abstention omission    │
│ • CONFL-11: Zero automated test coverage                    │
├─────────────────────────────────────────────────────────────┤
│ MEDIUM / LOW: Data Discipline & UI Polish                   │
├─────────────────────────────────────────────────────────────┤
│ • CONFL-04: Hardcoded coverage arithmetic                   │
│ • CONFL-06: Incomplete report assembly                      │
│ • CONFL-08: Missing integrity auditor pre-publication gate  │
│ • CONFL-10: Community report submission payload mismatch    │
└─────────────────────────────────────────────────────────────┘
```

This completes the comprehensive Worker 03 $\rightarrow$ Worker 04 Conflict Register. All findings are verified against the canonical codebase.
