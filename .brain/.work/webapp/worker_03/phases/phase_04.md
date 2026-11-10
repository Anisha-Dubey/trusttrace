# Worker 03 Phase 04 — Uncertainty Quantification, Abstention Engine & Report Integrity Auditor

## Phase Summary
Phase 04 establishes structured uncertainty modeling, explicit human-readable abstention notices, and an automated report integrity auditor that strictly enforces TRUSTTRACE core safety and claim discipline invariants before reports are published.

---

## 1. Architectural Components

```
                   +---------------------------------------------+
                   | policy_input.py (Canonical DTOs)            |
                   +---------------------------------------------+
                                          |
                                          v
                   +---------------------------------------------+
                   | signal_extractor.py (Typed Signal Pipeline) |
                   +---------------------------------------------+
                                          |
                                          v
                   +---------------------------------------------+
                   | triage_engine.py (TriageEngine)             |
                   | - Decision Composition & Dispositions      |
                   +---------------------------------------------+
                                     /         \
                                    /           \
                                   v             v
       +------------------------------------+  +------------------------------------+
       | uncertainty.py (UncertaintyEngine) |  | integrity_auditor.py               |
       | - UncertaintyType (5 categories)   |  | - ReportIntegrityAuditor           |
       | - ConfidenceBand (4 ordinal bands) |  | - Invariant Rules 1-6              |
       | - FreshnessPolicy (Source-specific)|  | - Anti-Marketing Claim Guard       |
       | - AbstentionNotice (Plain language)|  | - Referential & Arithmetic Checks  |
       +------------------------------------+  +------------------------------------+
                                   \             /
                                    \           /
                                     v         v
                   +---------------------------------------------+
                   | TriageResult with uncertainty & diagnostics |
                   | - to_report_fragment() (strict v1 schema)   |
                   +---------------------------------------------+
```

---

## 2. Uncertainty Taxonomy & Ordinal Confidence Bands

### 2.1 Categorical Uncertainty Types (`UncertaintyType`)
1. **`DATA_ABSENCE`**: A required observation was not available, not supplied, or omitted from scan inputs.
2. **`COLLECTION_FAILURE`**: A collector explicitly failed, dropped connection, or timed out (`status in ('failed', 'unavailable')`).
3. **`UNCHECKED_COVERAGE`**: A check was not run, safety-blocked by destination policy, or skipped due to budget exhaustion (`checks_not_run > 0`, `status in ('blocked', 'not_run')`).
4. **`TEMPORAL_STALENESS`**: Evidence age exceeds the source-specific freshness window defined in `FreshnessPolicy`.
5. **`EVIDENCE_CONFLICT`**: Contemporaneous observations materially disagree for the same target and scope/time window (e.g. `THREAT_FEED_MATCH` vs `NO_THREAT_MATCH`).

### 2.2 Ordinal Confidence Bands (`ConfidenceBand`)
> [!IMPORTANT]
> Confidence bands are qualitative policy categories, NOT calibrated mathematical probabilities. TRUSTTRACE strictly rejects presenting weighted heuristic scores as calibrated probabilities.

| Confidence Band | Definition | Triggering Condition |
| :--- | :--- | :--- |
| `SUFFICIENT_FOR_SCOPED_OBSERVATION` | All planned checks succeeded within freshness windows for the target. | 0 failures, 0 unchecked, 0 stale, 0 conflicts. |
| `LIMITED_OBSERVATION` | Assessment grounded in limited observation; some checks failed or were not completed. | Partial failures, unchecked coverage, or stale evidence present. |
| `INSUFFICIENT_EVIDENCE` | Insufficient evidence available to substantiate an affirmative verdict. | All required collectors failed or input failed contract validation. |
| `CONTRADICTORY_EVIDENCE` | Opposing observations exist for the same target and time window. | Contemporaneous behavioral, certificate, or reputation conflict. |

### 2.3 Configurable Source-Specific Freshness (`FreshnessPolicy`)
Rather than imposing an arbitrary universal freshness threshold, TRUSTTRACE configures source-appropriate windows:
- DNS resolution: 24 hours (86,400s)
- HTTP headers / redirect chains: 24 hours (86,400s)
- Threat intelligence / feeds: 12 hours (43,200s)
- TLS certificates: 7 days (604,800s)
- Community reputation: 48 hours (172,800s)
- Default fallback: 7 days (604,800s)

---

## 3. Abstention Engine & Plain-Language Rationales

When evaluation cannot reach an affirmative conclusion (`decision == "inconclusive"` or `band == CONTRADICTORY_EVIDENCE`), `UncertaintyEngine` generates a structured `AbstentionNotice`:
- **`reason_code`**: Standardized code (`ABSTAIN_EVIDENCE_CONFLICT`, `ABSTAIN_COLLECTION_FAILURE`, `ABSTAIN_UNCHECKED_COVERAGE`, `ABSTAIN_INSUFFICIENT_EVIDENCE`).
- **`affected_dimensions`**: Dimensions directly impacted by missing/conflicting data.
- **`missing_or_failed_checks`**: Exact collectors or checks that failed or were blocked.
- **`is_rescan_recommended`**: True if transient failure (network/timeout); False if safety-blocked destination or rate-limited.
- **`explanation`**: Plain-language explanation inserted into `TriageResult.limitations` so downstream consumers receive the rationale without violating v1 schema constraints.

---

## 4. Report Integrity Auditor (`ReportIntegrityAuditor`)

Enforces 6 invariant checks prior to report publication:

1. **`INV-TLS-001` (Identity Authorization vs TLS Validity)**:
   - Rejects reports where `dimensions.identity == "supported"` unless explicit, valid authorization evidence (`brand_authorization`, `domain_ownership`, `verified_identity`) is present in the scan evidence.
2. **`INV-EVID-002` (Affirmative Global Safety Claims)**:
   - Rejects affirmative global verdicts (`decision == "safe"` or `"clean"`).
   - Context-aware text inspection detects and rejects positive claims (`"this site is safe"`, `"guaranteed clean"`) while permitting negated disclaimers (`"does not establish that the site is safe"`).
3. **`INV-COV-001` (Coverage Invariant & No-Threat Scope)**:
   - Rejects `decision == "no_threat_observed"` under partial coverage (`checks_failed > 0` or `checks_not_run > 0`) if limitations omit partial coverage disclosure or if `evidence_quality == "strong"`.
4. **`INV-CLAIM-001` (Anti-Marketing Guard)**:
   - Detects unsupported absolute assertions (`"100% secure"`, `"bulletproof"`, `"zero false positives"`, `"guaranteed phishing-free"`).
   - Distinguishes affirmative claims from educational/negated phrasing (`"cannot guarantee 100% security"`).
5. **`INV-FINDING-001` (Finding Referential Integrity)**:
   - Rejects findings with empty `evidence_ids`.
   - Rejects findings citing evidence IDs that do not exist in the report's declared evidence records.
6. **`INV-COV-002` (Coverage Arithmetic Integrity)**:
   - Rejects reports where `checks_total != checks_observed + checks_failed + checks_not_run`.

---

## 5. Verification & Test Metrics
- **Total Tests**: 97 unit and integration tests passing in 0.010s.
- **Regressions**: 0 regressions on all 69 Phase 01, 02, and 03 tests.
- **Full Suite**: 223 tests passed across the entire repository in `run_tests.py` (0 failures, 1 skipped).
- **Worker Boundaries**: Locked strictly to `src/trusttrace/policy/`, `tests/test_triage_policy.py`, `.brain/`. Zero modifications to other workers or shared contracts.
