# Worker 03 — Phase 07: Multimodal Availability Masking & Missing-Modality Ablation

## Executive Summary
Phase 07 operationalizes Sections 9.1–9.4 of the *TRUSTTRACE Complete ML Research & Engineering Handbook*, introducing a formal multimodal availability gating architecture and comprehensive missing-modality ablation test suite within Worker 03 ownership boundaries.

Prior to Phase 07, evidence fusion evaluated signals without explicitly modeling whether missing modalities stemmed from collection failures, target scheme non-applicability (e.g. plain HTTP), policy blocks, or incomplete execution. Phase 07 establishes mathematically rigorous multimodal masking, preserving partial collection telemetry, verifying target scheme applicability via conservative URL parsing, and enforcing deterministic truth tables across all 32 combinations of evidence statuses.

---

## Architecture & Implementation Scope

### 1. Robust Target URL & Scheme Parsing (`src/trusttrace/policy/fusion.py`)
- Target evaluation uses `urllib.parse.urlsplit` to reliably separate scheme, hostname, and port.
- Bare domains (e.g. `example.com`) default to `https://` per Handbook Section 9.2.
- Explicit `http://` targets mark TLS as non-applicable (`is_tls_applicable = False`), permitting scoped clean observations when DNS and Threat Intelligence are verified.
- Malformed URLs, empty hostnames, and unsupported schemes (e.g. `ftp://`, `ws://`) fail target validation and immediately yield `decision: "inconclusive"` with `DiagnosticCode.INPUT_PARSE_ERROR`.

### 2. Four-Stage Evidence Modality Classifier
Evidence items are mapped into canonical modalities (`DNS`, `TLS`, `THREAT_INTEL`, `COMMUNITY`, `UNKNOWN`) through a 4-stage hierarchy:
1. **Stage 1 (Exact Kind Matching):** Explicit kinds (`dns_resolution`, `tls_certificate`, `threat_intelligence`, `community_report`).
2. **Stage 2 (Exact Source Matching):** Dedicated collectors (`dns_collector`, `tls_collector`, `threat_collector`, `community_service`), deliberately excluding generic adapters like `fixture_adapter`.
3. **Stage 3 (Controlled Prefix Matching):** Modality prefixes (`dns_`, `tls_`, `ssl_`, `threat_`, `community_`).
4. **Stage 4 (Unknown Modality Dispatch):** Unfamiliar kinds/sources map to `ModalityKind.UNKNOWN`, are preserved in `unmapped_records`, and emit `DiagnosticCode.UNSUPPORTED_EVIDENCE_KIND`.

### 3. Exhaustive 32-Subset Deterministic Status Aggregation
For each modality, raw evidence statuses $S_m \subseteq \{\text{observed}, \text{failed}, \text{blocked}, \text{unavailable}, \text{not\_run}\}$ are mapped into canonical `ModalityStatus`:
- Precedence: $\text{OBSERVED} > \text{BLOCKED} > \text{FAILED} > \text{UNAVAILABLE} > \text{NOT\_RUN} > \text{MISSING}$.
- Observation quality assessment separates pure observations without degradation (`OBSERVED_COMPLETE`) from mixed or degraded observations (`OBSERVED_PARTIAL`).
- All 32 power-set subsets $\mathcal{P}(\text{Statuses})$ resolve deterministically with zero unhandled combinations.

### 4. Safety Invariants & Decision Gating (`TriagePolicyEngine`)
- **Positive Threat Preservation (Rule 1 Invariant):** Verified malicious indicators (`THREAT_FEED_MATCH`) bypass missing-modality gates and maintain `high_risk` even if unrelated collectors (e.g. DNS or TLS) fail.
- **Negative Threat Baseline Discipline (Rule 5 Invariant):** Clean claims (`no_threat_observed`) require complete negative threat intelligence, verified DNS resolution without failures, and valid TLS (if HTTPS).
- **Reconciled Partial DNS Policy (ABL-07 Invariant):** A single successful DNS resolution cannot permit a clean baseline if accompanied by failed DNS checks (`OBSERVED_PARTIAL` with failures drops `evidence_quality` to `partial`, enforcing `inconclusive`).
- **Freshness & Provenance Enforcement:** Threat intelligence older than 12 hours (43,200s) or marked `untrusted` emits `STALE_EVIDENCE_FLAGGED` or `UNVERIFIED_THREAT_PROVENANCE` and cannot establish a clean baseline.

---

## Ablation Test Matrix Coverage (`tests/test_triage_policy.py`)

All 14 Phase 07 test scenarios pass cleanly in `TestPhase07MultimodalAblationAndMasking`:
1. `test_01_target_validation_and_scheme_applicability`: Validates ports, bare domains, plain HTTP, and rejects malformed targets.
2. `test_02_truth_table_all_32_subsets_deterministic`: Programmatically verifies all 32 status combinations across both clean and warning paths.
3. `test_03_abl_01_full_baseline_observation`: Full clean baseline across DNS, TLS, and Threat Intel on HTTPS -> `no_threat_observed`.
4. `test_04_abl_02_plain_http_clean_baseline`: Plain HTTP clean baseline -> TLS non-applicable -> `no_threat_observed`.
5. `test_05_abl_03_missing_dns_resolution`: Missing DNS resolution -> `COVERAGE_DEFICIT` -> `inconclusive`.
6. `test_06_abl_04_missing_threat_intelligence`: Missing Threat Intel -> `COVERAGE_DEFICIT` -> `inconclusive`.
7. `test_07_abl_05_positive_threat_overrides_missing_modalities`: Positive threat overrides failed/missing modalities -> `high_risk`.
8. `test_08_abl_06_tls_cert_expired_on_https`: Expired TLS certificate on HTTPS target -> `invalid_or_expired` cert dimension, `certificate_issue` finding.
9. `test_09_abl_07_partial_dns_with_failure_yields_inconclusive`: Partial DNS with collector failure -> `inconclusive` (Rule 5 preserved).
10. `test_10_abl_08_blocked_threat_feed`: Threat feed blocked by policy -> `inconclusive`.
11. `test_11_abl_09_untrusted_threat_provenance_cannot_establish_clean`: Untrusted threat provenance -> `inconclusive`.
12. `test_12_abl_10_stale_threat_intelligence_cannot_establish_clean`: Stale threat intelligence (>12h) -> `inconclusive` with `STALE_EVIDENCE_FLAGGED`.
13. `test_13_abl_11_malformed_url_and_empty_host`: Malformed URL/host -> `INPUT_PARSE_ERROR` -> `inconclusive`.
14. `test_14_abl_12_unknown_evidence_records_preserved`: Unknown evidence kind preserved in `unmapped_records` with `UNSUPPORTED_EVIDENCE_KIND`.

---

## Verification & Test Metrics
- **Worker 03 Tests:** 143 passed in `tests/test_triage_policy.py` in 0.152s (100% pass rate).
- **Full Repository Suite:** 315 tests discovered (314 passed, 1 skipped live DB test, 0 failures, 0 errors).
- **Contract & Fixture Invariants:** 8/8 passed.
- **Worker Boundary Isolation:** Modality fusion is completely contained within Worker 03. Zero shared contracts or external worker files were altered.

