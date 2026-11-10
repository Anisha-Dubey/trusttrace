# Worker 03 Phase 03 — Safe Evidence Interpretation & Signal Extraction Pipeline

## Phase Summary
Phase 03 establishes a robust, deterministic bridge between canonical v1 evidence/community reports (Worker 02) and Worker 03's conservative policy triage engine. It enforces strict input validation, prevents silent record suppression, generates structured diagnostics, deterministically extracts typed signals, computes cryptographically stable finding IDs, and preserves positive threat evidence across partial collector runs.

---

## 1. Architectural Components

```
                   +---------------------------------------------+
                   | Canonical v1 Input Dictionary (Worker 02)   |
                   +---------------------------------------------+
                                          |
                                          v
                   +---------------------------------------------+
                   | policy_input.py (DTO Parsing & Immutability)|
                   | - EvidenceItem, CoverageSummary             |
                   | - CommunityReportItem, PolicyInput          |
                   | - ParseIssue, PolicyInputParseError         |
                   +---------------------------------------------+
                                          |
                                          v
                   +---------------------------------------------+
                   | input_validation.py (Structural & Semantic) |
                   | - Timestamp, status, target scope checks    |
                   | - Coverage arithmetic & duplicate ID checks |
                   | - Produces ValidationResult & Diagnostics   |
                   +---------------------------------------------+
                                          |
                                          v
                   +---------------------------------------------+
                   | signal_extractor.py (EvidenceSignalExtractor|
                   | - TLS valid/expired/mismatch & fixture map  |
                   | - DNS & target policy separation            |
                   | - Threat provenance & NO_THREAT_MATCH gate  |
                   | - Community corroboration & unverified gate |
                   +---------------------------------------------+
                                          |
                                          v
                   +---------------------------------------------+
                   | triage_engine.py (TriageEngine)             |
                   | - evaluate_evidence(PolicyInput)            |
                   | - Zero orphan findings (referential check)  |
                   | - Deterministic SHA-256 finding IDs         |
                   | - Positive threat preservation              |
                   | - Coverage limitation merger                |
                   +---------------------------------------------+
```

---

## 2. Immutability & Safety Discipline

1. **DTO Immutability**:
   - All DTOs are `@dataclass(frozen=True)`.
   - All collection containers are immutable tuples (`Tuple[..., ...]`).
   - All `unparsed_fields` and nested dictionary payload values are wrapped in read-only `types.MappingProxyType`. In-place key insertion or modification raises `TypeError`.
2. **No Silent Data Loss**:
   - Strict parsing (`strict=True`, default) raises `PolicyInputParseError` with all aggregated `ParseIssue` items.
   - Non-strict parsing (`strict=False`) captures issues in `PolicyInput.parse_issues` and disables evaluation via `policy_input.is_valid == False`.
3. **No Unsafe Type Coercion**:
   - `_is_exact_int()` rejects boolean flags as integer check counts.
   - Non-strings and blank strings are rejected for identifiers.
   - Bare strings are rejected for list/tuple fields (`limitations`, `linked_evidence_ids`).

---

## 3. Evidence-to-Signal Mapping Policy

| Upstream Evidence Category | Upstream Status & Attributes | Emitted Signal / Diagnostic | Assessment Dimension | Policy Rationale |
| :--- | :--- | :--- | :--- | :--- |
| `tls_certificate` | `observed`, `is_valid=True`, `hostname_match=True`, `is_expired=False` | `TLS_VALID`, `TLS_HOSTNAME_MATCH`, `COLLECTOR_SUCCESS` | `CERTIFICATE`, `IDENTITY`, `EVIDENCE_QUALITY` | Invariant TLS-001: Encryption valid; identity remains unverified. |
| `tls_certificate` | `observed`, `is_expired=True` | `TLS_EXPIRED` | `CERTIFICATE` | Invariant TLS-002: Technical error; not sole proof of phishing. |
| `tls_certificate` | `observed`, `hostname_match=False` | `TLS_MISMATCH` | `CERTIFICATE` | Technical anomaly; preserves SAN mismatch. |
| `tls_hostname_validation` | `observed`, `result="valid_for_hostname"` | `TLS_HOSTNAME_MATCH`, `COLLECTOR_SUCCESS` | `IDENTITY`, `EVIDENCE_QUALITY` | Fixture hostname check only; CANNOT establish certificate validity or expiry. |
| `tls_certificate` | `failed` / `unavailable` | `TLS_UNAVAILABLE`, `COLLECTOR_FAILURE` | `CERTIFICATE`, `EVIDENCE_QUALITY` | Handshake timeout or connection drop. |
| `dns_resolution` | `observed`, valid IP list | `COLLECTOR_SUCCESS` | `EVIDENCE_QUALITY` | Proves DNS resolution success only; does not infer overall scan success. |
| `dns_resolution` | `blocked` / loopback IP | `BLOCKED_DESTINATION_POLICY` (diagnostic) | `N/A` (Diagnostic) | Distinguishes safety policy gate from collector failure. |
| `target_policy` | `blocked` | `BLOCKED_DESTINATION_POLICY` (diagnostic) | `N/A` (Diagnostic) | Egress policy enforcement; not an infrastructure failure. |
| `threat_intelligence` | `observed`, `matched=True`, verified provider | `THREAT_FEED_MATCH`, `COLLECTOR_SUCCESS` | `BEHAVIOR`, `EVIDENCE_QUALITY` | Verified malicious match; sets disposition ceiling to high_risk. |
| `threat_intelligence` | `observed`, `matched=False`, clean feed query | `NO_THREAT_MATCH`, `COLLECTOR_SUCCESS` | `BEHAVIOR`, `EVIDENCE_QUALITY` | Invariant EVID-002: Negative match within checked scope; never "safe". |
| `threat_intelligence` | `failed` / `unavailable` | `COLLECTOR_FAILURE` | `EVIDENCE_QUALITY` | Query failed; NEVER emits NO_THREAT_MATCH. |
| `threat_intelligence` | `untrusted` reliability | `UNVERIFIED_THREAT_PROVENANCE` (diagnostic) | `N/A` (Diagnostic) | Untrusted threat feed signals are suppressed. |
| `community_reports` | `verified`, $\ge 2$ independent sources | `COMMUNITY_REPORT_CORROBORATED` | `BEHAVIOR` | Independent corroboration elevates behavior to suspicious. |
| `community_reports` | `unverified` or 1 source | `COMMUNITY_REPORT_UNVERIFIED` | `BEHAVIOR` | Invariant COMM-001: Unverified reports stay unverified; no auto-label. |
| `community_reports` | `disputed` | `COMMUNITY_REPORT_DISPUTED` | `BEHAVIOR` | Invariant COMM-003: Retains both trails without resolution. |
| Unsupported kind | any | `UNSUPPORTED_EVIDENCE_KIND` (diagnostic) | `N/A` (Diagnostic) | Never fabricates signals from unrecognized evidence kinds. |

---

## 4. Referential Integrity & Deterministic Finding IDs

1. **Deterministic Finding IDs**:
   - Algorithm: Canonical JSON serialization of `{"evidence_ids": sorted(evidence_ids), "rule_id": rule_id, "scan_id": scan_id}`.
   - Hash: Full SHA-256 (64 hexadecimal characters) prefixed with `finding-`.
   - Invariants: Permutation invariant (`sorted()`) and cross-scan separated (`scan_id`).
2. **Zero Orphan Findings**:
   - Before emitting findings, `TriageEngine.evaluate_evidence()` cross-references every evidence ID in `finding["evidence_ids"]` against known `policy_input.evidence` and `policy_input.community_reports`.
   - Findings citing missing evidence IDs are completely suppressed.
   - A structured diagnostic (`DiagnosticCode.ORPHAN_FINDING_SUPPRESSED`) is appended to audit logs and results.

---

## 5. Verification & Test Metrics
- **Total Tests**: 69 unit tests passing in 0.007s.
- **Regressions**: 0 regressions on all 29 original Phase 01 & 02 tests.
- **Worker Boundaries**: Locked to `src/trusttrace/policy/`, `tests/test_triage_policy.py`, `.brain/`. Zero modifications to other workers or shared contracts.

