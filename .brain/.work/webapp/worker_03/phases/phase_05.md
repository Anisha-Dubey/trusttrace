# Worker 03 Phase 05 — Evaluation & Regression Engineering

## Phase Summary
Phase 05 hardens the explainable triage policy engine by implementing automated regression detection, expanding the controlled evaluation suite from 7 to 15 golden fixtures across versioned suites (`w03-eval-v1` and `w03-eval-v2`), establishing serializable decision audit logging without persistent database coupling, and introducing property-based permutation and fuzz testing to verify policy invariant preservation.

---

## 1. Architectural Components

```
                   +-------------------------------------------------+
                   | evaluation.py                                   |
                   | - FIXTURES_V1 (FIX-001..FIX-007, Immutable)     |
                   | - FIXTURES_V2 (FIX-001..FIX-015, Expanded Suite)|
                   | - build_eval_v1_set(), build_eval_v2_set()      |
                   | - ControlledEvaluationSet & ClaimAuditor        |
                   +-------------------------------------------------+
                                           |
                                           v
                   +-------------------------------------------------+
                   | regression.py (PolicyRegressionRunner)          |
                   | - capture_baseline_snapshot()                   |
                   | - run_regression_against_baseline()             |
                   | - RegressionDiffReport (zero false regressions) |
                   +-------------------------------------------------+
                                           |
                                           v
                   +-------------------------------------------------+
                   | decision_log.py (DecisionAuditRecord)           |
                   | - to_semantic_dict() (excludes IDs/timestamps)  |
                   | - DecisionLog.record_audit() (in-memory audit)  |
                   +-------------------------------------------------+
                                           |
                                           v
                   +-------------------------------------------------+
                   | tests/test_triage_policy.py                     |
                   | - TestPolicyRegression (drift & shift detection)|
                   | - TestExpandedFixtures (15/15 golden test cases)|
                   | - TestPolicyInvariantsAndFuzzing (fuzz & order) |
                   +-------------------------------------------------+
```

---

## 2. Controlled Evaluation Fixture Evolution

### 2.1 Suite Architecture
- **`w03-eval-v1` (Frozen Baseline)**: Contains the original 7 Phase 02 fixtures. Immutable, frozen upon construction, guaranteed backward compatibility.
- **`w03-eval-v2` (Expanded Suite)**: Contains all 15 fixtures (`FIX-001` through `FIX-015`). Covers new edge cases identified during cross-worker integration and boundary specification.
- **Honest Labeling**: Every fixture in both suites is explicitly marked `is_simulated = True`. Results measure policy deterministic consistency, NOT real-world phishing detection accuracy.

### 2.2 Complete 15-Fixture Matrix

| Fixture ID | Category / Scenario | Input Signals | Expected Dimensions | Expected Decision | Design Principle Tested |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FIX-001** | Baseline clean site | `tls_valid`, `tls_hostname_match`, `no_threat_match`, `collector_success` | identity: `unverified`<br>cert: `valid_for_hostname`<br>behavior: `no_threat_observed`<br>ev_quality: `strong` | `no_threat_observed` | EVID-002: absence of threat is not affirmative safe. TLS-001: TLS validity does not support identity. |
| **FIX-002** | Known threat match | `threat_feed_match`, `collector_success` | behavior: `malicious_evidence`<br>ev_quality: `strong` | `high_risk` | Positive threat evidence directly elevates disposition to high_risk. |
| **FIX-003** | Expired TLS alone | `tls_expired`, `collector_success` | cert: `invalid_or_expired`<br>identity: `unknown`<br>ev_quality: `strong` | `inconclusive` | TLS-002: technical certificate error is not sole proof of active hostility. |
| **FIX-004** | All collectors failed | `collector_failure` | ev_quality: `unavailable` | `inconclusive` | EVID-001: complete collection failure forces honest abstention. |
| **FIX-005** | Conflicting feeds | `threat_feed_match`, `no_threat_match`, `collector_success` | ev_quality: `partial` | `inconclusive` | EVID-004: material contradiction caps verdict at inconclusive, retaining both sides. |
| **FIX-006** | Corroborated report | `community_report_corroborated`, `collector_success` | behavior: `suspicious`<br>ev_quality: `strong` | `caution` | Multi-source community corroboration elevates behavior to suspicious. |
| **FIX-007** | Stale evidence only | `stale_evidence` | ev_quality: `weak` | `inconclusive` | EVID-003: stale evidence without fresh observations degrades quality to weak. |
| **FIX-008** | Legitimate expired TLS | `tls_expired`, `tls_hostname_match`, `no_threat_match`, `collector_success` | cert: `invalid_or_expired`<br>identity: `unverified`<br>behavior: `no_threat_observed`<br>ev_quality: `strong` | `no_threat_observed` | TLS-002: expired certificate on legitimate site with clean threat feed does not trigger high_risk. |
| **FIX-009** | IDN Lookalike Candidate | `idn_lookalike`, `tls_valid`, `tls_hostname_match`, `collector_success` | identity: `unverified`<br>cert: `valid_for_hostname`<br>behavior: `unknown`<br>ev_quality: `strong` | `inconclusive` | IDN candidate signal keeps identity unverified without asserting definitive impersonation. |
| **FIX-010** | Blocked private target | `collector_failure` (limitation: `blocked_private_target`) | ev_quality: `unavailable` | `inconclusive` | Upstream destination safety blocks abstain truthfully with unavailable quality. |
| **FIX-011** | Stale threat observation | `stale_evidence`, `threat_feed_match`, `collector_success` | behavior: `malicious_evidence`<br>ev_quality: `partial` | `high_risk` | Positive threat evidence preservation: threat match is retained despite staleness. |
| **FIX-012** | Rate-limited collector | `collector_failure` (limitation: `upstream_rate_limited`) | ev_quality: `unavailable` | `inconclusive` | Uses valid v1 failure status without fabricating invalid status schema codes. |
| **FIX-013** | Worker 02 corroborated | `community_report_corroborated`, `collector_success` | behavior: `suspicious`<br>ev_quality: `strong` | `caution` | Verifies Worker 02 independent-source corroboration handoff into policy caution. |
| **FIX-014** | Complete timeout | `collector_failure` (limitation: `network_timeout_all_collectors`) | ev_quality: `unavailable` | `inconclusive` | Complete network timeout forces total abstention. |
| **FIX-015** | Conflicting providers | `threat_feed_match`, `no_threat_match`, `conflicting_signals`, `collector_success` | behavior: `malicious_evidence`<br>ev_quality: `partial` | `inconclusive` | Retains both positive and negative evidence; caps decision at inconclusive. |

---

## 3. Policy Regression Architecture (`regression.py`)

### 3.1 Design Principles
1. **Zero False Regressions**: Nondeterministic fields (event IDs, UUIDs, ISO timestamps) are excluded from baseline snapshot comparisons via `to_semantic_dict()`.
2. **Deep Semantic Diffing**: Detects decision shifts, individual dimension value changes, and rule firing modifications across engine versions.
3. **Structured Reporting**: Produces `RegressionDiffReport` with explicit list of regressions, passed counts, and deterministic JSON/dict serialization.

### 3.2 Regression Runner Interface
```python
runner = PolicyRegressionRunner(triage_engine=engine)

# Capture baseline snapshot
snapshot = runner.capture_baseline_snapshot(eval_set)

# Run regression check against candidate engine
diff = runner.run_regression_against_baseline(candidate_engine, snapshot, eval_set)
if diff.has_regressions:
    print(f"Detected {len(diff.decision_shifts)} decision regressions!")
```

---

## 4. Decision Audit Records (`decision_log.py`)

`DecisionAuditRecord` provides an immutable, lightweight audit structure:
- Captures: `audit_id`, `scan_id`, `target`, `policy_version`, `canonical_input_fingerprint`, `decision`, `dimensions`, `fired_rule_ids`, `uncertainty_codes`, `confidence_band`, `evidence_ids`, `finding_ids`, `limitations`, `timestamp`.
- Method `to_semantic_dict()`: Extracts canonical semantic fields only, guaranteeing stable equality checks across runs.
- In-memory collection via `DecisionLog.record_audit()` without introducing external database requirements.

---

## 5. Invariant & Fuzzing Suite (`test_triage_policy.py`)

### 5.1 Permutation Invariance
Verifies that changing signal presentation order (reversed or randomly shuffled) never alters the triage outcome:
$$\text{evaluate}(\text{signals}).\text{decision} = \text{evaluate}(\text{reversed}(\text{signals})).\text{decision}$$
$$\text{evaluate}(\text{signals}).\text{dimensions} = \text{evaluate}(\text{reversed}(\text{signals})).\text{dimensions}$$

### 5.2 Fixed-Seed Property-Based Fuzzing
- Seed: `random.Random(1337)`
- Iterations: 150 randomized combinations of valid signals from `SignalKind`
- Invariants strictly verified on every iteration:
  1. No unhandled exceptions.
  2. Decision in legal non-affirmative set (`high_risk`, `caution`, `no_threat_observed`, `inconclusive`).
  3. Never produces `safe`, `clean`, `benign`, or `secure` (EVID-002).
  4. All four dimensions present and non-empty.
  5. `identity == "supported"` strictly requires `AUTHORIZATION_EVIDENCE` (TLS-001).
  6. `evidence_quality == "unavailable"` cannot produce `no_threat_observed` (EVID-001).

---

## 6. Acceptance Criteria Verification

- [x] Canonical Phase 02 fixtures remain immutable and frozen (`build_eval_v1_set()`, 7/7 passing).
- [x] Expanded Phase 05 fixture suite (`build_eval_v2_set()`, 15/15 passing).
- [x] All 15 fixtures evaluate to exact expected decisions and dimensions.
- [x] Policy regression comparisons detect deliberate verdict shifts, dimension changes, and rule trace diffs with zero false positives.
- [x] Permutation invariance holds across forward, reverse, and shuffled signal sequences.
- [x] 150-iteration fixed-seed fuzz testing verifies zero invariant violations or unhandled exceptions.
- [x] All 248 repository unit and integration tests pass (1 skipped).
- [x] Boundary checks pass cleanly with 0 boundary violations.
