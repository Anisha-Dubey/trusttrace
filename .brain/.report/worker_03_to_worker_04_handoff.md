# TRUSTTRACE — WORKER 03 TO WORKER 04 IMPLEMENTATION HANDOFF

**Author:** Worker 03 (Risk Policy, Evidence Interpretation, Uncertainty & Claim Discipline)
**Target Recipient:** Worker 04 (Web Interface, Evidence Passport Presentation & Stage Demos)
**Date:** 2026-11-10
**Baseline Git Commit:** `7354365058f101e5ada2af34e7ccb0eb2309dbc2`
**Companion Document:** [`.brain/.report/worker_03_worker_04_conflict_register.md`](file:///c:/Users/adity/OneDrive/Desktop/HackMatrix26/.brain/.report/worker_03_worker_04_conflict_register.md)
**Status:** READY FOR WORKER 04 EXECUTION

---

## 1. Executive Summary & Purpose

This handoff provides Worker 04 with a step-by-step, actionable implementation roadmap to remediate all 12 identified conflicts in the Conflict Register.

Every code snippet in this guide references the **actual public interfaces** implemented by Worker 03 in `src/trusttrace/policy/`. Worker 04 can implement these fixes directly without guessing parameter ordering, field names, return types, or invariant behaviors.

---

## 2. Phase 1: Immediate Critical Fixes (Hotfixes)

### 2.1 Fix `SignalRecord` Invocations in `src/trusttrace/web/routes.py` (CONFL-01, CONFL-02)

#### The Problem:
`SignalRecord`'s dataclass constructor requires:
```python
SignalRecord(kind, evidence_ids, source, confidence=..., value=..., limitations=...)
```
Passing strings as argument 2 triggers a fatal `TypeError` at runtime.

#### The Fix:
Worker 03 provides two safe ways to instantiate `SignalRecord`:

##### Pattern A: Using `SignalRecord.create()` (Recommended)
`SignalRecord.create()` accepts either a single string ID or a list of IDs for `evidence_ids`:
```python
from trusttrace.policy.signal_taxonomy import SignalRecord, SignalKind, SignalConfidence

# In scenario "phishing_lookalike" (lines 42–46):
signals = [
    SignalRecord.create(
        kind=SignalKind.TLS_VALID,
        source="tls_collector",
        evidence_ids=["ev-tls-001"],
        value={"is_valid": True},
        limitations=["Valid DV TLS proves transport encryption only, not identity."],
    ),
    SignalRecord.create(
        kind=SignalKind.TLS_HOSTNAME_MATCH,
        source="tls_collector",
        evidence_ids=["ev-tls-001"],
        value={"hostname_match": True},
    ),
    SignalRecord.create(
        kind=SignalKind.IDN_LOOKALIKE,
        source="url_policy",
        evidence_ids=["ev-idn-003"],
        value={"confusable": True, "script": "Cyrillic"},
        limitations=["IDN homoglyph is a heuristic candidate; not sole proof of impersonation."],
    ),
    SignalRecord.create(
        kind=SignalKind.COLLECTOR_SUCCESS,
        source="intake_boundary",
        evidence_ids=["ev-intake-001"],
        value={"url_safe": True},
    ),
]
```

##### Pattern B: In Scenario "expired_tls" (lines 103–105):
```python
signals = [
    SignalRecord.create(
        kind=SignalKind.TLS_EXPIRED,
        source="tls_collector",
        evidence_ids=["ev-tls-exp-01"],
        value={"is_expired": True, "days_expired": 5},
        limitations=["Certificate is expired; technical hygiene warning, not sole proof of malice."],
    ),
    SignalRecord.create(
        kind=SignalKind.COLLECTOR_SUCCESS,
        source="intake_boundary",
        evidence_ids=["ev-intake-001"],
    ),
]
```

### 2.2 Eliminate Fabricated `NO_THREAT_MATCH` Signal (CONFL-09)
In custom URL triage (line 154):
**REMOVE:**
```python
SignalRecord(SignalKind.NO_THREAT_MATCH, "reputation_feed", "No negative blacklist entry observed")  # VIOLATES EVID-002
```
**REPLACE WITH:**
```python
signals = [
    SignalRecord.create(
        kind=SignalKind.COLLECTOR_SUCCESS,
        source="intake_boundary",
        evidence_ids=["ev-live-intake-01"],
        value={"intake_valid": True},
        limitations=["Passed URL policy and SSRF boundary."],
    )
]
```
*Note: In the absence of an executed reputation feed query, `UncertaintyEngine` will truthfully report `UNCHECKED_COVERAGE` on behavior.*

---

## 3. Phase 2: API and Contract Compatibility Fixes

### 3.1 Adopt `PolicyInput` and `TriageEngine.evaluate_evidence()` (CONFL-03, CONFL-05)

Instead of calling `TriageEngine.evaluate(signals)`, pass canonical evidence structures to `evaluate_evidence()`:

```python
from trusttrace.policy.policy_input import PolicyInput
from trusttrace.policy.triage_engine import TriageEngine

# Build canonical PolicyInput
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
            "value": {
                "is_valid": True,
                "hostname_match": True,
                "san": ["bank-secure-lоgin.com"]
            },
            "limitations": ["Valid DV TLS proves transport encryption only, not identity."]
        },
        {
            "evidence_id": "ev-idn-003",
            "kind": "url_canonicalization",
            "source": "url_policy",
            "observed_at": "2026-11-10T00:30:00Z",
            "status": "observed",
            "reliability": "high",
            "value": {"has_homoglyphs": True},
            "limitations": ["Unicode confusable homoglyph detected."]
        }
    ],
    coverage={
        "checks_total": 4,
        "checks_observed": 3,
        "checks_failed": 0,
        "checks_not_run": 1
    },
    scan_profile="standard",
    strict=True
)

engine = TriageEngine()
triage_result = engine.evaluate_evidence(policy_input)
```

### 3.2 Canonical Report Assembly (CONFL-06)
Assemble the complete candidate report compliant with `scan_report.schema.json`:

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
    "decision": triage_result.decision,
    "policy_version": triage_result.policy_version,
    "dimensions": dict(triage_result.dimensions),
    "coverage": {
        "checks_total": policy_input.coverage.checks_total,
        "checks_observed": policy_input.coverage.checks_observed,
        "checks_failed": policy_input.coverage.checks_failed,
        "checks_not_run": policy_input.coverage.checks_not_run,
    } if policy_input.coverage else None,
    "findings": list(triage_result.findings),
    "evidence": [
        {
            "evidence_id": e.evidence_id,
            "kind": e.kind,
            "source": e.source,
            "observed_at": e.observed_at,
            "status": e.status,
            "reliability": e.reliability,
            "limitations": list(e.limitations),
        }
        for e in policy_input.evidence
    ],
    "uncertainty": triage_result.uncertainty.to_dict() if triage_result.uncertainty else None,
    "limitations": list(triage_result.limitations),
}
```

### 3.3 Enforce `ReportIntegrityAuditor` Pre-Publication Gate (CONFL-08)
Audit the report before sending it to the client:

```python
audit_res = engine.audit_report(candidate_report)
if not audit_res.is_valid:
    error_details = [f"[{i.rule_id}] {i.explanation}" for i in audit_res.issues if i.severity.value == "error"]
    raise HTTPException(status_code=500, detail=f"Report failed integrity audit: {error_details}")

return candidate_report
```

---

## 4. Phase 3: UI and Uncertainty Integration (CONFL-07, CONFL-10)

### 4.1 Expose Uncertainty in the Web Interface Response
The `uncertainty` dictionary contains:
- `confidence_band`: e.g. `"sufficient_for_scoped_observation"` or `"limited_observation"`
- `abstention_notice`: Optional object with `reason_code`, `explanation`, `is_rescan_recommended`
- `affected_dimensions`: e.g. `{"behavior": ["unchecked_coverage"]}`

### 4.2 Render Confidence Band & Abstention Banner in HTML/JS
Update the client-side JavaScript in `routes.py` (and standalone `index.html`):

```javascript
function renderPassport(data) {
  // 1. Existing badges...

  // 2. Confidence Band Badge
  const unc = data.uncertainty || {};
  const confBand = unc.confidence_band || 'limited_observation';
  const confBandEl = document.getElementById('confidenceBandBadge');
  if (confBandEl) {
    confBandEl.textContent = 'Confidence: ' + confBand.replace(/_/g, ' ');
    confBandEl.className = confBand === 'sufficient_for_scoped_observation' ?
      'px-2.5 py-1 rounded-lg bg-emerald-500/20 text-emerald-400 font-mono text-xs' :
      'px-2.5 py-1 rounded-lg bg-amber-500/20 text-amber-400 font-mono text-xs';
  }

  // 3. Abstention Banner
  const abstentionBanner = document.getElementById('abstentionBanner');
  if (unc.abstention_notice) {
    abstentionBanner.classList.remove('hidden');
    document.getElementById('abstentionReason').textContent = unc.abstention_notice.reason_code;
    document.getElementById('abstentionExplanation').textContent = unc.abstention_notice.explanation;
    document.getElementById('rescanNotice').textContent = unc.abstention_notice.is_rescan_recommended ?
      'Rescan recommended once network budget resets.' : 'Permanent policy abstention.';
  } else if (abstentionBanner) {
    abstentionBanner.classList.add('hidden');
  }
}
```

### 4.3 Clean Community Form Submission (CONFL-10)
In `routes.py` (HTML template line 712):
```javascript
const cleanDomain = domainInput.value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

const payload = {
  normalized_domain: cleanDomain,
  claim_type: claimType,
  note: noteInput.value.trim(),
};
```
*Note: Do not include `reporter_id` in the JSON.*

---

## 5. Phase 4: Real End-to-End Pipeline Integration (CONFL-12)

For custom URLs, connect the actual Worker 01 collectors and Worker 02 persistence:

```python
from trusttrace.intake.boundary import IntakeBoundary
from trusttrace.collectors.orchestrator import ScanOrchestrator
from trusttrace.evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
from trusttrace.evidence.services.evidence_service import EvidenceService

@router.post("/api/v1/triage/demo")
async def triage_demo_endpoint(payload: TriageDemoRequest):
    url = payload.url.strip()
    scenario = payload.scenario or "custom"

    # Pre-canned fixtures for scenarios...
    if scenario == "legitimate": ...
    if scenario == "phishing_lookalike": ...
    if scenario == "expired_tls": ...
    if scenario == "conflicting": ...

    # Custom URL Live Pipeline:
    boundary = IntakeBoundary()
    is_safe, code, msg, rej_report = boundary.evaluate_url(url, "scan-live-user-001")
    if not is_safe and rej_report:
        return rej_report

    # Execute Bounded Collectors
    orchestrator = ScanOrchestrator(timeout_budget=5.0)
    collection_result = orchestrator.execute(url)

    # Adapt into Evidence Models
    adapter = Worker01EvidenceAdapter()
    evidence_items = adapter.to_evidence_items(collection_result)

    # Persist via Worker 02
    service = EvidenceService()
    persisted_batch = service.ingest_evidence_batch("scan-live-user-001", evidence_items)

    # Evaluate Policy via Worker 03
    policy_input = PolicyInput.from_components(
        scan_id="scan-live-user-001",
        target=url.split("//")[-1].split("/")[0].split(":")[0],
        evidence=persisted_batch.evidence,
        coverage=persisted_batch.coverage,
    )
    engine = TriageEngine()
    triage_result = engine.evaluate_evidence(policy_input)
    candidate_report = build_canonical_report(policy_input, triage_result)

    # Audit & Return
    engine.audit_report(candidate_report)
    return candidate_report
```

---

## 6. Phase 5: Automated Regression Testing (CONFL-11)

Worker 04 must add `tests/test_web_interface.py` to test all scenarios and prevent regressions:

### Required Test Suite Structure:
```python
"""Tests for Worker 04 Interactive Web Interface and Triage Routes."""

import unittest
from fastapi.testclient import TestClient
from trusttrace.api.app import create_app

class TestWebInterface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = TestClient(cls.app)

    def test_dashboard_html_served_successfully(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("TRUSTTRACE", res.text)
        self.assertIn("Evidence Passport", res.text)

    def test_triage_scenario_phishing_lookalike(self):
        res = self.client.post("/api/v1/triage/demo", json={"url": "https://bank-secure-lоgin.com", "scenario": "phishing_lookalike"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["decision"], "caution")
        self.assertEqual(data["dimensions"]["identity"], "unverified")
        self.assertEqual(data["dimensions"]["certificate"], "valid_for_hostname")

    def test_triage_scenario_expired_tls(self):
        res = self.client.post("/api/v1/triage/demo", json={"url": "https://legacy.corp", "scenario": "expired_tls"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["decision"], "caution")
        self.assertEqual(data["dimensions"]["certificate"], "invalid_or_expired")

    def test_triage_scenario_legitimate(self):
        res = self.client.post("/api/v1/triage/demo", json={"url": "https://example.com", "scenario": "legitimate"})
        self.assertEqual(res.status_code, 200)

    def test_triage_scenario_conflicting(self):
        res = self.client.post("/api/v1/triage/demo", json={"url": "https://disputed.io", "scenario": "conflicting"})
        self.assertEqual(res.status_code, 200)

    def test_custom_url_valid_target(self):
        res = self.client.post("/api/v1/triage/demo", json={"url": "https://github.com", "scenario": "custom"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data.get("status"), "completed")

    def test_custom_url_ssrf_rejection(self):
        res = self.client.post("/api/v1/triage/demo", json={"url": "http://127.0.0.1:8000/admin", "scenario": "custom"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "rejected")

    def test_custom_url_embedded_credentials_rejection(self):
        res = self.client.post("/api/v1/triage/demo", json={"url": "https://user:pass@bank.com", "scenario": "custom"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "rejected")

if __name__ == "__main__":
    unittest.main()
```

---

## 7. Acceptance Criteria Checklist for Worker 04

Worker 04 will be certified as integration-ready when:
- [ ] `SignalRecord.create()` is used across all routes without `TypeError`.
- [ ] Zero fabricated `NO_THREAT_MATCH` signals are emitted.
- [ ] `TriageEngine.evaluate_evidence()` and `PolicyInput` are integrated.
- [ ] Every candidate report passes `ReportIntegrityAuditor` before returning.
- [ ] `uncertainty` (confidence band and abstention notice) is exposed in API and rendered in UI.
- [ ] Community form sanitizes domain names and omits `reporter_id`.
- [ ] `tests/test_web_interface.py` is committed and all 8 tests pass in `python run_tests.py`.
- [ ] `python scripts/check_worker_boundaries.py` reports `[PASS]`.
