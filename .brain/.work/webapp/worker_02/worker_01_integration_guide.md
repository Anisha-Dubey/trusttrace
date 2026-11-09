# Worker 01 Integration Guide: Submitting Observations to Worker 02

This guide specifies how **Worker 01 (Intake & Safe Collectors)** passes validated network observations to **Worker 02 (Evidence Intelligence & Persistence)** without architectural coupling.

---

## 1. Golden Rule of Separation

- **Worker 01** owns: URL canonicalization, credential blocking, IDNA punycode handling, query token redaction, SSRF validation, DNS destination classification, connection-time rebinding defense, hop-capped redirects, and passive collectors.
- **Worker 02** owns: Evidence ingestion, contract validation, idempotency, persistence, coverage calculations, provenance tracking, finding linkage, and community threat intelligence.
- **Worker 02 NEVER imports internal Worker 01 networking modules** (`dns_resolver`, `ip_classifier`, `redirect_policy`).
- All communication occurs across the stable `Worker01EvidenceAdapter` contract or via the REST API (`POST /api/v1/evidence/ingest`).

---

## 2. Adapter Contract Interface

Worker 02 provides `Worker01EvidenceAdapter`:

```python
from trusttrace.evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
from trusttrace.evidence.services.evidence_service import EvidenceService

adapter = Worker01EvidenceAdapter()
batch = adapter.adapt_payload(scan_id="scan-xyz", payload=w01_collector_payload)

service = EvidenceService()
result = service.ingest_batch(batch)
```

---

## 3. Sample Collector Payloads

### A. Passive DNS Lookup Observation
```json
{
  "submitted_url_redacted": "https://example.test/",
  "normalized_host": "example.test",
  "status": "collecting",
  "evidence": [
    {
      "evidence_id": "ev-dns-001",
      "kind": "dns_lookup",
      "value": {
        "hostname": "example.test",
        "resolved_ips": ["93.184.216.34"],
        "ttl": 300,
        "is_safe_egress": true
      },
      "source": "worker01_dns_resolver",
      "observed_at": "2026-11-09T10:00:00Z",
      "status": "observed",
      "reliability": "direct_observation",
      "limitations": [
        "DNS observation pinned to resolved destination IP; does not prove application layer trust."
      ]
    }
  ]
}
```

### B. TLS Certificate Observation
```json
{
  "submitted_url_redacted": "https://example.test/",
  "normalized_host": "example.test",
  "status": "collecting",
  "evidence": [
    {
      "evidence_id": "ev-tls-001",
      "kind": "tls_hostname_validation",
      "value": {
        "subject_cn": "example.test",
        "subject_alt_names": ["example.test", "www.example.test"],
        "issuer": "DigiCert Global Root G2",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T23:59:59Z",
        "hostname_matches": true
      },
      "source": "worker01_tls_inspector",
      "observed_at": "2026-11-09T10:00:01Z",
      "status": "observed",
      "reliability": "direct_observation",
      "limitations": [
        "Valid TLS certificate proves cryptographic channel only; does not prove organizational authorization."
      ]
    }
  ]
}
```

### C. Collector Failure / Timeout Observation
```json
{
  "submitted_url_redacted": "https://slow-target.test/",
  "status": "partial",
  "evidence": [
    {
      "evidence_id": "ev-tls-timeout-001",
      "kind": "tls_hostname_validation",
      "value": null,
      "source": "worker01_tls_inspector",
      "observed_at": "2026-11-09T10:00:05Z",
      "status": "failed",
      "reliability": "direct_observation",
      "limitations": [
        "TLS handshake timed out after 3000ms."
      ]
    }
  ]
}
```

---

## 4. Rejection Report Submission

When Worker 01's `IntakeBoundary.evaluate_target` rejects a destination (e.g. loopback SSRF, private IP, credentials in URL):

```python
from trusttrace.intake.boundary import IntakeBoundary
from trusttrace.evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
from trusttrace.evidence.services.evidence_service import EvidenceService

# Worker 01 produces rejected report
intake = IntakeBoundary()
eval_res = intake.evaluate_target("http://127.0.0.1/admin")
rejected_report = intake.build_rejected_report(scan_id="scan-block-001", evaluation=eval_res)

# Worker 02 adapter ingests it without knowing intake internals
adapter = Worker01EvidenceAdapter()
batch = adapter.adapt_payload(scan_id="scan-block-001", payload=rejected_report)

service = EvidenceService()
result = service.ingest_batch(batch)

print("Ingested blocked observation into Worker 02:", result.inserted_count)
```

---

## 5. Verification Commands

Verify cross-worker contract compliance:
```bash
python run_tests.py
```
This runs all 45 tests, including `tests/test_evidence_adapters.py`, verifying that Worker 02 accepts all Worker 01 payloads without importing Worker 01 collector modules.
