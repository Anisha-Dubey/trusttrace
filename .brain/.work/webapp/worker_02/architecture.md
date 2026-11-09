# Worker 02 Architecture & Adapter Strategy

**Worker 02 — Evidence Model, Provenance Engine, Persistence & Collaborative Threat Intelligence**
**Status:** IN PROGRESS — Feature Branch `feature/worker-02-evidence-intelligence`

---

## 1. Executive Summary & Repository Audit

### Existing Architecture & Source Modules
- **Intake Layer (`src/trusttrace/intake`)**: Implemented by Worker 01 (Phase 01 complete). Provides safe parsing, credential blocking, IDNA punycode normalization, query token redaction (`url_policy.py`), IPv4/IPv6 classification (`ip_classifier.py`), SSRF protection & DNS rebinding mitigation (`dns_resolver.py`), hop-capped redirect policies (`redirect_policy.py`), and a unified `IntakeBoundary` (`boundary.py`).
- **Contracts (`.brain/.work/contracts/v1`)**: Version 1.0 JSON schemas (`scan_request.schema.json`, `scan_report.schema.json`, `community_report.schema.json`) with automated validator (`validate_fixtures.py`) enforcing Draft 2020-12 compliance and cross-record invariants.
- **Fixtures (`.brain/.testdata/v1`)**: Controlled synthetic fixtures (`complete_report.json`, `partial_report.json`, `rejected_report.json`, `conflicting_community_report.json`).
- **Dependencies Available**: Python 3.14, SQLAlchemy 2.0.54, FastAPI 0.141.1, Pydantic 2.13.5, jsonschema 4.26.0, Uvicorn 0.52.4.

### Missing Worker 02 Subsystems
1. Evidence domain models and persistence layer with transactional guarantees and indexing.
2. Adapter abstraction (`EvidenceProvider`) decoupling Worker 02 from Worker 01.
3. Ingestion pipeline with source attribution, UTC timestamping, idempotency, and coverage arithmetic.
4. Finding model with strict referential integrity (forbidding orphaned or dangling evidence IDs).
5. Community intelligence lifecycle with deduplication, source-family lineage tracking, corroboration guards, and append-only moderation audit logging.
6. Clean REST API endpoints exposing evidence, findings, community reports, and moderation workflows.

---

## 2. Decoupled Adapter Architecture

Worker 02 must **never** perform network requests, DNS lookups, or URL fetches. Worker 01 owns safe intake and bounded network observation.

```
                      +---------------------------------------+
                      |         Intake / Collectors           |
                      |  - Worker 01 Safe Boundary            |
                      |  - Controlled Test Fixtures           |
                      |  - External Feeds (future)            |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |           Adapter Interface           |
                      |          (EvidenceProvider)           |
                      +-------------------+-------------------+
                                          |
                       +------------------+------------------+
                       |                                     |
                       v                                     v
         +---------------------------+         +---------------------------+
         |   FixtureEvidenceAdapter  |         |   Worker01EvidenceAdapter |
         | (Deterministic Test Data) |         | (Validated Intake Payloads)|
         +---------------------------+         +---------------------------+
                       |                                     |
                       +------------------+------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |        Evidence Ingestion Engine      |
                      |  - Schema Contract Validation (v1)    |
                      |  - Source & Reliability Tagging       |
                      |  - Idempotency & Deduplication Check  |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |           Persistence Layer           |
                      |  - SQLAlchemy 2.0 ORM                 |
                      |  - Transactional Repository           |
                      |  - Indexes, Constraints & History     |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |         Finding Linkage Layer         |
                      |  - Referential Integrity Check        |
                      |  - No Orphan Evidence Allowed         |
                      |  - Rule ID / Version Attribution      |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |    Community Intelligence Engine      |
                      |  - Deduplication & Source Families    |
                      |  - State Machine & Corroboration Guard|
                      |  - Redaction & Append-Only Audit Log  |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |               API Layer               |
                      |  - FastAPI Endpoints                  |
                      |  - Privacy-Preserving Public Views    |
                      +---------------------------------------+
```

### Adapter Contracts
1. **`EvidenceProvider` (Protocol)**:
   - `fetch_evidence(scan_id: str) -> List[EvidencePayload]`
   - `fetch_scan_summary(scan_id: str) -> ScanSummaryPayload`
2. **`FixtureEvidenceAdapter`**:
   - Reads directly from `.testdata/v1/` fixtures (`complete_report.json`, `partial_report.json`, `rejected_report.json`).
   - Labels all returned records with `reliability="direct_observation"`, `source="fixture_adapter"`, and explicit limitation: `"Synthetic fixture; demo evidence only."`
3. **`Worker01EvidenceAdapter`**:
   - Consumes raw dictionaries or Pydantic payloads emitted by Worker 01's boundary.
   - Does **not** import any network/socket/DNS resolver modules from Worker 01.
   - Maps `target_policy`, `dns_resolution`, `redirect_trace`, and future collector outputs into standard v1 `EvidencePayload` objects.

---

## 3. Persistence & Data Model Strategy

### Database Engine
- **Engine**: SQLite via SQLAlchemy 2.0 (`sqlite:///trusttrace.db` in file or memory mode for tests).
- **Driver**: Standard library `sqlite3` with foreign key enforcement enabled (`PRAGMA foreign_keys = ON;`).
- **Isolation**: Serialized / WAL mode with transactions managed via session context managers.

### Tables & Relationships
1. **`evidence_records`**:
   - `evidence_id` (PK, string)
   - `scan_id` (Indexed string)
   - `kind` (string, e.g., `tls_hostname_validation`, `dns_lookup`, `target_policy`)
   - `value` (JSON text)
   - `source` (string)
   - `source_type` (string, e.g., `internal_collector`, `fixture`, `external_feed`)
   - `observed_at` (UTC ISO-8601 string / datetime)
   - `ingested_at` (UTC ISO-8601 string / datetime)
   - `status` (Enum: `observed`, `unavailable`, `failed`, `not_run`, `blocked`)
   - `reliability` (Enum: `provider_assertion`, `direct_observation`, `derived_signal`, `user_report`, `unknown`)
   - `limitations` (JSON array of strings)
   - `schema_version` (string, default `"1.0"`)
   - `fingerprint` (Unique hash of `scan_id` + `kind` + `source` + canonicalized `value` for idempotency)
2. **`finding_records`**:
   - `finding_id` (PK, string)
   - `scan_id` (Indexed string)
   - `kind` (string)
   - `severity` (Enum: `info`, `low`, `medium`, `high`, `critical`)
   - `summary` (string)
   - `rule_id` (string)
   - `rule_version` (string)
   - `created_at` (UTC datetime)
   - `limitations` (JSON array of strings)
3. **`finding_evidence_links`**:
   - `finding_id` (FK -> `finding_records.finding_id`, ON DELETE CASCADE)
   - `evidence_id` (FK -> `evidence_records.evidence_id`, ON DELETE RESTRICT)
   - Unique constraint `(finding_id, evidence_id)`
4. **`community_reports`**:
   - `report_id` (PK, string)
   - `normalized_domain` (Indexed string)
   - `claim_type` (Enum: `phishing`, `impersonation`, `malware_delivery`, `suspicious_redirect`, `other`)
   - `note_redacted` (string, max 1000 chars, sanitized)
   - `submitted_at` (UTC datetime)
   - `verification_state` (Enum: `unverified`, `corroborated`, `disputed`, `reviewed`)
   - `independent_source_count` (integer, min 0)
   - `source_family` (string, grouped lineage)
   - `reporter_hash` (salt-hashed identifier; raw reporter IP/ID is **never** stored or exposed)
   - `reviewed_at` (Nullable UTC datetime)
5. **`community_report_evidence_links`**:
   - `report_id` (FK -> `community_reports.report_id`)
   - `evidence_id` (FK -> `evidence_records.evidence_id`)
6. **`community_report_audit_events`**:
   - `event_id` (PK, string)
   - `report_id` (FK -> `community_reports.report_id`)
   - `previous_state` (Enum: `unverified`, `corroborated`, `disputed`, `reviewed`, `null`)
   - `new_state` (Enum)
   - `action` (string: `submitted`, `corroborated`, `disputed`, `reviewed`, `moderated`)
   - `reason` (string)
   - `actor_ref` (string, pseudonymized/internal reviewer ID)
   - `timestamp` (UTC datetime)

---

## 4. Evidence Ingestion & Coverage Arithmetic

### Idempotency Strategy
- Ingestion computes an idempotency fingerprint: `sha256(scan_id + ":" + kind + ":" + source + ":" + json_dumps(value))`.
- If an evidence record with the same fingerprint already exists for the scan, the existing record is returned without duplicating database rows.
- If an existing record has different observation time, historical observations are preserved; records are append-only.

### Coverage Semantics
Contracts require:
$$\text{checks\_total} = \text{checks\_observed} + \text{checks\_failed} + \text{checks\_not\_run}$$
Mapping rules:
- `status == "observed"` $\rightarrow \text{checks\_observed} += 1$
- `status == "failed"` $\rightarrow \text{checks\_failed} += 1$
- `status in ("not_run", "unavailable", "blocked")` $\rightarrow \text{checks\_not\_run} += 1$
This ensures mathematical consistency with `validate_fixtures.py` and `scan_report.schema.json`.

---

## 5. Community Threat Intelligence & Corroboration Engine

### Lifecycle State Machine
```
       [ Submission ]
             |
             v
       [ unverified ] (default for all new reports)
         |         |
         |         +---------> [ disputed ] <--------+
         |                          |                |
         v                          v                |
  [ corroborated ] ---------> [ reviewed ] ----------+
```
- **Allowed Transitions**:
  - `unverified` $\rightarrow$ `corroborated` (only upon satisfying multi-source independent family policy)
  - `unverified` $\rightarrow$ `disputed` (conflicting evidence or report filed)
  - `unverified` $\rightarrow$ `reviewed` (moderator review action)
  - `corroborated` $\rightarrow$ `disputed` (contradicting observation arrives)
  - `disputed` $\rightarrow$ `reviewed` (resolution after review)
- **Forbidden Transitions**:
  - Direct creation in `corroborated` or `reviewed` state.
  - Automatic promotion to `corroborated` based on same-family or duplicate reports.

### Deduplication & Source-Family Analysis
- **Exact Duplicate**: Identical `normalized_domain` + `claim_type` + same `reporter_hash` within 24h window. Returns existing report reference; independent source count remains unchanged.
- **Copied Source**: Different reporter submitting identical threat-feed ID or syndicated feed reference (e.g., downstream consumer of same PhishTank list). Grouped into a single `source_family`. Independent source count is incremented at most once per source family.
- **Independent Source**: Distinct reporter hash AND distinct `source_family`. Increments `independent_source_count`.
- **Conflicting Report**: Conflicting claim (e.g., legitimate vs phishing report) flags domain as `disputed`. Both reports are preserved and visibly linked.

---

## 6. Security, Privacy & Public Display Guardrails
1. **Reporter Anonymity**: Never persist raw IP address, email, or user token. Store only a non-reversible HMAC-SHA256 hash. Public API responses omit `reporter_hash` entirely.
2. **Text Sanitization**: `note_redacted` stripped of HTML tags, control characters, scripts, and capped at 1000 characters.
3. **Parameterization**: 100% of database interactions run through SQLAlchemy parameterized queries.
4. **No Egress**: Worker 02 contains zero HTTP client calls or DNS resolver invocations.
