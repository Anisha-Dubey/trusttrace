# Worker 02 Architecture, Evidence Intelligence & Security Specifications

**Worker 02 — Evidence Model, Provenance Engine, Persistence & Collaborative Threat Intelligence**  
**Repository Branch:** `feature/worker-02-evidence-intelligence`  
**Status:** PHASE 8 COMPLETED, HARDENED, MIGRATED & INDEPENDENTLY VERIFIED

---

## 1. Architecture Overview

Worker 02 is the evidentiary spine and collaborative threat intelligence foundation of TRUSTTRACE. It provides:
1. **Contract-Compliant Evidence Ingestion**: Validates, normalizes, fingerprints, and persists network observations emitted by Worker 01 without direct networking coupling.
2. **Strict Provenance & Fingerprinting**: Computes deterministic SHA-256 fingerprints across canonical payload fields to ensure idempotency while preserving historical observations.
3. **Transactional Persistence Layer**: SQLAlchemy 2.0 ORM with PostgreSQL 15 and SQLite support, enforcing database-level unique constraints, foreign keys, and row-level coordination.
4. **Collaborative Threat Intelligence**: Complete community reporting lifecycle with privacy-preserving HMAC-SHA256 reporter pseudonymization, HTML/XSS sanitization, source-family lineage tracking, and multi-process corroboration guards.
5. **Fail-Closed Security & Atomic Rate Limiting**: Production startup credential validation, fail-closed Redis backend enforcement, atomic sliding-window Lua rate limiting, and RBAC-protected moderation/audit endpoints.

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
                      |  - Deterministic SHA-256 Fingerprint  |
                      |  - Idempotency & Savepoint Safety     |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |           Persistence Layer           |
                      |  - SQLAlchemy 2.0 ORM                 |
                      |  - Row Locking (with_for_update)      |
                      |  - Normalized Junction Tables         |
                      |  - Alembic Migrations (Postgres/SQL)  |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |         Finding Linkage Layer         |
                      |  - Referential Integrity Check        |
                      |  - Foreign Key Constraints            |
                      |  - Rule ID / Version Attribution      |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |    Community Intelligence Engine      |
                      |  - Server-Bound Source Families       |
                      |  - Multi-Process Corroboration Guard  |
                      |  - Sanitization & Pseudonymization    |
                      |  - Append-Only Moderation Audit Log   |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |         FastAPI REST Service          |
                      |  - Production Lifespan Gates          |
                      |  - RBAC (viewer, moderator, admin)    |
                      |  - Atomic Lua Redis Rate Limiter      |
                      +-------------------+-------------------+
```

---

## 2. Module Responsibilities

The codebase in `src/trusttrace/` is strictly partitioned:

| Module Path | Subsystem | Responsibility |
| :--- | :--- | :--- |
| `trusttrace.api.app` | REST Application | FastAPI app factory, CORS security, request correlation middleware, body size cap (2MB), application `lifespan` startup validation. |
| `trusttrace.api.auth` | Authentication & RBAC | Production token verification, token registry, constant-time comparison, role hierarchy (`viewer`, `moderator`, `admin`, `collector`), permitted source-family principal binding. |
| `trusttrace.api.schemas` | Pydantic Schemas | Strict RFC 1035/1123 domain validation, IDNA punycode verification, payload size limits (1MB), request/response DTOs. |
| `trusttrace.api.routes.evidence` | Evidence REST Endpoints | Ingest observations, query scan evidence, create findings, compute coverage, calculate provenance freshness. |
| `trusttrace.api.routes.community` | Community REST Endpoints | Rate-limited report intake, server-side source-family binding, RBAC-protected review/moderation, authenticated audit trails. |
| `trusttrace.evidence.domain.models` | Domain Models | Pure Python dataclasses: `EvidenceModel`, `FindingModel`, `CoverageModel`, `CommunityReportModel`, `ReportAuditEntry`. |
| `trusttrace.evidence.domain.enums` | Enums | Status (`observed`, `unavailable`, `failed`, `not_run`, `blocked`), Reliability (`direct_observation`, `provider_assertion`, etc.), VerificationState (`unverified`, `corroborated`, `disputed`, `reviewed`). |
| `trusttrace.evidence.persistence.database` | Database Engine | SQLAlchemy engine configuration, connection pooling (`StaticPool` for in-memory SQLite), SQLite foreign key pragma listener. |
| `trusttrace.evidence.persistence.models` | ORM Entities | Mapped SQLAlchemy 2.0 classes: `ScanEntity`, `EvidenceEntity`, `FindingEntity`, `FindingEvidenceLinkEntity`, `CommunityReportEntity`, `CommunityDomainSourceFamilyEntity`, `CommunityDomainCoordinationEntity`. |
| `trusttrace.evidence.persistence.repository` | Repository | Database operations, savepoint collision guards (`session.begin_nested()`), `with_for_update()` row locks, distinct count calculations. |
| `trusttrace.evidence.services.evidence_service` | Evidence Service | Ingestion pipeline, coverage arithmetic invariant enforcement ($\text{total} = \text{observed} + \text{failed} + \text{not\_run}$). |
| `trusttrace.evidence.services.provenance` | Provenance Service | Evidence age calculation, staleness decay classification, collector reliability attribution. |
| `trusttrace.evidence.community.service` | Community Service | Thread-safe & multi-process community intake, database-coordinated deduplication, authoritative independent count updates. |
| `trusttrace.evidence.community.deduplicator` | Deduplication | Exact duplicate detection (24h window), copied source lineage mapping, conflicting claim resolution, canonical family validation. |
| `trusttrace.evidence.community.moderation` | Moderation Service | Authenticated verification state transitions (`validate_transition`), append-only audit event logging. |
| `trusttrace.evidence.community.rate_limiter` | Rate Limiter | Pluggable rate limiter, atomic Lua script execution on Redis, replay protection with unique UUID4 nonces, fail-closed production checks. |
| `trusttrace.evidence.community.sanitizer` | Sanitization & Privacy | Stored XSS defense (HTML stripping, control character removal), salt-keyed HMAC-SHA256 reporter pseudonymization. |
| `trusttrace.evidence.adapters.base` | Adapter Protocol | `EvidenceProvider` protocol definition and `EvidenceBatch` payload structure. |
| `trusttrace.evidence.adapters.worker01_adapter`| Adapter | Maps Worker 01 target policy, DNS, and redirect payloads into standard v1 `EvidenceBatch`. |
| `trusttrace.evidence.adapters.fixture_adapter` | Adapter | Ingests `.brain/.testdata/v1/` golden fixtures for deterministic testing without live collectors. |

---

## 3. Database Schema

Managed via Alembic (`alembic/versions/`):

```
+----------------------------------------------------------------------------------------------------+
|                                             scans                                                  |
+----------------------------------------------------------------------------------------------------+
| scan_id (PK, String 128)                                                                           |
| submitted_url_redacted (Text)                                                                      |
| normalized_host (String 255)                                                                       |
| status (String 32)                                                                                 |
| decision (String 32)                                                                               |
| policy_version (String 32)                                                                         |
| coverage_total (Integer) | coverage_observed (Integer) | coverage_failed (Integer) | not_run (Integer)|
| created_at (String 64) | completed_at (String 64)                                                  |
| limitations_json (Text)                                                                            |
+----------------------------------------------------------------------------------------------------+
          | 1
          |
          | N
+----------------------------------------------------------------------------------------------------+
|                                        evidence_records                                            |
+----------------------------------------------------------------------------------------------------+
| evidence_id (PK, String 128)                                                                       |
| scan_id (FK -> scans.scan_id, Index)                                                               |
| kind (String 64)                                                                                   |
| value_json (Text)                                                                                  |
| source (String 128) | source_type (String 64)                                                      |
| observed_at (String 64) | ingested_at (String 64)                                                  |
| status (String 32) | reliability (String 32)                                                       |
| limitations_json (Text) | schema_version (String 16)                                               |
| fingerprint (String 64, Index)                                                                     |
| UNIQUE CONSTRAINT: (scan_id, fingerprint)                                                          |
+----------------------------------------------------------------------------------------------------+
          | N
          |
          | M (via finding_evidence_links)
+----------------------------------------------------------------------------------------------------+
|                                            findings                                                |
+----------------------------------------------------------------------------------------------------+
| finding_id (PK, String 128)                                                                        |
| scan_id (FK -> scans.scan_id, Index)                                                               |
| kind (String 64) | severity (String 32)                                                            |
| summary (Text) | rule_id (String 64) | rule_version (String 32)                                     |
| created_at (String 64) | limitations_json (Text)                                                   |
+----------------------------------------------------------------------------------------------------+

+----------------------------------------------------------------------------------------------------+
|                                        community_reports                                           |
+----------------------------------------------------------------------------------------------------+
| report_id (PK, String 128)                                                                         |
| normalized_domain (String 255, Index)                                                              |
| claim_type (String 32)                                                                             |
| note_redacted (Text)                                                                               |
| submitted_at (String 64) | reviewed_at (String 64, Nullable)                                       |
| verification_state (String 32)                                                                     |
| independent_source_count (Integer)                                                                 |
| source_family (String 64)                                                                          |
| reporter_hash (String 128)                                                                         |
+----------------------------------------------------------------------------------------------------+
          | 1
          |
          | N
+----------------------------------------------------------------------------------------------------+
|                                 community_report_audit_events                                      |
+----------------------------------------------------------------------------------------------------+
| event_id (PK, String 128)                                                                          |
| report_id (FK -> community_reports.report_id, Index)                                               |
| previous_state (String 32, Nullable) | new_state (String 32)                                       |
| action (String 64) | reason (Text) | actor_ref (String 128) | timestamp (String 64)                |
+----------------------------------------------------------------------------------------------------+

+----------------------------------------------------------------------------------------------------+
|                                community_domain_source_families                                    |
+----------------------------------------------------------------------------------------------------+
| id (PK, Integer autoincrement)                                                                     |
| normalized_domain (String 255, Index)                                                              |
| source_family (String 64)                                                                          |
| first_report_id (String 128)                                                                       |
| registered_at (String 64)                                                                          |
| UNIQUE CONSTRAINT: (normalized_domain, source_family)                                              |
+----------------------------------------------------------------------------------------------------+

+----------------------------------------------------------------------------------------------------+
|                                   community_domain_coordination                                    |
+----------------------------------------------------------------------------------------------------+
| normalized_domain (PK, String 255)                                                                 |
| is_disputed (Boolean, Default False)                                                               |
| active_claim (String 32, Nullable)                                                                 |
| lock_version (Integer, Default 1)                                                                  |
| updated_at (String 64)                                                                             |
+----------------------------------------------------------------------------------------------------+
```

---

## 4. API Endpoints

All endpoints run on FastAPI at prefix `/api/v1` and adhere to JSON Schema v1 contracts:

| Method | Path | Auth / Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | Health probe returning subsystem status, uptime, and database engine type. |
| `GET` | `/ready` | Public | Readiness probe checking database connectivity and Redis availability. |
| `POST` | `/api/v1/evidence/ingest` | Public / Collector | Ingests an observation batch with idempotency, coverage arithmetic, and scan binding. |
| `GET` | `/api/v1/scans/{scan_id}/evidence` | Public | Retrieves all evidence records for a scan, with pagination (`limit`, `offset`). |
| `POST` | `/api/v1/scans/{scan_id}/findings` | Public / Analyzer | Creates a finding referencing valid evidence IDs (rejects orphan/dangling IDs). |
| `GET` | `/api/v1/scans/{scan_id}/findings` | Public | Retrieves all findings for a scan with linked evidence models. |
| `GET` | `/api/v1/scans/{scan_id}/coverage` | Public | Retrieves scan coverage metrics verifying the coverage arithmetic invariant. |
| `GET` | `/api/v1/scans/{scan_id}/provenance` | Public | Computes freshness, staleness decay, and collector attribution for evidence in a scan. |
| `POST` | `/api/v1/community/reports` | Rate Limited / Principal-bound | Submits a community report. Unauthenticated users are assigned `community_user`; authenticated collectors are verified against permitted families. |
| `GET` | `/api/v1/community/reports` | Public | Lists community reports with pagination and filtering by domain, state, and claim type. |
| `GET` | `/api/v1/community/reports/{id}` | Public | Retrieves a single community report (omitting sensitive reporter hash). |
| `POST` | `/api/v1/community/reports/{id}/review` | `moderator`, `admin` | Moderates report state. Target state validated by state machine. Actor ref bound to token. |
| `GET` | `/api/v1/community/reports/{id}/audit` | `viewer`, `moderator`, `admin` | Chronological audit trail for a report. |
| `GET` | `/api/v1/community/domain/{domain}/audit` | `viewer`, `moderator`, `admin` | Chronological audit trail across all reports for a domain. |

---

## 5. Evidence Lifecycle

```
Collector Observation -> Schema Validation -> Normalization -> SHA-256 Fingerprint -> DB Savepoint (Idempotent Insert) -> Scan Coverage Calculation -> Finding Linkage
```

1. **Intake Validation**: The payload is validated against `IngestEvidenceRequest` (RFC 1035 hostname syntax, 1MB size limit, valid timestamp format, recognized `status` and `reliability` enums).
2. **Canonical Normalization**: Status, kind, and source are lowercased and stripped. `value` dictionary is canonicalized with sorted keys: `json.dumps(value, sort_keys=True, separators=(',', ':'), default=str)`.
3. **Fingerprinting**: `sha256(scan_id + ":" + kind + ":" + source + ":" + observed_at + ":" + status + ":" + canonical_value)`.
4. **Idempotency & Savepoint Safety**:
   - The repository executes `session.begin_nested()`.
   - If `(scan_id, fingerprint)` already exists, the insert is rolled back to the savepoint without aborting the outer database transaction.
   - The existing evidence record is returned with `was_created=False`.
5. **Coverage Calculation**:
   $$\text{checks\_total} = \text{checks\_observed} + \text{checks\_failed} + \text{checks\_not\_run}$$
   - `status == "observed"` $\rightarrow$ `checks_observed`
   - `status == "failed"` $\rightarrow$ `checks_failed`
   - `status in ("not_run", "unavailable", "blocked")` $\rightarrow$ `checks_not_run`

---

## 6. Provenance and Fingerprinting Rules

- **Deterministic SHA-256**: Calculated strictly over:
  - `scan_id` (string)
  - `kind` (string, e.g. `tls_hostname_validation`, `dns_lookup`)
  - `source` (string, e.g. `worker01_dns_resolver`)
  - `observed_at` (UTC ISO-8601 string)
  - `status` (string, e.g. `observed`, `failed`)
  - `value` (compact JSON string with sorted keys)
- **Distinct Observations Preserved**:
  - If a collector re-probes a domain 10 minutes later with a new timestamp, a new distinct evidence record is created.
  - If an observation fails after previously succeeding, both are retained in chronological sequence.
- **Freshness & Staleness Windows**:
  - `fresh`: Age $\le 24\text{ hours}$.
  - `stale`: $24\text{ hours} < \text{Age} \le 7\text{ days}$.
  - `expired`: $\text{Age} > 7\text{ days}$.

---

## 7. Community Report Lifecycle

### State Machine Transitions

```
               [ Submission ]
                     |
                     v
               [ unverified ] (default for all new submissions)
                 |         |
                 |         +---------> [ disputed ] <--------+
                 |                          |                |
                 v                          v                |
          [ corroborated ] ---------> [ reviewed ] ----------+
```

- **Allowed Transitions**:
  - `unverified` $\rightarrow$ `corroborated`: Promoted only when distinct canonical source families $\ge 2$.
  - `unverified` $\rightarrow$ `disputed`: Conflicting claim submitted for the same domain.
  - `unverified` $\rightarrow$ `reviewed`: Authorized moderator evaluates and signs off.
  - `corroborated` $\rightarrow$ `disputed`: Contradictory observation arrives after initial corroboration.
  - `disputed` $\rightarrow$ `reviewed`: Authorized moderator resolves conflicting claims.
- **Prohibited Transitions**:
  - Reports can NEVER be created directly in `corroborated` or `reviewed`.
  - Transitions from `reviewed` back to `unverified` are prohibited.

### Deduplication Categories

- **Exact Duplicate**: Same domain + same claim + same `reporter_hash` within 24 hours. The existing report is returned; independent source count does NOT increment.
- **Copied Source**: Different reporter submitting from the same threat feed lineage (e.g. syndicated PhishTank or URLhaus feeds). Mapped to canonical `source_family`. Does NOT increment independent count if the family was already registered for that domain.
- **Independent Source**: Distinct reporter submitting from an independent, previously unregistered source family. Safely increments `independent_source_count`.
- **Conflicting Report**: Contradictory claim submitted (e.g., `legitimate` vs `phishing`). Transitions domain coordination record and all sibling reports to `disputed`.

---

## 8. Authentication and Authorization

### Role Hierarchy & Token Mappings

Authentication uses HTTP Bearer tokens evaluated via constant-time comparison (`secrets.compare_digest`).

| Role | Allowed Actions | Endpoints |
| :--- | :--- | :--- |
| `anonymous` (Public) | Submit community report, browse reports, ingest scan observations. | `/community/reports` (POST/GET), `/evidence/ingest` |
| `collector` | Ingest observations, submit provider-attributed threat intelligence. | Bound strictly to designated `permitted_source_families`. |
| `viewer` | Read-only inspection of reports and privileged moderation audit trails. | `/community/reports/{id}/audit`, `/domain/{domain}/audit` |
| `moderator` | Transition report verification states, resolve disputes, record audit reasons. | `/community/reports/{id}/review`, audit endpoints |
| `admin` | Full system access, all moderation operations, credential configuration verification. | All endpoints |

### Production Startup Validation Gate

When `TRUSTTRACE_ENV=production` (or `ENV=production`), the application startup lifespan verifies:
- `MODERATOR_TOKEN`, `ADMIN_TOKEN`, `COLLECTOR_TOKEN`, and `VIEWER_TOKEN` environment variables are present and non-empty.
- Tokens cannot equal insecure defaults (`mod-secret-token-key-2026`, `secret`, `admin`, `password`).
- Tokens must not be duplicated across roles.
- Failure to satisfy these constraints halts application startup immediately with `ValueError`. Credential values are never printed in error logs.

---

## 9. Redis Configuration & Connection Requirements

When running in production, a shared Redis instance is required for atomic distributed rate limiting and replay prevention:

- **Environment Variable**: `TRUSTTRACE_REDIS_URL=redis://user:password@redis-host:6379/0`
- **Fail-Closed Gate**:
  - In production (`TRUSTTRACE_ENV=production`), if `TRUSTTRACE_REDIS_URL` is omitted or Redis is unreachable during startup ping health check, startup fails immediately.
  - If a runtime Redis network fault occurs, protected submission endpoints reject requests with HTTP 503 Service Unavailable rather than silently bypassing rate limiting.
- **Development/Test Fallback**: In-memory rate limiting is permitted ONLY when `TRUSTTRACE_ENV` is set to `development` or `test`.

---

## 10. Rate-Limit Behavior & Atomic Lua Script

Sliding-window rate limiting is executed via an atomic Redis Lua script (`ATOMIC_RATE_LIMIT_LUA`):

```lua
-- KEYS[1]: Replay key (replay:{token})
-- KEYS[2]: IP sliding-window key (rate:ip:{ip})
-- KEYS[3]: Domain sliding-window key (rate:domain:{domain})
-- ARGV[1]: Current epoch timestamp (seconds)
-- ARGV[2]: IP window limit (e.g. 30 requests)
-- ARGV[3]: IP window duration (e.g. 60 seconds)
-- ARGV[4]: Domain window limit (e.g. 10 requests)
-- ARGV[5]: Domain window duration (e.g. 60 seconds)
-- ARGV[6]: Replay TTL (e.g. 86400 seconds)
-- ARGV[7]: Unique member nonce (timestamp:uuid4)
```

1. **Atomic Replay Check**: If `KEYS[1]` exists, returns rejection code `1` immediately without altering rate limit sets.
2. **Atomic IP Limit Check**: Removes entries older than $(T - \text{window})$ from `KEYS[2]`. If cardinality $\ge \text{limit}$, returns rejection code `2`.
3. **Atomic Domain Limit Check**: Removes entries older than $(T - \text{window})$ from `KEYS[3]`. If cardinality $\ge \text{limit}$, returns rejection code `3`.
4. **Atomic Acceptance**: Only when all three checks pass, records `KEYS[1]` (SET with TTL), adds unique nonce member to `KEYS[2]` and `KEYS[3]`, and sets bounded key expiration.
5. **No State Pollution**: Rejected requests leave zero state behind and do not consume quotas.
6. **Iterative Key Scanning**: Operational reset operations utilize non-blocking `SCAN` rather than production-blocking `KEYS`.

---

## 11. Environment Variables

| Variable Name | Environment | Description | Default |
| :--- | :--- | :--- | :--- |
| `TRUSTTRACE_ENV` | All | Deployment mode (`production`, `development`, `test`). | `development` |
| `TRUSTTRACE_DB_URL` | All | SQLAlchemy database connection string. | `sqlite:///trusttrace.db` |
| `TRUSTTRACE_REDIS_URL` | Production | Redis connection URL for atomic rate limiter. | None |
| `MODERATOR_TOKEN` | Production | High-entropy Bearer token for moderator role. | Required in prod |
| `ADMIN_TOKEN` | Production | High-entropy Bearer token for admin role. | Required in prod |
| `COLLECTOR_TOKEN` | Production | High-entropy Bearer token for collector role. | Required in prod |
| `VIEWER_TOKEN` | Production | High-entropy Bearer token for audit viewer role. | Required in prod |
| `HMAC_REPORTER_SECRET` | Production | Secret salt key for HMAC-SHA256 reporter hashing. | Secure fallback |
| `RATE_LIMIT_BACKEND` | Dev / Test | Rate limiter backend selection (`memory`, `redis`). | `memory` |

---

## 12. Migration Instructions

Database schema revisions are managed using Alembic:

```bash
# Apply all pending migrations to HEAD
python -m alembic upgrade head

# Inspect current database revision
python -m alembic current

# View migration history
python -m alembic history --verbose

# Roll back migration by one revision (or to base)
python -m alembic downgrade -1
python -m alembic downgrade base
```

### PostgreSQL Execution:
```bash
export TRUSTTRACE_DB_URL="postgresql+psycopg2://user:password@localhost:5432/trusttrace"
python -m alembic upgrade head
```

---

## 13. Local Testing Instructions

Run the unified test runner (all 145 unit/integration tests and 8 contract invariant checks):
```bash
python run_tests.py
```

Run specific test modules:
```bash
# 18-point adversarial & concurrency regression suite
python -m unittest tests/test_phase8_adversarial_suite.py -v

# Reliability and security hardening tests
python -m unittest tests/test_reliability_and_hardening.py -v

# Security audit remediation tests (SEC-01 to SEC-23)
python -m unittest tests/test_security_audit.py -v

# Collaborative threat intelligence lifecycle tests
python -m unittest tests/test_community_intelligence.py -v

# Evidence intelligence and persistence tests
python -m unittest tests/test_evidence_intelligence.py -v
```

---

## 14. CI Behavior

The GitHub Actions CI pipeline (`.github/workflows/ci.yml`) executes on every push to `feature/worker-02-evidence-intelligence`:
1. **Matrix Testing**: Concurrently runs on Python 3.11 and Python 3.12.
2. **Service Containers**:
   - `redis:7-alpine` on port 6379 (with health check `redis-cli ping`).
   - `postgres:15-alpine` on port 5432 (with health check `pg_isready`).
3. **Database Migrations on Live PostgreSQL**: Executes `alembic upgrade head` and `alembic current` on live PostgreSQL.
4. **Full Test Execution**: Runs `python run_tests.py` testing live Redis and PostgreSQL backends.
5. **Fail-Fast Gates**: Any test failure, schema mismatch, or lint error terminates the build with non-zero exit status.

---

## 15. Worker 01 Integration Contract

Worker 02 is completely decoupled from Worker 01:
- **Zero Networking in Worker 02**: Worker 02 contains no socket operations, DNS resolution calls, or HTTP clients.
- **Contract Boundary**: Worker 01 passes validated observations to Worker 02 via `Worker01EvidenceAdapter`:
  ```python
  from trusttrace.evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
  from trusttrace.evidence.services.evidence_service import EvidenceService

  adapter = Worker01EvidenceAdapter()
  batch = adapter.adapt_payload(scan_id="scan-xyz", payload=w01_collector_payload)

  service = EvidenceService()
  result = service.ingest_batch(batch)
  ```
- **Rejection Reports**: When Worker 01's boundary blocks a target (SSRF, credential in URL, etc.), the rejected report conforms to `scan_report.schema.json` and is ingested by Worker 02 as an immutable blocked observation record.

---

## 16. Known Limitations

1. **SQLite vs PostgreSQL Concurrency**: Under SQLite, database-level locking utilizes transaction-level file locks. Full row-level locking (`with_for_update()`) is active only when connected to PostgreSQL. For production high-throughput multi-worker deployments, PostgreSQL is required.
2. **Redis Single-Node vs Cluster**: The atomic Lua script operates across 3 keys (`KEYS[1]`, `KEYS[2]`, `KEYS[3]`). In a Redis Cluster environment, these keys must share the same hash tag (e.g. `{domain}`) to ensure single-slot script execution.
3. **Reporter Identity Non-Reversibility**: HMAC-SHA256 reporter hashing is one-way. If an investigator requires deanonymizing abuse sources, raw reporter logs must be correlated via external secure audit channels outside Worker 02.
