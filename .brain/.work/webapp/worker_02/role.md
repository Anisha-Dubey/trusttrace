# Worker 02 — Evidence model & collaborative intelligence

**Status: COMPLETED & VERIFIED (Phases 01 & 02).**

## Mission
Own typed observations/findings, source/time provenance, missingness, deduplication and community report states. Do not turn unverified input into labels.

## Locked Scope & Code Paths
- `src/trusttrace/evidence/` (all modules: domain, persistence, community, adapters, services)
- `src/trusttrace/api/` (all API routes)
- `alembic/` (all schema migration scripts) & `alembic.ini`
- `tests/test_evidence_intelligence.py`, `tests/test_evidence_adapters.py`, `tests/test_community_intelligence.py`, `tests/test_api_endpoints.py`, `tests/test_reliability_and_hardening.py`
- `.brain/.work/webapp/worker_02/` and `.brain/.report/worker_02_*`

## Responsibilities
- Own implementation contract, tests and documentation for this workstream.
- Coordinate shared schema changes before merging.
- Provide a working fixture/mock interface early for integration.
- Report blockers and distinguish implemented, tested, and deferred work.

## Domain Lock & Boundary Protection
- **Decoupled Architecture:** Worker 02 strictly communicates with external tracks via public contracts and adapters (`FixtureEvidenceAdapter`, `Worker01EvidenceAdapter`).
- **No Direct Imports:** Never import Worker 01 internal socket/resolver modules (strictly verified by `test_no_worker01_internal_modules_imported_in_worker02`).
- **Ask Twice Protocol:** Any request to enter another worker's locked domain requires:
  1. Justification logged in `.brain/.work/shared/cross_boundary_log.md`.
  2. Explicit sign-off from the target domain owner.
- External workers seeking to alter Worker 02 database, evidence schemas, or community intelligence code must obtain Worker 02's two-step sign-off.

## Out of scope
Do not claim a production-ready security product, unmeasured detection quality, or capabilities owned by another track.
