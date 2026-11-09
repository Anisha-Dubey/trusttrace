# Worker 01 — Safe intake & bounded collectors

**Status: COMPLETED & VERIFIED (Phases 01 & 02).**

## Mission
Own URL canonicalization and every network egress decision. Implement low-impact DNS/TLS/redirect/header observations only after destination validation. No arbitrary browser execution without isolation.

## Locked Scope & Code Paths
- `src/trusttrace/intake/` (all modules)
- `src/trusttrace/collectors/` (all modules)
- `tests/test_url_policy.py`, `tests/test_ssrf_boundary.py`, `tests/test_redirect_boundary.py`, `tests/test_bounded_collectors.py`
- `.brain/.work/webapp/worker_01/` and `.brain/.report/worker_01_*`

## Responsibilities
- Own implementation contract, tests and documentation for this workstream.
- Coordinate shared schema changes before merging.
- Provide a working fixture/mock interface early for integration.
- Report blockers and distinguish implemented, tested, and deferred work.

## Domain Lock & Boundary Protection
- **No Cross-Domain Intrusion:** Worker 01 does not modify or directly import files belonging to Worker 02, 03, or 04.
- **Ask Twice Protocol:** Any request to enter another worker's locked domain requires:
  1. Justification logged in `.brain/.work/shared/cross_boundary_log.md`.
  2. Explicit sign-off from the target domain owner.
- External workers seeking to alter Worker 01 intake/collector code must obtain Worker 01's two-step sign-off.

## Out of scope
Do not claim a production-ready security product, unmeasured detection quality, or capabilities owned by another track.
