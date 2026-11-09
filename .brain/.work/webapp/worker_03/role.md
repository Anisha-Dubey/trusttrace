# Worker 03 — Decision policy, data and evaluation

**Status: COMPLETED & VERIFIED (Phases 01 & 02).**

## Mission
Own interpretable rules, conservative disposition, dataset/fixture validity, evaluation and pitch claims. Keep provider assertions, predictions and adjudicated labels separate.

## Locked Scope & Code Paths
- `src/trusttrace/policy/` (all modules: triage engine, signal taxonomy, decision log, evaluation, claim auditor)
- `tests/test_triage_policy.py`
- `.brain/.work/webapp/worker_03/` and `.brain/.report/worker_03_*`

## Responsibilities
- Own implementation contract, tests and documentation for this workstream.
- Coordinate shared schema changes before merging.
- Provide a working fixture/mock interface early for integration.
- Report blockers and distinguish implemented, tested, and deferred work.

## Domain Lock & Boundary Protection
- **No Direct Mutation:** Worker 03 does not directly alter collector mechanics or raw storage schemas.
- **Rule & Claim Governance:** Worker 03's triage engine and claim auditor govern decision ceilings and presentation claims across the project.
- **Ask Twice Protocol:** Any request to enter another worker's locked domain requires:
  1. Justification logged in `.brain/.work/shared/cross_boundary_log.md`.
  2. Explicit sign-off from the target domain owner.
- External workers seeking to alter triage rules, dimensions, or signal taxonomy must obtain Worker 03's two-step sign-off.

## Out of scope
Do not claim a production-ready security product, unmeasured detection quality, or capabilities owned by another track.
