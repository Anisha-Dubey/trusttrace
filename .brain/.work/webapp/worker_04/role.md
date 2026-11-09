# Worker 04 — Product workflow, integration & demo

**Status: PLANNED & PREPARED.**

## Mission
Own user journey, UI, contract integration, setup/release documentation and stage demo. Keep fixture mode available and make simulated data obvious.

## Locked Scope & Code Paths
- `src/trusttrace/web/` or UI frontend application directories
- User-facing presentation scripts and demo harnesses
- `.brain/.demo/` (demo scripts and flows)
- `.brain/.work/webapp/worker_04/` and `.brain/.report/worker_04_*`

## Responsibilities
- Own implementation contract, tests and documentation for this workstream.
- Coordinate shared schema changes before merging.
- Provide a working fixture/mock interface early for integration.
- Report blockers and distinguish implemented, tested, and deferred work.

## Domain Lock & Boundary Protection
- **Consume Contracts via Public APIs/Adapters:** Worker 04 builds against Worker 02's REST APIs/schemas and Worker 03's triage output. Worker 04 does not modify backend internals (intake, database queries, policy rules).
- **Ask Twice Protocol:** Any request to enter another worker's locked domain requires:
  1. Justification logged in `.brain/.work/shared/cross_boundary_log.md`.
  2. Explicit sign-off from the target domain owner.
- External workers seeking to alter UI screens, routes, or demo flows must obtain Worker 04's two-step sign-off.

## Out of scope
Do not claim a production-ready security product, unmeasured detection quality, or capabilities owned by another track.
