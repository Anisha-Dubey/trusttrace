# Worker 01 — Safe intake & bounded collectors

**Status: PLANNED.**

## Mission
Own URL canonicalization and every network egress decision. Implement low-impact DNS/TLS/redirect/header observations only after destination validation. No arbitrary browser execution without isolation.

## Responsibilities
- Own implementation contract, tests and documentation for this workstream.
- Coordinate shared schema changes before merging.
- Provide a working fixture/mock interface early for integration.
- Report blockers and distinguish implemented, tested, and deferred work.

## Out of scope
Do not claim a production-ready security product, unmeasured detection quality, or capabilities owned by another track.
