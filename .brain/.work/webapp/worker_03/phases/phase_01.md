# worker_03 — Phase 01: 01 explainable triage policy

**Status: COMPLETED & TESTED.**

## Objective
01 explainable triage policy.

## Inputs and dependencies
Master plan; shared interface contracts; prior phase outputs; approved repo/stack; controlled fixtures. Coordinate dependencies in `.work/shared/dependency_graph.md`.

## Tasks
Define signal taxonomy and conservative deterministic policy; separate identity/certificate/behavior/evidence-quality dimensions; document rationale, rule version and abstention conditions.

## Deliverables
- Working module: `src/trusttrace/policy/signal_taxonomy.py`, `triage_engine.py`, `decision_log.py`
- Tests: `tests/test_triage_policy.py` — 29 tests passing
- Updated status and handoff with commit/evidence.
- Phase report at `.report/worker_03_phase_01_report.md`.

## Evidence
- 18 signal kinds mapped to 4 dimensions
- 6 named rules with conservative disposition ceilings
- All golden cases verified: TLS-001, TLS-002, EVID-001–004, COMM-001
- Decision audit log with serialization and retrieval

## Validation and acceptance
Golden cases: valid TLS/unverified identity ✅; weak signal ✅; corroborated match ✅; no match ✅; missing/conflicting checks ✅. Rationale supports each result ✅.
