# worker_03 — Phase 02: 02 controlled evaluation and claim audit

**Status: COMPLETED & TESTED.**

## Objective
02 controlled evaluation and claim audit.

## Inputs and dependencies
Master plan; shared interface contracts; prior phase outputs; approved repo/stack; controlled fixtures. Coordinate dependencies in `.work/shared/dependency_graph.md`.

## Tasks
Freeze controlled evaluation set or eligible dataset manifest; verify source, terms, version, hash, label/time semantics; measure baselines only if data gate passes; conduct error review and pitch claim audit.

## Deliverables
- Working module: `src/trusttrace/policy/evaluation.py`
- Tests: part of `tests/test_triage_policy.py` — evaluation and claim audit tests
- Updated status and handoff with commit/evidence.
- Phase report at `.report/worker_03_phase_02_report.md`.

## Evidence
- 7 golden fixtures: FIX-001 through FIX-007, all passing
- Decision accuracy: 100% on simulated fixtures (noted as limited sample)
- Class prevalence reported honestly
- ClaimAuditor: 7 tests covering accuracy, safety, novelty, probability claims
- CLAIM-001: Unsupported claims correctly flagged

## Validation and acceptance
Record sample counts ✅, class prevalence ✅, fixtures labeled simulated ✅, negative result accepted ✅.
No random-split-only generalization claims ✅; no dataset absence as benign ✅; no fabricated metrics ✅.
