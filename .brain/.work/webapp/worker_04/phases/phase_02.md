# worker_04 — Phase 02: 02 integrated scan workflow

**Status: PLANNED — NOT EXECUTED.**

## Objective
02 integrated scan workflow.

## Inputs and dependencies
Master plan; shared interface contracts; prior phase outputs; approved repo/stack; controlled fixtures. Coordinate dependencies in `.work/shared/dependency_graph.md`.

## Tasks
Integrate scan API, safe collector and evidence/policy modules; add report/community feed flow; align error handling and source attribution; maintain offline fixtures.

## Deliverables
- Working module or explicit fixture-backed interface.
- Tests and brief run instructions.
- Updated status and handoff with commit/evidence.
- Phase report at `.report/worker_04_phase_02_report.md`.

## Validation and acceptance
End-to-end contract test; partial scan and conflict demo; test missing provider; verify no secret leakage and all simulated values are marked.

## Safety/claim guard
Do not hide collector failure behind a green score.

## Risks and handoff
Escalate blockers before parallel work is built on an unstable contract. Hand off actual changed files, interfaces, commands, test outcomes, limitations and next step.
