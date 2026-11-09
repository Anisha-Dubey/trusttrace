# worker_02 — Phase 01: 01 evidence contracts and persistence

**Status: PLANNED — NOT EXECUTED.**

## Objective
01 evidence contracts and persistence.

## Inputs and dependencies
Master plan; shared interface contracts; prior phase outputs; approved repo/stack; controlled fixtures. Coordinate dependencies in `.work/shared/dependency_graph.md`.

## Tasks
Freeze observation, finding, report and community-report schemas; distinguish observed/unavailable/failed/not-run/blocked; define redaction and retention rules; make sample data available to all workers.

## Deliverables
- Working module or explicit fixture-backed interface.
- Tests and brief run instructions.
- Updated status and handoff with commit/evidence.
- Phase report at `.report/worker_02_phase_01_report.md`.

## Validation and acceptance
Schema validation; round-trip fixtures; every displayed finding references evidence; no secrets in test logs.

## Safety/claim guard
Do not equate provider feed assertion or community claim with ground truth.

## Risks and handoff
Escalate blockers before parallel work is built on an unstable contract. Hand off actual changed files, interfaces, commands, test outcomes, limitations and next step.
