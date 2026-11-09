# worker_02 — Phase 02: 02 community intelligence lifecycle

**Status: PLANNED — NOT EXECUTED.**

## Objective
02 community intelligence lifecycle.

## Inputs and dependencies
Master plan; shared interface contracts; prior phase outputs; approved repo/stack; controlled fixtures. Coordinate dependencies in `.work/shared/dependency_graph.md`.

## Tasks
Implement report intake, normalized-domain grouping, duplicate/source-family handling, status transitions (unverified/corroborated/disputed/reviewed), privacy-preserving display and audit metadata.

## Deliverables
- Working module or explicit fixture-backed interface.
- Tests and brief run instructions.
- Updated status and handoff with commit/evidence.
- Phase report at `.report/worker_02_phase_02_report.md`.

## Validation and acceptance
Duplicate/copied-source cases do not inflate independent count; conflict remains visible; rate/abuse tests; reviewer status is auditable.

## Safety/claim guard
No auto-training from user reports; no public reporter identity.

## Risks and handoff
Escalate blockers before parallel work is built on an unstable contract. Hand off actual changed files, interfaces, commands, test outcomes, limitations and next step.
