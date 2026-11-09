# worker_01 — Phase 01: 01 URL policy and safe scan boundary

**Status: PLANNED — NOT EXECUTED.**

## Objective
01 URL policy and safe scan boundary.

## Inputs and dependencies
Master plan; shared interface contracts; prior phase outputs; approved repo/stack; controlled fixtures. Coordinate dependencies in `.work/shared/dependency_graph.md`.

## Tasks
Define URL input contract; normalize host/IDNA; block unsupported schemes and URL credentials; resolve and classify IPv4/IPv6 targets; revalidate before connection; establish fixture-only vertical slice if egress checks unavailable.

## Deliverables
- Working module or explicit fixture-backed interface.
- Tests and brief run instructions.
- Updated status and handoff with commit/evidence.
- Phase report at `.report/worker_01_phase_01_report.md`.

## Validation and acceptance
URL parser tests; prohibited address fixtures; allowed controlled host; schema examples; security review.

## Safety/claim guard
Live scan remains disabled until destination checks and redirect policy pass.

## Risks and handoff
Escalate blockers before parallel work is built on an unstable contract. Hand off actual changed files, interfaces, commands, test outcomes, limitations and next step.
