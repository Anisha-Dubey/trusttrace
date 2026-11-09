# worker_01 — Phase 02: 02 bounded collectors and partial-result semantics

**Status: PLANNED — NOT EXECUTED.**

## Objective
02 bounded collectors and partial-result semantics.

## Inputs and dependencies
Master plan; shared interface contracts; prior phase outputs; approved repo/stack; controlled fixtures. Coordinate dependencies in `.work/shared/dependency_graph.md`.

## Tasks
Implement bounded DNS/TLS/redirect/header collectors; record source, time, status, limitations; revalidate every redirect and DNS result; add timeout/byte/concurrency limits and safe partial result.

## Deliverables
- Working module or explicit fixture-backed interface.
- Tests and brief run instructions.
- Updated status and handoff with commit/evidence.
- Phase report at `.report/worker_01_phase_02_report.md`.

## Validation and acceptance
Mocks for DNS/TLS/redirect/error/timeout/large response; prove prohibited redirect blocked; confirm no auth/cookie forwarding.

## Safety/claim guard
Do not render pages or submit forms; no active vulnerability testing.

## Risks and handoff
Escalate blockers before parallel work is built on an unstable contract. Hand off actual changed files, interfaces, commands, test outcomes, limitations and next step.
