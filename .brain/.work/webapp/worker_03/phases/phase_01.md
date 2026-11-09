# worker_03 — Phase 01: 01 explainable triage policy

**Status: PLANNED — NOT EXECUTED.**

## Objective
01 explainable triage policy.

## Inputs and dependencies
Master plan; shared interface contracts; prior phase outputs; approved repo/stack; controlled fixtures. Coordinate dependencies in `.work/shared/dependency_graph.md`.

## Tasks
Define signal taxonomy and conservative deterministic policy; separate identity/certificate/behavior/evidence-quality dimensions; document rationale, rule version and abstention conditions.

## Deliverables
- Working module or explicit fixture-backed interface.
- Tests and brief run instructions.
- Updated status and handoff with commit/evidence.
- Phase report at `.report/worker_03_phase_01_report.md`.

## Validation and acceptance
Golden cases: valid TLS/unverified identity; weak signal; corroborated match; no match; missing/conflicting checks. Ensure rationale supports each result.

## Safety/claim guard
Do not label arbitrary weighted score as probability; no unsupported AI/novelty claim.

## Risks and handoff
Escalate blockers before parallel work is built on an unstable contract. Hand off actual changed files, interfaces, commands, test outcomes, limitations and next step.
