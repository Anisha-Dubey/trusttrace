# worker_03 — Phase 02: 02 controlled evaluation and claim audit

**Status: PLANNED — NOT EXECUTED.**

## Objective
02 controlled evaluation and claim audit.

## Inputs and dependencies
Master plan; shared interface contracts; prior phase outputs; approved repo/stack; controlled fixtures. Coordinate dependencies in `.work/shared/dependency_graph.md`.

## Tasks
Freeze controlled evaluation set or eligible dataset manifest; verify source, terms, version, hash, label/time semantics; measure baselines only if data gate passes; conduct error review and pitch claim audit.

## Deliverables
- Working module or explicit fixture-backed interface.
- Tests and brief run instructions.
- Updated status and handoff with commit/evidence.
- Phase report at `.report/worker_03_phase_02_report.md`.

## Validation and acceptance
Record sample counts, class prevalence, split/grouping, precision/recall/FPR/PR-AUC if model; fixtures labeled simulated; negative result accepted.

## Safety/claim guard
No random-split-only generalization claims; no dataset absence as benign; do not fabricate metrics.

## Risks and handoff
Escalate blockers before parallel work is built on an unstable contract. Hand off actual changed files, interfaces, commands, test outcomes, limitations and next step.
