# worker_04 — Phase 02: 02 integrated scan workflow

**Status: COMPLETED & VERIFIED.**

## Objective
02 integrated scan workflow.

## Deliverables
- Integrated preflight intake gate (`IntakeBoundary`) blocking SSRF, loopback, and credentials.
- Connected real bounded collection pipeline (`ScanOrchestrator`) without evidence fabrication.
- Integrated `PolicyInput`, `TriageEngine.evaluate_evidence`, and `ReportIntegrityAuditor`.
- Connected community intelligence reporting (`POST /api/v1/community/reports`).
- Phase report at `.brain/.report/worker_04_phase_02_report.md`.

## Validation and acceptance
End-to-end contract test; partial scan and conflict demo; test missing provider; verify no secret leakage and all simulated values are marked.

## Safety/claim guard
Do not hide collector failure behind a green score.

## Risks and handoff
Escalate blockers before parallel work is built on an unstable contract. Hand off actual changed files, interfaces, commands, test outcomes, limitations and next step.
