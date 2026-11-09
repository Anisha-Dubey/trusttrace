# worker_01 — Phase 01: 01 URL policy and safe scan boundary

**Status: COMPLETED & TESTED.**

## Objective
01 URL policy and safe scan boundary.

## Inputs and dependencies
Master plan; shared interface contracts; prior phase outputs; approved repo/stack; controlled fixtures. Coordinated dependencies in `.work/shared/dependency_graph.md`.

## Tasks Completed
- [x] Defined URL input contract adhering to `scan_request.schema.json`.
- [x] Normalized host/IDNA; preserved Punycode and Unicode display form as contextual evidence.
- [x] Blocked unsupported schemes (`file:`, `javascript:`, `data:`, `ftp:`) before DNS or network calls.
- [x] Blocked URLs containing embedded credentials with zero network egress.
- [x] Resolved and classified IPv4/IPv6 targets against loopback, RFC1918, ULA, link-local, and cloud metadata.
- [x] Implemented connection-time validation against DNS rebinding attacks.
- [x] Built redirect evaluator with hop limits, SSRF validation at every hop, and cross-origin header stripping.
- [x] Implemented schema-compliant rejection report generation conforming to `scan_report.schema.json`.
- [x] Established fixture-only vertical slice support.

## Deliverables
- Working intake package: `src/trusttrace/intake/`
- Full test suite: `tests/` and test runner: `run_tests.py`
- Completed phase report: `.report/worker_01_phase_01_report.md`
- Status & handoff updated: `.work/webapp/worker_01/status.md` and `handoff.md`

## Validation and acceptance
- 16 unit and integration tests passing (`URL-001`–`URL-005`, `SSRF-001`–`SSRF-005`, `REDIR-001`–`REDIR-003`, `DATA-001`).
- JSON Schema Draft 2020-12 validation passing on all rejection reports.
