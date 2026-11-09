# Task assignment

| Owner | Accountable scope | Collaborates with |
|---|---|---|
| Worker 01 | URL normalization, safe collector boundary, bounded network observations | W02 contract; W03 signal meaning; Tester 02 security gate |
| Worker 02 | Evidence schema, source/time/provenance, community-report lifecycle | All workers on schema; Tester 01 semantics |
| Worker 03 | Rules/decision policy, uncertainty, dataset/test case validity, claim discipline | W01 signal contract; W02 provenance; Tester 01 evaluation |
| Worker 04 | User journey, UI/integration, setup docs, demo coordination | All owners; Tester 02 release |
| Tester 01 | Functional end-to-end and outcome-state assurance | W01–W04 |
| Tester 02 | Safety boundary, input/redirect abuse cases, data handling, regression | W01 and W04 primary |

Each task has one owner. Pairing is welcome; changing shared contracts requires review from affected owners.

---

## Strict Domain Locks & "Ask Twice" Boundary Rule

All code and report paths are locked per [Worker Boundary Protocol](worker_boundary_protocol.md):
- **Worker 01:** `src/trusttrace/intake/`, `src/trusttrace/collectors/`, and associated intake tests.
- **Worker 02:** `src/trusttrace/evidence/`, `src/trusttrace/api/`, `alembic/`, and evidence tests.
- **Worker 03:** `src/trusttrace/policy/` and policy tests.
- **Worker 04:** `src/trusttrace/web/`, frontend UI, and demo harnesses.

**The "Ask Twice" Gate:** No contributor or agent may modify files in another worker's locked domain without:
1. **First Ask:** Documenting necessity and proposed minimal diff in [`cross_boundary_log.md`](cross_boundary_log.md).
2. **Second Ask:** Receiving explicit sign-off from the domain's accountable owner.
Violating this gate will trigger automated pre-commit failure and immediate reversion.
