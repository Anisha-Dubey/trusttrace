# Runbook: test, release and demo freeze

1. Pull a clean commit; record commit hash, dependency lock and environment.
2. Run schema validation, unit tests, API/contract tests and security test matrix. Preserve command/output, not just a summary.
3. Review each failed test. Track severity, owner, fix and retest. A disabled feature is acceptable only if removed from user journey and pitch.
4. Load controlled fixtures; verify complete, partial, rejected and conflicting examples.
5. Inspect result copy against `.work/shared/claims_register.md`; verify no “safe”/accuracy/novelty overclaim.
6. Run setup from a clean environment; scan repository/logs/screenshots for secrets.
7. Rehearse the `.demo/demo_scope.md` flow; record build, duration, blockers and backup.
8. Freeze scope. Publish known limitations and integration evidence.

**Release gate:** no unresolved critical/high security defect in enabled features; all privacy decisions approved; functional acceptance passed; fallback works.
