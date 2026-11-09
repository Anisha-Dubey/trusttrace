# Team conventions

- Status terms: `PLANNED`, `IN_PROGRESS`, `BLOCKED`, `IMPLEMENTED_UNVERIFIED`, `TESTED`, `ACCEPTED`, `DEFERRED`. Do not mark completed without linked evidence.
- Keep submitted URL, normalized host, evidence source, timestamp and redaction status distinct.
- Use UTC ISO-8601 timestamps and stable internal IDs.
- Never commit secrets, credentials, real user-submitted sensitive URLs, or raw hostile HTML without an approved retention plan.
- Treat every observation as typed evidence, not unquestioned truth. Keep provider/feed assertions separate from adjudicated labels.
- PRs that touch URL fetching, DNS resolution, redirects, browser isolation, storage of user input or report verification require security review.
- Label simulated/fixture data visibly.
- Phase reports describe work performed only after it actually happens; planning templates must say `NOT EXECUTED`.
- **Worker Domain Lock & Ask-Twice Protocol:** Every worker's files and directories are locked (see `worker_boundary_protocol.md`). No contributor or agent may touch another worker's code without completing the Two-Confirmation Gate (Justification + Domain Owner Sign-Off logged in `cross_boundary_log.md`). Directly importing another worker's internal modules is strictly forbidden; always use adapters or contracts.
