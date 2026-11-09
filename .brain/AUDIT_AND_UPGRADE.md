# TRUSTTRACE `.brain` quality audit and upgrade

**Audit date:** 2026-11-09  
**Scope:** The supplied `HackMatrix-TRUSTTRACE-brain.zip`, including its planning, research, demo, worker, tester, and report files. This is a documentation audit; no application repository or implementation was supplied for code-level verification.

## Rating

**Before upgrade: 7.8/10 for a hackathon planning workspace.**  
**After this documentation upgrade: 9.2/10 for planning quality.**  
**Implementation/release readiness: not rated / not demonstrated.**

A literal 10/10 end-to-end rating would be misleading: worker and tester states are planned, report stubs are not execution evidence, and the archive contains no product implementation, executed test results, or rehearsed demo. The most responsible route to 10/10 is to complete the closure checklist below with evidence—not to raise the score by wording alone.

## Scorecard

| Dimension | Before | After | Rationale |
|---|---:|---:|---|
| Scope and hackathon feasibility | 9 | 9 | Clear vertical slice; long-term research is separated from MVP. |
| TRUSTTRACE research alignment | 8 | 9 | Strong separation of identity, TLS, behavior, feed assertions, models, and uncertainty; evidence provenance is central. |
| Safety and threat awareness | 8 | 9 | SSRF, redirects, private IPs, limits, credentials, and browser isolation are explicit; executable test cases still need implementation. |
| Interfaces and traceability | 7 | 8 | Ownership and high-level requirements exist; schemas and acceptance evidence need more concrete, versioned examples. |
| Execution readiness and accountability | 6 | 8 | Planning status is honest, but no named owners, deadlines, dependency sign-offs, or objective exit artifacts are recorded. |
| QA and evaluation discipline | 7 | 9 | Good anti-overclaiming guidance; tests need precise expected outcomes, severity, and evidence capture. |
| Research provenance and archive hygiene | 8 | 8 | Audit cautions are valuable; two links in retained original material point to paths outside the archive and were not silently rewritten. |
| Demo readiness | 8 | 9 | Safe, clear scenario plan and fallback; rehearsal evidence and exact fixture manifest are outstanding. |

## What is already strong

- The README clearly calls this a planning workspace and explicitly disclaims unverified code, tests, scans, metrics, and rehearsal.
- Scope control is unusually good: a coherent scan-to-report MVP is favored over an implausible full research platform.
- Core TRUSTTRACE semantics are responsible: valid TLS is not identity assurance; feed absence is not a benign verdict; failures and unknowns remain visible; community reports are not automatically ground truth.
- The safety boundary is explicit and correctly treats arbitrary browsing as a separate, gated capability.
- Research limitations and novelty cautions are preserved rather than hidden, including PhishShift as a strategic caveat without silently replacing the chosen concept.

## Current remaining gaps after the follow-up package

The following are still open based on the current archive: no application implementation or runtime security evidence is included; owner/reviewer/deadline fields are `TBD`; the retention policy and decision policy remain drafts requiring team approval; no threat-feed or identity-provider integration is selected; functional, SSRF, and demo tests remain `PLANNED`; and the chosen official HackMatrix track/problem statement is not confirmed in this archive. These are real blockers to implementation/release claims.

The follow-up package has addressed several original documentation gaps: versioned schemas and fixtures, case-level test IDs, a proposed privacy/retention policy, a source-link map, and repair of the known synthesis line-break artifacts. The validator passing fixture checks does not prove runtime controls. See `UPGRADE_CHANGELOG.md` and `COMPETITION_PLAYBOOK.md` for the later additions and event-specific constraints.

## Upgraded execution closure checklist

Do not mark an item complete without attaching a commit/build identifier, command or procedure, result, and retained evidence (log, screenshot, fixture output, or reviewer sign-off).

### Gate A — Contract freeze
- [ ] Name one accountable person and one reviewer for each worker and tester role; record event deadline and available implementation hours.
- [ ] Publish a versioned request/result schema with explicit enums for scan state, evidence type, source status, identity status, and final assessment; include at least one complete, partial, failed, and conflicting example.
- [ ] Specify timestamp format/time zone, evidence identifiers, source attribution, freshness semantics, policy version, and whether raw URLs/observations are stored.
- [ ] Agree an MVP source policy: fixtures first; every live provider must have documented terms, rate limits, retention, and failure behavior.

### Gate B — URL and network safety
- [ ] Validate parsing, HTTP(S)-only policy, userinfo rejection, IDNA normalization, IPv4/IPv6 literals, ambiguous numeric forms, and malformed URL cases.
- [ ] Resolve and reject loopback, private, link-local, multicast, reserved, and metadata-service destinations for both address families; test DNS rebinding and re-check immediately before connection.
- [ ] Revalidate each redirect target and cap redirect count; block downgrade or unsupported scheme transitions.
- [ ] Prove connect/read/total timeouts, response-byte ceiling, concurrency ceiling, request rate limit, and cancellation behavior under tests.
- [ ] Verify no cookies, authorization, client certificates, or user-supplied secrets are forwarded; no forms submitted, scripts executed, files downloaded/executed, or arbitrary ports probed.
- [ ] If browser rendering is not isolated with tested egress controls, keep it disabled and document that boundary.

### Gate C — Evidence and decision integrity
- [ ] Every finding references immutable evidence IDs and carries observation time, source/provider, collection status, limitations, and rule/policy version.
- [ ] Keep certificate validity/hostname match separate from organizational identity authorization.
- [ ] Show check coverage and stale/missing/failed observations; no feed match never becomes `safe`.
- [ ] Test duplicated, copied, dependent, stale, conflicting, and unverified community signals; they must not silently increase independent corroboration.
- [ ] Test deterministic policy cases including conflicting indicators and insufficient evidence; abstention/partial/inconclusive outputs must be reachable and explainable.

### Gate D — Evaluation and user-facing claims
- [ ] If reporting model metrics, record dataset URL/version/hash, license/terms, collection date, label policy, exclusions, deduplication, grouping/split strategy, sample counts, prevalence, and confidence/limitations.
- [ ] Avoid leakage by grouping related URLs by registrable domain where applicable; do not call a random-row split a generalization test.
- [ ] Label synthetic/demo results clearly and segregate them from real-world performance measurements.
- [ ] Review UI, demo script, and pitch for unsupported safety, accuracy, coverage, and novelty claims.

### Gate E — Release/demo evidence
- [ ] Run functional and security suites against the integrated build; record failing tests and disposition, not just a pass summary.
- [ ] Rehearse the two-minute flow with an offline fixture fallback; record date, build, duration, observed blockers, and owner sign-off.
- [ ] Confirm secrets are absent from repository, logs, screenshots, and fixtures; verify setup steps from a clean environment.
- [ ] Resolve or explicitly accept every critical/high blocker with the person accountable and a fallback; disable any feature whose safety gate did not pass.

## Verification boundary and next step

The documentation upgrade improves auditability and turns the plan into a clearer set of gates. It does **not** upgrade project implementation status. Next, the team should freeze Gate A, implement the fixture-based vertical slice, then run Gates B–E against the actual build. Update `.report/` only with observed results and evidence; keep the current planned templates intact until execution occurs.


## Upgrade 2 verification addendum

The subsequent package adds versioned JSON contracts, fixtures and reusable validation, P0/P1 test cases, provider/source and retention decisions, a policy table, claims register, owner roster, runbooks and release-gate templates. It also restores the UTF-8 research-audit filename and aligns the retained-source manifest with the actual files. The fixture validator passed eight schema/negative/cross-record fixture checks, and source hashes were checked. This verifies the documentation bundle only; actual implementation and runtime gates remain unexecuted. See `UPGRADE_CHANGELOG.md`.


## Audit currency note

This audit has been updated to supersede its initial open-gap list. The closure checklist remains a set of execution gates, not a claim that they passed. Event-specific online and offline requirements were checked against the official HackMatrix handbook, homepage, and submission guidance on 9 November 2026; public pages have inconsistencies, so the logged-in team dashboard and current official announcements control.


## Competition-readiness addendum

`COMPETITION_PLAYBOOK.md` and `WINNING_EXECUTION_RUNBOOK.md` translate the public HackMatrix rubric and submission guidance into a challenge-fit gate, feature priorities, truthful demo script, rehearsal checks, and final link checks. They do not establish the actual selected prompt/track, online shortlist rubric, winner probability, implementation quality, or event submission status. The offline prompt/continuation rules and submission form have discrepancies across official public pages; confirm the controlling dashboard/organizer instructions before building or reusing assets.
