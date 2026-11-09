# TRUSTTRACE — master execution plan

**Mode:** planning-only. **Project:** HackMatrix TRUSTTRACE. **Team assumption:** four contributors. **Delivery:** MVP vertical slice → safe collectors → explainable intelligence → integrated demo and assurance. Phase plans are scoped to the Hackathon, not the 24-week research roadmap in the source archive.

## Goal and measurable question
Deliver a URL-to-assessment flow that shows separate identity, certificate, behavior and evidence-quality observations, explains its result with traceable evidence, and can represent partial/inconclusive cases. Optional evaluation question: does explicit freshness/coverage/source-dependence display help users interpret cases compared with a flat rule summary? This is a hypothesis, not a result.

## Non-goals
No universal threat detection; no public claim of classifier superiority; no arbitrary-site exploit or port scanning; no real credentials; no unisolated browser execution; no automatic safe verdict from absent feed matches; no requirement for paid passive DNS; no graph neural network, blockchain or production deployment as an MVP prerequisite.

## Workstream topology
| Owner | MVP responsibility | Phases |
|---|---|---:|
| Worker 01 — Safe intake & collectors | URL normalization/SSRF safety; bounded DNS/TLS/redirect/header observations | 2 |
| Worker 02 — Evidence & collaborative intelligence | Evidence schema/provenance; report statuses and aggregation safeguards | 2 |
| Worker 03 — Risk policy & evaluation | Transparent rule policy, uncertainty, controlled test set and honest metrics | 2 |
| Worker 04 — Product workflow & integration | User journey, report UI, integration, setup and demo | 3 |
| Tester 01 — Functional assurance | Lifecycle, result semantics, evidence traceability and acceptance | 1 cycle |
| Tester 02 — Security/release assurance | SSRF controls, safe rendering, limits, regression and demo readiness | 1 cycle |

## Sequence and gates
1. **Preflight:** freeze product language, status vocabulary, safety policy, data sources, URL/report schema and team owner. Gate: no live scanning before SSRF policy is approved.
2. **Contract first:** Worker 02 defines observation/finding schema; Worker 01 and 03 agree collector and decision inputs; Worker 04 uses the same states. Gate: sample JSON passes across the team.
3. **Vertical slice:** Worker 04 integrates fixture scan → report view; Worker 01 implements validation boundary; others supply fixture observations and result semantics. Gate: full journey succeeds with fixtures.
4. **Bounded collection:** Worker 01 adds real low-impact checks if safety test gate passes; Worker 02 persists provenance; Worker 03 applies explainable policy. Gate: partial/failure results remain truthful.
5. **Intelligence loop:** community reports are displayed as unverified until justified corroboration; test duplicates and conflict. Gate: feed data cannot silently become ground truth.
6. **QA and demo freeze:** testers review integrated build; resolve blockers or disable risky features. Gate: all mandatory controls pass and fallback is clear.

## MVP completeness rule
MVP is complete only when submission, validation, bounded checks or controlled fixtures, evidence-backed report, failure/partial handling, and a rehearsed demo work end-to-end. If safe public scanning cannot be guaranteed, fixture-only mode is the correct MVP boundary—not a known unsafe live scanner.

## Acceptance targets (planned, not achieved)
- Every scan returns state and timestamps, including missing/failed checks.
- Every finding points to an evidence record/source and rule/policy version.
- Certificate validity is not presented as proof of legitimacy.
- No threat-feed match does not imply benign.
- At least one inconclusive/partial case and one conflicting/unverified report case are demonstrable.
- Safety gates cover schemes, DNS/IP classes, redirects, timeouts, bytes, rate limits and no-credential behavior.
- Any classifier claim reports dataset/version, label policy, split, prevalence, sample size and metrics; otherwise no accuracy claim.

## Stop condition
Planning is ready when interfaces, phase plans, acceptance/test criteria, demo guide, source index, risks and report templates exist. Implementation is ready only after owners verify dependencies and the actual event constraints. No implementation completion is implied by this plan.


## Execution prerequisites added in upgrade
Before implementation, assign named people in `.work/shared/owner_roster.md`; approve privacy/retention in `.work/shared/data_and_retention_policy.md`; freeze v1 JSON contracts; validate fixtures; complete the provider register for any external source. Run integration in `.work/runbooks/integration_order.md`. Live scanning remains disabled until Tester 02 signs the security gate.
