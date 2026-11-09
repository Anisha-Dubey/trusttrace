# Conservative decision policy table — v1 draft

This is a transparent starting policy, not a validated threat classifier. Each row describes permissible interpretation; actual output must cite evidence IDs and policy version.

| Evidence pattern | Disposition ceiling | Identity | Behavior | Quality / rationale |
|---|---|---|---|---|
| Exact current high-confidence provider threat assertion plus matching normalized URL/domain | `high_risk` only if provider terms/status semantics support that label; otherwise `caution` | `unknown` unless separate authorization evidence | `suspicious`/`malicious_evidence` attributed to provider | Preserve feed name, timestamp, identifier, freshness and provider uncertainty. |
| Only valid TLS hostname match | `no_threat_observed` only if all declared checks run with adequate coverage; otherwise `inconclusive`/`caution` | `unverified` absent authorization evidence | `unknown` | TLS is not identity authorization. |
| Expired/mismatched TLS, alone | `caution` at most | `unknown` | `unknown` | Technical failure is not proof of phishing. |
| IDN/lookalike heuristic, alone | `caution` at most | `unverified` | `unknown` | Candidate-generation signal can create false positives. |
| Collector failure, stale evidence, or major missing checks | `inconclusive` unless independent strong evidence already justifies caution | based only on available evidence | `unknown` | Downgrade evidence quality and show missing checks. |
| Unverified community report only | `caution` at most, or `inconclusive` depending on policy | `unknown` | `unknown` | Display as user report; no automatic label/training. |
| Independent corroborated evidence plus no material conflict | `caution` or `high_risk` according to explicit source/severity policy | separate assessment | separate assessment | Count independent source families, not copies or repeats. |
| Material credible conflict among signals | `inconclusive` or `caution`; never silently average away | `unknown`/`contradicted` only with direct evidence | `unknown` | Show both supporting and opposing evidence. |
| No reputation match and no suspicious rule fired | Never `safe`; `no_threat_observed` only with declared successful coverage | usually `unknown` | `no_threat_observed` within tested scope only | Display exact checks and scan time. |

## Policy tests
Every row needs one positive fixture, one negative/near-boundary fixture, exact expected output, evidence references, and a policy-version assertion. Changing a disposition requires a decision-log entry and regression update.
