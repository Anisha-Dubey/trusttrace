# Shared interface contracts (proposed)

## Scan request
`{url: string, profile: "fixture" | "passive_metadata", client_request_id?: string, consent_to_external_lookup?: boolean}` as defined by `.work/contracts/v1/scan_request.schema.json`. Server returns `202`/scan ID for async operation or synchronous documented response for fixture-only prototype. Never accept arbitrary scan flags from client that bypass policy. Do not enable external lookup solely from a client boolean; consent does not replace provider terms or server policy.

## Observation
`{evidence_id, scan_id, kind, value, source, observed_at, status, reliability, limitations[]}`. `status`: `observed | unavailable | failed | not_run | blocked`. Store only minimum data; redact query secrets.

## Finding
`{finding_id, kind, severity, summary, evidence_ids[], rule_id, rule_version, source_type, created_at, limitations[]}`. A finding must not assert beyond its evidence.

## Scan report
`{scan_id, submitted_url_redacted, normalized_host, status, decision, dimensions, findings[], evidence[], policy_version, created_at, completed_at, coverage}`. `decision`: `high_risk | caution | no_threat_observed | inconclusive | rejected | failed`. Scan `status`: `queued | validating | collecting | analyzing | completed | partial | failed | rejected`.

## Community report
`{report_id, normalized_domain, claim_type, note_redacted, submitted_at, verification_state, independent_source_count, linked_evidence_ids[]}`. Verification state `unverified | corroborated | disputed | reviewed`. Never expose reporter private identifiers in public feed. Deduplicate by normalized claim/domain/time/source family.

## Contract rule
These are proposed hackathon contracts, not implemented API guarantees. Freeze versions before parallel implementation; add schema tests and update this document with actual changes.
