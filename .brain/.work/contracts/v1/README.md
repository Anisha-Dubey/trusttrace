# TRUSTTRACE API contracts — v1 (proposed)

These JSON Schemas are the canonical proposed interchange contract for the MVP. They are versioned as `1.0`; breaking changes require a new schema version and fixtures. No endpoint is implied to exist until implemented.

- `scan_request.schema.json`: submission. Format validation is not an SSRF defense; the server must apply the network safety policy.
- `scan_report.schema.json`: status, separate dimensions, coverage, typed evidence, findings and limitations.
- `community_report.schema.json`: attributable report status without public reporter identity.
- `../../../.testdata/v1/`: valid/invalid request and complete/partial/rejected/conflicting report fixtures.
- `validate_fixtures.py`: reusable schema plus cross-record invariant validation.

Cross-record checks not expressible in JSON Schema—e.g. every finding `evidence_id` exists in report evidence, or `checks_observed + failed + not_run` agrees with total—must be enforced by application validation and tests. `no_threat_observed` is not a synonym for “safe.”
