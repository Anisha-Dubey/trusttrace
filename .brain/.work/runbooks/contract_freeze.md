# Runbook: contract freeze

1. Fill owner/reviewer/time fields in `.work/shared/owner_roster.md`.
2. Review schemas under `.work/contracts/v1/`; resolve privacy, timestamps, URL redaction, coverage invariants, and status semantics.
3. Validate all four fixtures and add one invalid fixture per schema.
4. Write contract version and decision in `.work/shared/decision_log.md`; obtain W01–W04 review.
5. Do not rename enum values or fields in an implementation without a versioned schema update.
6. Start parallel phases only after integration owner confirms compatible sample payloads.

**Exit evidence:** schema-validation command output, reviewed contract version, owner acknowledgements, fixture hashes, and a commit ID.
