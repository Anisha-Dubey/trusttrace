# Data, privacy and retention policy — draft for owner approval

**Status: PROPOSED, NOT APPROVED.** Before collecting public user URLs, the team must make and document a retention/access decision appropriate to event policy and applicable law. This document is not legal advice. Until approved, use synthetic fixtures only.

## Data classes
| Data | Examples | Handling default for prototype | Decision needed |
|---|---|---|---|
| Submitted locator | scheme, host, path, query, fragment | Do not log raw URL; strip/redact query and fragment before logs; prefer fixture mode | Is scan input persisted? TTL? deletion path? |
| Network observations | DNS answers, certificate metadata, redirect hostnames | Collect only for requested scan; timestamp and source; do not infer identity from shared hosting | Which observations retained and for how long? |
| Community report | claimed domain, category, free text, reporter metadata | Minimize free text; escape output; do not publish reporter identity; rate limit | Moderation and removal process? |
| Credentials/secrets | passwords, tokens, OTPs, payment details | Never request, autofill, transmit, or train on them; reject/redact obvious URL userinfo | None—prohibited |
| Provider credentials | API tokens | Server-side secret store only; never frontend/logs/fixtures | Who can access/rotate? |

## Required decisions before live use
- Data controller/owner and purpose; whether public submissions are permitted at all.
- Raw URL storage policy, query/fragment redaction, retention TTL, access roles, deletion and backup handling.
- Whether IP observations or user reports are personal/sensitive in the relevant context.
- Hosting region, logs, analytics, external providers and their retention terms.
- Abuse/report removal process and contact point.

## Safe default if undecided
Operate in local controlled-fixture mode. Do not persist raw user-submitted URLs. Redact query, fragment, userinfo, tokens and credentials from logs. Do not send URLs to external providers without explicit product disclosure and approved provider terms. Disable community free-text public display until moderation is implemented.
