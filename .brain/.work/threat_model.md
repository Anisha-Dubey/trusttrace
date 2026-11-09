# TRUSTTRACE threat model (planning)

## Assets and trust boundaries
Assets: user-submitted URLs, scan metadata, evidence, community reports, provider API credentials, stored page metadata, user sessions. Boundaries: user/browser → API; API → collectors; collector → public network; optional browser worker → untrusted page; app → external intelligence provider; user input → rendered report.

## Threats and controls
- **SSRF/internal network access:** validate URL schemes; resolve and block prohibited IP ranges; re-check redirects and DNS; deny metadata endpoints; egress firewall; bounded time/bytes.
- **DNS rebinding/redirect bypass:** validate at connection time and each hop; do not trust hostname pre-check alone.
- **Hostile page execution/browser escape:** do not render arbitrary targets unless disposable isolated browser, restricted egress and no host secrets are proven.
- **Resource exhaustion:** concurrency, response size, redirect, timeout, rate and queue limits.
- **Phishing payload or prompt injection in page content:** treat as untrusted data; escape HTML; do not follow page instructions with agent tools.
- **Threat-intel/API secret exposure:** server-side secret store; do not expose keys to browser or logs.
- **Community poisoning/Sybil/duplication:** provenance, dedup, independent source families, rate limits, review state, disputes and audit trail.
- **Privacy leakage:** redact URL query/fragment tokens; minimize retention; avoid credentials and personal data; protect reporter identities.
- **False confidence / misclassification:** separate observations and interpretations; show limitations; allow inconclusive; do not count absent feed match as clean.

## Hard safety boundary
If a required control is not implemented and tested, disable live scan capability and use controlled fixtures. This is a release blocker, not a documented caveat that can be ignored.
