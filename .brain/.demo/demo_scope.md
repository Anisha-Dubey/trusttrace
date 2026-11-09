# TRUSTTRACE controlled demo plan

**Status: planning only.** Purpose: demonstrate a user can distinguish certificate status from identity confidence, see evidence and limitations, and contribute a report without the system overstating certainty. Use fixtures and authorized benign targets only.

## Scenario set
1. **Known legitimate/control fixture:** evidence says what was observed; no claim that the open internet site is guaranteed safe.
2. **Lookalike simulation:** synthetic/mock hostname or local page with controlled suspicious indicators. Mark as simulated.
3. **HTTPS-but-unverified:** a controlled example where certificate hostname validity does not substantiate organizational endorsement.
4. **Partial/failure:** DNS/TLS lookup unavailable or timed out; decision becomes partial/inconclusive.
5. **Community conflict:** one unverified report and a conflicting observation; do not call consensus.

Keep ground truth separate from scanner inputs where possible. Avoid accessing or redistributing active malicious pages.

## Two-minute demo sequence
1. State: “HTTPS is not proof of legitimacy.”
2. Submit a controlled example; show validation and scan status.
3. Open result: show identity, certificate, behavior and evidence-quality dimensions separately.
4. Drill into a finding and point to source, time and limitation.
5. Show a missing check produces partial/inconclusive rather than green.
6. Submit community report; show unverified status and dedup/corroboration distinction.
7. Close with current limits and one testable next research question.

## Rehearsal gates
- Safety controls are implemented/tested before live scans; otherwise fixture-only.
- No credentials, OTPs, payment data, personal data or real malicious payloads submitted.
- Every synthetic datum/score is visibly marked.
- No unsupported accuracy, coverage, novelty or “safe” claim.
- One network-independent fallback is ready and labeled “recorded fixture result.”
