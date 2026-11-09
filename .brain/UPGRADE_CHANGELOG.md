# TRUSTTRACE .brain — upgrade changelog

## Upgrade 2: execution-readiness package

This update responds to the prior archive review. It is a documentation, contract and planning upgrade; it does not implement the product or claim live security controls passed.

### Corrected
- Restored the original UTF-8 filename `HackMatrix_’26_Research_Audit_and_Selection_Ready_Project_Plan.md`. The source content is retained; the inherited absolute machine-local links are mapped in `.ORG_research/source_link_map.md` rather than silently altering the source.
- Rebuilt `.ORG_research/manifest.csv` to list archived source materials only, with checksums matching the actual retained files.

### Added
- Versioned JSON Schemas for scan requests, scan reports and community reports.
- Four sample report/community fixtures and valid/invalid request fixtures, plus a reusable validator for JSON Schema and cross-record invariants.
- A 30+ case CSV test matrix with stable IDs, P0/P1 priorities, expected behavior and evidence artifacts.
- Explicit policy disposition table; provider/source register; data and retention decision draft; claim-control register; named-owner roster.
- Contract-freeze, integration-order, security-gate and test/release runbooks; release and security report templates.

### Verification performed on this bundle
- ZIP structure/path check and CRC test.
- JSON Schema draft 2020-12 validation of the included fixtures, plus one negative request case and report evidence-reference/coverage arithmetic checks.
- Source manifest existence and SHA-256 checks.
- Local Markdown-link inspection; inherited source links are documented in the link map.

These checks validate the planning artifacts and fixtures only. They do not verify application code, network-safety behavior, detection accuracy, provider availability, privacy compliance or demo performance.


## Upgrade 3: competition-focused strategy

- Added `COMPETITION_PLAYBOOK.md`, aligned to the official HackMatrix ’26 offline judging weights and public online submission guidance checked 9 November 2026.
- Captured the official uncertainty that online shortlisting criteria are undisclosed and flagged discrepancies across official pages (challenge/track process, timing, and pitch-deck form field). The logged-in dashboard/current announcement is specified as controlling.
- Added a TRUSTTRACE Evidence Passport positioning hypothesis, rubric-mapped build priorities, a sub-three-minute demo script, judge-question answers, submission checklist, and round-rule cautions. These are recommendations, not claims about implemented features.
- Updated the README navigation and audit to distinguish resolved documentation gaps from remaining team decisions and unverified implementation gates.
- No application code or event submission was changed or made; the playbook does not guarantee shortlisting or a win.


## Upgrade 4: winning-oriented execution system

- Added `WINNING_EXECUTION_RUNBOOK.md` to operationalize challenge fit, priority cuts, relative sprint timeboxing, self-review against the known offline rubric, stable demo/rehearsal, submission-lock verification, and offline-round uncertainty.
- Kept unverified challenge alignment, team assignments, code, results, and demo status explicitly unresolved. Added a stoplight to prevent plans from being presented as proof.
- Updated the README and competition playbook navigation; no application code, team dashboard, or submission was changed.
