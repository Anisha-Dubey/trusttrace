# TRUSTTRACE × HackMatrix ’26 — competition playbook

**Prepared:** 9 November 2026, IST  
**Purpose:** Shape the already-selected TRUSTTRACE concept for the event. This is a strategy and communication plan, not implementation or test evidence. It cannot guarantee selection or a prize.

## What the official event materials say

The official [participant handbook](https://hackmatrix.codes/handbook) gives the offline judging weights as 25% innovation/originality, 25% technical depth/code quality, 20% impact/relevance, 20% execution/working demo, and 10% presentation/communication. It says online-round shortlisting criteria are not disclosed. The [submission guidelines](https://hackmatrix.codes/project-submission-guidelines) require a public GitHub repository and pitch deck link, and expect a demo video (3 minutes or less) plus a working live link or clear run steps. The handbook lists repository, README, video, live link or run instructions, selected track, and submission form; it does not list a pitch-deck link in its checklist. **Resolve this mismatch using the actual logged-in submission form and current event announcements.** Include a deck link anyway if the form offers it.

The pages are not fully consistent about the online build window and challenge format: the handbook describes the 7–10 November build period and a 10 November, 10:00 PM IST deadline; the homepage calls it a 48-hour sprint that begins when teams open the problem statement and describes a common statement, while the submission page says to choose a problem statement. At the time of this playbook, the online round is underway. Check the team dashboard and Discord announcement for the controlling problem statement, team-specific start/deadline, track lock, submission fields, and any update. Do not infer a track from the TRUSTTRACE concept.

The handbook prohibits pre-round code, permits research and design sketches, allows AI coding assistants and libraries subject to disclosure, and requires commit history to show work during the round. Keep the supplied `.brain` as planning/research material. Do not backdate code or misrepresent when implementation began. Disclose AI tools, libraries, APIs, templates, and reused sources accurately.

## Competition thesis: win trust by showing what the system knows—and does not know

**User problem:** People see HTTPS, a clean-looking page, or no blacklist hit and may treat that as proof a site is legitimate. Those signals do not establish that an organization authorized the site, and an unobserved threat is not a safe site.

**TRUSTTRACE promise:** Give a reviewer a concise, traceable web-risk assessment that separates certificate mechanics from identity authorization, shows what was checked and what failed or was missing, and links each conclusion to evidence and its source/time.

**Differentiating demo feature — Evidence Passport:** Every result opens as a compact, shareable evidence record: assessment state; coverage of declared checks; identity and TLS kept separate; evidence source/time/freshness; unresolved conflicts; and a plain-language rationale. The feature's strength is not an asserted first-ever algorithm. It is a visible, testable product behavior: the user can inspect why the assessment is limited instead of receiving an unexplained green/red badge.

**Judge-facing contribution statement:** “TRUSTTRACE is an evidence-first URL triage prototype. It makes missing coverage and contradictory signals visible, and it never treats HTTPS or a negative feed lookup as proof of legitimacy. In this demo, every shown result is a labeled fixture unless the interface explicitly says a bounded live check ran.” Adapt this statement to the project actually implemented. Do not say it unless the demo verifies it.

### What not to build for the competition

Do not add a generic ML score, blockchain, graph neural network, broad crawler, live page execution, or paid threat-feed integration just to make the project sound advanced. Each adds risk and explanation burden. A small, reliable end-to-end flow plus visible evidence lineage is a better fit for the known rubric than unsupported feature breadth. Keep any live scanning off unless the code-level security gates have actually passed.

## Build choices mapped to the published offline rubric

**Innovation and originality (25%).** Demonstrate evidence coverage, provenance, and contradiction handling in the user's decision path. Position it as an evidence-quality interaction and hypothesis, not an unverified novelty claim. Explain the baseline problem and what the prototype concretely changes.

**Technical depth and code quality (25%).** Show the versioned contract, schema validation, evidence-to-finding references, deterministic policy version, meaningful partial/rejected cases, safe URL boundary, and tests. Keep a clean repository with understandable modules and setup steps. The schemas and fixtures in `.work/contracts/v1/` help start this work; they do not prove the product uses them.

**Impact and relevance (20%).** Use a short concrete scenario: a user sees a valid certificate and a negative feed lookup, but authorization evidence is absent. TRUSTTRACE returns limited/inconclusive status, explains why, and offers a next step. State who benefits and which scope the prototype covers; do not claim broad protection.

**Execution and working demo (20%).** Make the whole path work in one take: submit controlled URL/fixture → show progress/state → inspect Evidence Passport → open the evidence for one finding → show partial/conflict behavior. Preload all fixtures. Provide offline fallback and clean-machine run instructions. Test the actual public links in a private browser window before submission.

**Presentation and communication (10%).** Lead with the user risk, demonstrate before explaining internals, use plain terms, and finish with honest limits and the next validation experiment. All teammates should be able to describe their contribution and explain one architectural decision.

The online-shortlisting rubric is officially undisclosed. Use the same fundamentals—clear problem fit, working project, visible contribution and reliable submission—without claiming they are the unpublished official criteria.

## Three-minute video / judge walkthrough

Target 2:30–2:45 so small pauses do not exceed the official three-minute cap. Record the real running build, not a slide presentation. Replace bracketed notes only with verified details.

- **0:00–0:15 — Problem and claim boundary:** “A padlock means an encrypted connection, not that this organization authorized this site. A missing blacklist match does not prove safety. TRUSTTRACE makes those evidence gaps visible.”
- **0:15–0:35 — Product and scope:** State the actual chosen track/problem statement. Show the deployed app or local run. Say which parts are fixtures and which, if any, are live observations.
- **0:35–1:20 — Complete case:** Submit the benign/known fixture. Show scan state, separate TLS and identity status, coverage, and an evidence detail with source and timestamp. Avoid calling the fixture a live scan.
- **1:20–1:55 — The key insight:** Open an HTTPS-but-unverified fixture. Point out that TLS is valid while authorization evidence is absent. Show a non-safe, limited status and explain one concrete next step.
- **1:55–2:20 — Failure/conflict:** Select partial or conflicting fixture. Show the failed/missing check and both sides of the conflict. Explain why the system abstains instead of averaging away uncertainty.
- **2:20–2:40 — Engineering and impact:** Name one test or contract that protects the semantics, the actual security boundary, and the intended user. Mention one limitation.
- **2:40–2:50 — Close:** “We are not claiming universal phishing detection. We are building an auditable triage record that shows its evidence and uncertainty.”

If recording, show visible “SIMULATED FIXTURE” labels. No active malicious links, personal data, secrets, or unsafe targets should appear. Ensure narration, captions, and screen text are legible, and the link opens without login.

## Likely judge questions and evidence-led answers

**“What is actually new?”** Describe the Evidence Passport interaction and show it. Say that the broad technical area has prior art and that novelty is a narrow product/evaluation hypothesis. Never say “first” without a documented comparative review.

**“Why not just use a phishing API or browser warning?”** Explain the different goal: provenance, check coverage, identity-versus-certificate distinction, and uncertainty. Acknowledge that established reputation tools may be better at their intended classification task. Do not claim measured superiority.

**“How do you know it is accurate?”** If no representative labeled evaluation has been run, say so plainly. Report schema/security tests as software checks, not detection accuracy. Show how a future evaluation would use a dated, licensed dataset, domain-separated split, baselines, class prevalence, precision/recall, false positives, and limitations.

**“How do you prevent SSRF or harm?”** Explain the implemented boundary and show passing code-level tests. If no live checks exist, say the event demo uses local fixtures and does not contact arbitrary targets. A planned test matrix is not proof of protection.

**“What if a threat feed says nothing?”** Show that the output reports no match only for the named source and time, includes coverage, and never returns “safe” solely from absence.

**“How do community reports affect the result?”** Explain current implemented verification/moderation and source-independence handling. If those are not implemented, label submissions as unverified fixture/user reports and do not claim they drive an automated verdict.

**“What did each teammate build?”** Each person names a concrete component, a difficult decision, and one artifact/test they can show. Rehearse this; do not invent ownership.

## Submission and operations checklist

Use the logged-in [team dashboard](https://hackmatrix.codes/dashboard) and official announcements as the source of truth. Current public guidance gives a 10 November 2026, 10:00 PM IST online deadline, but the dashboard may show the controlling team deadline. Submit early enough to test every link. The guidelines say that final submission locks links and require the actual form's required fields.

Before final submit:
- Confirm exact problem statement and track, team start/end time, eligibility, member list, and current rules with the dashboard/organizers.
- Provide public GitHub repository; keep it public through judging. Ensure legitimate round-period commit history and no leaked API keys, tokens, or personal data.
- Follow the official README order: project name/one-line description; problem; solution; demo links and screenshot; tech stack; architecture; setup/run steps; disclosures; track.
- Supply pitch deck link if requested by the form; video of at most three minutes; working public live link if reliable, otherwise clean-machine run steps and sample data; short description and write-up if requested.
- Test repository, deck, video, demo and live links while signed out/private. Confirm correct access permissions and no login wall.
- Declare frameworks, libraries, APIs, starter templates, AI tools, and reused materials. Never suggest AI use was absent if it was used.
- Capture a fallback screen recording or local fixture run. Keep hosting stable through judging and document any setup requirements.
- Save the final submitted links and submission confirmation; do not rely on a draft being submitted.

## Highest-value next work, in order

1. Verify dashboard problem statement, exact team-specific deadline, selected track, required form fields, and whether the online round is 48 elapsed hours. Resolve discrepancies before shaping the final story.
2. Confirm all repository work complies with the official start rule; establish a public, clean repository with round-period commits. The `.brain` is planning material, not code implementation.
3. Build one usable vertical slice against the v1 fixture contract; prioritize the Evidence Passport, provenance links, coverage/partial state, and a compelling end-to-end journey. Drop features that cannot be finished, verified, and explained.
4. Run the schema validator and unit tests immediately, then execute only the security tests applicable to enabled functions. Do not turn a planned test into a claimed pass.
5. Assign actual people to demo-critical tasks, with one integration owner. Ensure every team member can explain their contribution.
6. Record a full demo rehearsal and video; freeze scope before deadline; test all submitted links from a signed-out browser.

## Current readiness

This playbook improves positioning and submission discipline. It does not certify that TRUSTTRACE has selected the official track, complies with every dashboard rule, has working software, passed security tests, or was submitted. Update the claims and demo only from the actual build. No planning document can guarantee that judges shortlist or award the project.


## Detailed execution companion

Use `WINNING_EXECUTION_RUNBOOK.md` for the challenge-fit gate, relative sprint plan, criterion-by-criterion rehearsal, internal self-score, offline-round uncertainty plan, and final submission-lock checklist. It is a strategy aid only; follow the actual dashboard and organizer instructions.
