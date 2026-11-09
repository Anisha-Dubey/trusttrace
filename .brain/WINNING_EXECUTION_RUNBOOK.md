# TRUSTTRACE — HackMatrix ’26 winning-oriented execution runbook

**Prepared:** 9 November 2026 (IST)  
**Purpose:** Convert the project brain into a focused plan for maximizing competition quality, judged relevance, and submission reliability. “Winning-oriented” means prioritizing the work with the best chance of scoring well; it is not a promise of shortlisting or a prize. This document is strategy until the team completes and verifies the work.

## First: the no-regrets gates

Do these before feature work. A technically impressive prototype that answers the wrong challenge, violates a round rule, or has broken links can lose before the judges understand it.

1. **Confirm the actual challenge and track in the team dashboard.** The `.brain` archive does not prove that TRUSTTRACE is the selected official problem statement or track. Map the published prompt to a named user, task, and outcome. If the match is weak, adapt the story and MVP to the challenge rather than forcing the TRUSTTRACE name onto an unrelated task.
2. **Confirm the operative clock and submission fields.** The official public pages differ: the handbook describes the 7–10 November online period and 10 November 10:00 PM IST cutoff; the homepage describes a 48-hour sprint starting when a team opens the prompt; public pages also differ on challenge/track flow and pitch-deck requirements. Use the logged-in dashboard and current organizer/Discord announcement as the source of truth. Save a screenshot or written confirmation of your team deadline and required fields.
3. **Check round rules and team eligibility.** The handbook says no code before the online round starts, allows research/design beforehand, permits AI assistants and libraries with disclosure, and expects all team members to explain their work. Keep the `.brain` as planning, not a claim that pre-round code was built. Ensure source history reflects actual work, tools, templates, APIs, and AI use.
4. **Name the integration lead and feature-freeze owner.** The supplied owner roster still has `TBD`. Assign real people now. If no owner is available, cut that feature.

## Competitive strategy in one sentence

**Build the smallest complete product that directly answers the selected challenge, then make the judges understand its value within the first 30 seconds and verify it with a stable, truthful demo.**

For TRUSTTRACE, the candidate product spine is **Evidence Passport**: a URL assessment that shows the checks performed, their status and freshness, separate certificate and identity conclusions, evidence behind each finding, and uncertainty/conflict without a false “safe” answer. Treat this as a hypothesis until the actual challenge prompt confirms it is relevant and the working UI demonstrates it.

## Challenge-fit gate: decide whether TRUSTTRACE is the right submission

Copy the official prompt verbatim into `.work/shared/decision_log.md` (or a new challenge brief) and answer these questions as a team:

- Who experiences the problem? What specific task are they trying to complete?
- Which explicit clause of the challenge does the current TRUSTTRACE prototype solve?
- What does the user do before and after the product? What measurable pain or risk changes?
- Which element is demonstrable in this round rather than promised as future work?
- Can a judge verify the claimed outcome from the live build in under one minute?
- What would make TRUSTTRACE a poor fit? What is the smallest adaptation that remedies that mismatch?

Score fit 0–2 for each: (a) exact prompt relevance, (b) user specificity, (c) demo-able outcome, (d) data/technical feasibility inside available time, (e) defensible distinction from a generic scanner. **0–5:** pivot to a closer challenge fit before building. **6–7:** narrow and adapt. **8–10:** proceed. This is an internal decision aid, not HackMatrix’s official scoring. Save the team's evidence and choice. Never claim fit just because the project is cybersecurity/AI themed.

## The product judges should remember

**Name:** TRUSTTRACE — Evidence Passport for web trust triage (use only if the dashboard track permits this positioning).  
**Problem:** People can mistake encryption or a clean reputation lookup for proof of organizational legitimacy.  
**Solution:** Show the evidence, source, time, check coverage, conflicts, and limits behind a cautious assessment.  
**One memorable interaction:** The page has valid TLS, but there is no separate evidence that the organization authorized the domain. TRUSTTRACE shows “TLS valid” and “identity unverified” separately and explains what was—and was not—checked.  
**Boundary:** It is a triage aid, not a universal phishing detector and not a safety guarantee.

Do not lead with the architecture acronym, “AI-powered” label, or unsupported novelty claim. Lead with the user problem, run the memorable interaction, then explain the engineering that supports it.

## Build priority: only ship a complete vertical slice

### P0 — Must work in the demo

- One obvious starting screen with the selected challenge and scope stated plainly.
- A supported submission path that validates input and provides clear errors.
- A clear state transition: accepted/rejected, running if applicable, and complete/partial/inconclusive.
- A result with distinct identity, certificate, behavior, and evidence-quality status. Remove dimensions the build cannot support honestly.
- An Evidence Passport panel that links each displayed finding to an evidence record, source, timestamp, limitation, and policy/version where those exist.
- At least one complete case and one partial or conflicting case. Label simulated fixtures visibly; never present fixtures as live scans.
- Working setup/live path with a seeded fallback and no login required for a judge.
- A modest set of automated tests run against the real code and captured in the repo/CI or logs.

### P1 — Only after P0 is stable

- Community-report submission with unverified status, safe rendering, and duplicate/source-dependence handling.
- Freshness/coverage comparison or a small user comprehension test—only if data collection and consent can be handled within the event rules.
- Visual polish, useful empty states, keyboard-accessible controls, responsive display, and loading/error states.

### Explicitly defer

Broad ML training, accuracy claims without suitable data, live browser execution, arbitrary-site crawling, active probing, passive-DNS dependencies, blockchain, graph neural networks, external feeds without terms review, and features that cannot be tested before deadline. A conservative fixture-only demo is stronger than an unsafe or unreliable public scanner.

## Timebox for the online sprint

Use relative time from the team's **verified** start time. Do not assume the clock if the dashboard says otherwise. Reserve the final 15–20% for integration, demo, and submission rather than feature work.

- **First 5% — Prompt and plan:** lock the challenge fit, assign owners, define one main user journey, select only P0 features, record exact finish time and submission checklist.
- **Next 15% — Contract and skeleton:** run the supplied fixture validator; freeze the payloads actually used; create the UI and result route; confirm clean startup and one local end-to-end fixture.
- **Next 45% — Vertical slice:** implement the user journey and Evidence Passport. Integrate continuously; do not let each component live on an untested branch until the end.
- **Next 15% — Differentiator and edge states:** add one partial/conflict behavior, evidence traceability, helpful empty/error states, and tests for critical semantics.
- **Next 10% — Hardening:** clean install, test on a second machine/browser, scan repo and logs for secrets, verify safe boundaries, and fix only P0/P1 defects.
- **Final 10% — Freeze and submit:** rehearse, record short demo video, publish README/deck/links, test as signed-out user, submit ahead of cutoff, confirm receipt, and preserve a backup recording.

If the verified time remaining is shorter, cut P1 and polish, not setup reliability or the single complete user journey. If less than a few hours remain, use fixture-only mode and submit a small functioning build rather than attempting untested scanning.

## Rubric-directed rehearsal (offline round)

The public handbook weights offline judging as innovation/originality 25%, technical depth/code quality 25%, impact/relevance 20%, execution/working demo 20%, presentation/communication 10%. The following internal checklist is a rehearsal tool, not the organizer's scoring form.

### Innovation and originality — make the difference visible

- The opening identifies one specific failure in the status quo, not “phishing is bad.”
- The core interaction demonstrates what ordinary green/red scanners hide: evidence coverage, source, time, and uncertainty.
- The team describes the novelty boundary honestly and knows the prior-art caveat in `.research/research_synthesis.md`.
- Judges can distinguish the team's actual contribution from third-party services, open-source packages, and AI-generated scaffolding.

### Technical depth and code quality — show evidence, not jargon

- A simple architecture diagram matches the implementation; contracts and fixtures are actually consumed by code.
- One team member can trace a request through validation, evidence generation, policy, and UI.
- Tests cover contract validity, finding-to-evidence references, partial/failure states, and enabled safety controls.
- No live network claim unless actual tests show URL and IP validation, redirect revalidation, time/byte limits, and safe outbound behavior. Otherwise state “fixtures only.”
- Setup works from a clean environment; dependency versions and `.env.example` are present; secrets are absent.

### Impact and relevance — make a bounded claim

- Show the selected prompt and map the product function to it explicitly.
- Name the target user and the decision this helps them make.
- Use a realistic but controlled example and say what the product does not establish.
- If claiming speed, comprehension, accuracy, or reduced risk, show the measurement and sample; otherwise call it a hypothesis.

### Execution — prove end-to-end reliability

- Demo works on the exact machine/network/session used for judging, with a reset/backup path.
- Fixtures are seeded and clearly labeled; no unpredictable internet dependency.
- One complete journey runs without navigating hidden admin pages or manually editing database records.
- If something fails, the presenter switches cleanly to the labeled recorded fixture and explains the limitation. Never disguise a recording as a live run.

### Communication — teach the decision, not the system internals

- All teammates can explain their work and the product's safety boundary.
- Start with user and payoff; demonstrate before architecture; close with measurable next step.
- Keep answers short, precise, and evidence-based. Do not answer an accuracy question with the number of unit tests.

## Self-score before each judging checkpoint

For each published dimension, privately rate 1–5 and attach proof. If proof is missing, score it 1—not aspirationally 4.

- **1:** claim only; unclear fit or broken demo.
- **2:** partial implementation; weak evidence, significant manual steps.
- **3:** usable core path; some limitations or integration roughness.
- **4:** clean tested demo; strong prompt relevance and understandable technical rationale.
- **5:** exceptional clarity and execution, with direct evidence for every material claim and no critical failure path.

Do not multiply by the published weights to forecast a result; actual judges may interpret the rubric differently. Use the score to discover the weakest axis. Fix the weakest high-weight criterion first, provided it does not destabilize the working slice.

## Offline-round strategy: plan for uncertainty

Public event materials are inconsistent. The homepage describes a fresh problem statement at the offline Hack Day; the handbook describes shortlisted teams continuing to build and be evaluated. Neither statement in this archive establishes what the shortlisted team's exact offline task will be. Before travel/build, obtain the current organizer briefing and confirm whether the project continues, pivots to a new prompt, or is judged in a different format.

Prepare a modular demo and team roles, not a fixed promise to extend the online build. Retain reusable assets that are actually allowed: UI shell, evidence schema, safe fixture harness, tested components, and presentation practice. At the offline briefing, map each asset to the fresh prompt and rules. If reuse is restricted, comply and start from the allowed materials. Make no assumptions about using the old repository/code in the second round without confirmation.

For a 12-hour day if that format is confirmed: first 30 minutes to interpret and clarify prompt; next 30 minutes to choose measurable scope and roles; next 6 hours to build one end-to-end slice; next 2 hours to integrate/harden; next 1 hour to rehearse; retain remaining time as contingency and submit before the actual lock. Follow organizer schedule; this is an internal planning template, not the official agenda.

## Submission lock checklist

Before clicking the final submit action:

- Confirm the dashboard's actual required fields; the public handbook and submission page differ on whether a pitch deck is listed.
- Confirm the final prompt, track, team deadline, and current submission portal.
- Repository is public with valid round-period commits; no secrets, personal data, active malicious URL, or private API key appears anywhere in repo history or demo artifacts.
- README follows the official order and includes project, problem, solution, demo/screenshot, tech stack, architecture, setup, disclosures, and track.
- Add a deck link if the dashboard requests it; make it public to judges.
- Demo video is at most three minutes, plays while signed out, contains working product rather than only slides, and labels simulations.
- Live link is stable through judging. If not, provide exact clean-run steps and seed data; state whether keys or special hardware are needed.
- Links open in a private/signed-out browser. Submit early, capture confirmation, and check latest saved/submitted version.
- AI, templates, libraries, public APIs, and reused assets are disclosed accurately. No claim of work before the permitted start.

## End-of-day decision rule

A feature stays only if it (1) directly answers the confirmed prompt, (2) works end-to-end, (3) has an understandable benefit, (4) can be honestly described, and (5) does not fail an enabled-feature safety gate. Otherwise cut it or mark it as future work. A working, relevant, well-explained prototype beats a broad roadmap that cannot be demonstrated.

## Current stoplight

**Green for planning:** evidence-first position, fixture architecture, testable interaction, rubric rehearsal.  
**Yellow:** track/prompt alignment, actual team owners, user-facing proof, real application integration, demo recording, public links.  
**Red for claims:** any assertion of live scanning safety, detection accuracy, superior performance, validated novelty, production readiness, online selection, or winning without direct evidence.

Update this stoplight from the actual build and dashboard. Keep all planned states marked `PLANNED` until someone runs the test or rehearsal and records evidence.

## Official sources

- [HackMatrix ’26 participant handbook](https://hackmatrix.codes/handbook) — published offline judging weights, round rules, submission checklist, and handbook schedule.
- [HackMatrix project submission guidelines](https://hackmatrix.codes/project-submission-guidelines) — dashboard workflow, links, video, README, and online deadline.
- [HackMatrix official homepage](https://hackmatrix.codes/) — public round overview and Hack Day description. Public information may differ from the handbook and dashboard; verify current instructions with organizers.
