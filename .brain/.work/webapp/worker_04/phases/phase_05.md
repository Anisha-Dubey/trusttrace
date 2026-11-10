# worker_04 — Phase 05: Baseline Studio Design Engineering, Modular Bento Grid & Electric Volt Architecture

**Status: COMPLETED & VERIFIED.**

## Objective
Infuse the TRUSTTRACE presentation layer with the design engineering philosophy, visual hierarchy, and structural rigor of **Baseline Studio** (`baseline.agency` / Victor Deaconu). Implement a high-impact, brutalist-luxury interface featuring deep void canvas (`#080808`), tactile bento grid cards (`#121212`), high-contrast typography (`Space Grotesk` / `Syne` ultra-bold display + `Space Mono` / `JetBrains Mono` telemetry), and Baseline's signature **Electric Acid Volt (`#CCFF00`)** signal palette.

## Deliverables
- **Baseline Studio Design Engineering System**:
  - **Philosophy Integration**: *"People decide what level you're at before they audit what you do."* Adapted for cybersecurity triage: *"Security analysts decide what level your triage engine is at before they inspect your telemetry."*
  - **Color Architecture**: Deep Void Black (`#080808`), Charcoal Bento Surfaces (`#121212`), Hairline Structural Borders (`rgba(255, 255, 255, 0.08)`), Crisp Studio White (`#F5F5F5`), and Signature Electric Volt Accent (`#CCFF00`).
  - **Typography Pairings**:
    - Display Headings: `Space Grotesk` / `Syne` (weights 800/900, tight negative tracking `-0.04em`).
    - Data Telemetry & Code: `Space Mono` / `JetBrains Mono` with uppercase micro-indexing (`[01 // INTAKE]`, `[02 // TRANSPORT]`).
- **Tactical Bento Grid Layout**:
  - Numbered, modular bento containers with clean hairlines, corner coordinate stamps, and subtle hover elevations.
  - Interactive triage command bar with real-time intake boundary status:
    - `SEC-001`: Cloud metadata (`169.254.169.254`) and loopback rejection.
    - `SEC-002`: Embedded credentials (`user:pass@host`) prohibited without egress.
    - `Homoglyph`: Unicode Cyrillic lookalike warning in hostname labels.
  - Animated 5-stage scan sequence ticker (`[01] INTAKE GATE` -> `[02] CRYPTO AUDIT` -> `[03] DELEGATION` -> `[04] ADVERSARIAL FEEDS` -> `[05] POLICY ADJUDICATION`).
- **Baseline Project-Style Case Gallery**:
  - Full-width editorial case cards featuring oversized case numbers (`CASE // 01`), category tags, and multi-dimensional split metrics (`Transport: 100% Valid`, `Identity: 0% Spoofed`, `Behavior: Credential Trap`).
  - Instant triage trigger linking directly to the Evidence Passport.
- **High-Density Evidence Passport**:
  - Large unbundled decision badge with high-contrast electric volt styling.
  - Qualitative ordinal confidence bands (`HIGH`, `MEDIUM`, `LOW`, `NEGLIGIBLE`) with explicit anti-probability disclosures.
  - Explicit plain-language Abstention Notice banner (`INV-EVID-004`).
  - Strict mathematical coverage meter: `Total = Observed + Failed + Not Run` (`INV-COV-001`).
  - 4-Dimensional assessment grid (`01 // IDENTITY`, `02 // TRANSPORT`, `03 // BEHAVIOR`, `04 // REPUTATION`).
  - Finding cards with verifiable evidence ID tags and zero dangling findings (`INV-FINDING-001`).
  - Canonical v1 JSON drawer with one-click clipboard copying.
- **Community Threat Feed & 8 Invariants Explorer**:
  - Technical engineering documentation aesthetic matching Baseline's design system manuals.
  - Invariant category filters, formal mathematical specifications, and benchmark scenario launchers.
- **Web Audio API Procedural Synthesizer & Custom Cursor**:
  - Procedural sound generator (`SoundEngine`) with synthesized tactile clicks, scan ticks, alert sweeps, and success chimes.
  - Custom fluid cursor with reactive magnetic follower.
- **Dual-Mode FastAPI Backend Integration**:
  - Probes live backend at `/health` and `/api/v1/triage/demo` with 2s timeout.
  - Falls back gracefully to deterministic client-side evaluation engine when offline.

## Invariant Adherence
- `INV-TLS-001`: Valid DV TLS certificate explicitly separated from organizational identity in all views.
- `INV-EVID-002`: Negative blacklist matches carry non-absolute safety disclaimers.
- `INV-COV-001`: Coverage bar mathematically enforces `Observed + Failed + Not Run == Total`.
- `INV-CLAIM-001`: Ordinal confidence bands; uncalibrated pseudo-probabilities strictly prohibited.
- `INV-FINDING-001`: Every finding displays verifiable evidence ID links.
- `INV-SEC-001`: SSRF loopback and cloud metadata blocked at intake with zero network egress.

## Validation & Verification
- 10/10 tests in `tests/test_web_interface.py` pass cleanly.
- 258/258 tests in `run_tests.py` pass cleanly.
- Worker boundary checks pass with zero violations.
