# TRUSTTRACE

**Evidence Passport for Web Threat & Digital Trust Triage**  
*HackMatrix ’26 Project Submission*

[![Test Suite](https://img.shields.io/badge/tests-127%20passed-brightgreen.svg)](file:///run_tests.py)
[![Architecture](https://img.shields.io/badge/architecture-4%20worker%20modular-blue.svg)](file:///.brain/.work/shared/task_assignment.md)
[![Boundary Policy](https://img.shields.io/badge/security-strict%20SSRF%20guard-red.svg)](file:///src/trusttrace/intake/ip_classifier.py)
[![License](https://img.shields.io/badge/platform-FastAPI%20%7C%20Python%203.10%2B-blue.svg)](file:///src/trusttrace/api/app.py)

---

## 1. Executive Overview

Most traditional web scanners output binary **green/red** badges or arbitrary scores. If a domain isn't on a known blacklist and has an active HTTPS connection, it is often erroneously labeled "safe". In reality, modern phishing infrastructure routinely utilizes valid DV certificates (e.g. Let's Encrypt), and a negative blacklist hit does not prove organizational legitimacy.

**TRUSTTRACE** introduces the **Evidence Passport**: an evidence-first web trust triage platform that:
- **Separates Certificate from Identity:** Verifies cryptographic transport encryption separately from organizational authorization.
- **Enforces Mathematical Coverage:** Guarantees that `checks_total == checks_observed + checks_failed + checks_not_run` without silent drops.
- **Preserves Traceable Provenance:** Every displayed finding links directly to a timestamped observation, source identity, and recorded limitations.
- **Abstains Honestly on Uncertainty:** Never averages away contradictory threat signals; conflicting observations trigger explicit caution/inconclusive states.

---

## 2. Quickstart: 1-Click Launch

### Windows (Direct Launch)
Double-click [`launch.bat`](file:///launch.bat) or run from PowerShell:
```cmd
.\launch.bat
```

### Cross-Platform (macOS / Linux / Windows)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the application
python run_app.py
```

The launcher will initialize the SQLite database and automatically open your default browser to:
* **Interactive Web Dashboard:** [http://localhost:8000](http://localhost:8000)
* **Interactive Swagger API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
* **ReDoc Technical Reference:** [http://localhost:8000/redoc](http://localhost:8000/redoc)
* **Subsystem Health Probe:** [http://localhost:8000/health](http://localhost:8000/health)

---

## 3. Interactive Web Dashboard Features

When launched, the interactive dashboard exposes the complete end-to-end user journey:

1. **Target URL Input & Custom Triage:**
   Enter any domain or URL to evaluate real-time URL normalization, query credential redaction, and SSRF/IP safety boundaries.
2. **One-Click Demonstration Scenarios:**
   - 🔴 **Phishing Lookalike with Valid TLS:** Demonstrates the core thesis—valid Let's Encrypt TLS certificate combined with unverified identity and an IDN confusable homoglyph.
   - 🟢 **Legitimate Domain:** Full multi-source verification and authorized organizational identity.
   - 🟡 **Expired TLS Certificate:** Demonstrates `TLS-002`—expired certificate is treated as a technical hygiene warning, not sole proof of phishing.
   - 🟣 **Conflicting Threat Reports:** Demonstrates abstention under contradictory community claims.
   - ⛔ **SSRF Prohibited Target:** Targets such as `http://169.254.169.254` (cloud metadata) or `http://127.0.0.1` are rejected immediately with zero network egress.
3. **The Evidence Passport Card:**
   - **4 Independent Dimensions:**
     1. `Identity`: `unverified` | `corroborated` | `claimed`
     2. `Certificate`: `valid_for_hostname` | `expired_or_mismatch` | `unobserved`
     3. `Behavior`: `no_threat_observed` | `suspicious` | `high_risk`
     4. `Evidence Quality`: `complete` | `partial` | `weak` | `unavailable`
   - **Coverage Arithmetic Bar:** Visual breakdown of observed, failed, and not run checks.
   - **Traceable Findings Drawer:** Shows rule ID, linked evidence IDs, and plain-language rationale.
   - **Evidence Drawer:** Shows observation timestamps, source attribution, and technical limitations.
4. **Collaborative Threat Intelligence:**
   - Live community threat feed.
   - Report submission form with real-time XSS sanitization and HMAC-SHA256 reporter pseudonymization.

---

## 4. Subsystem Architecture & Workstream Ownership

TRUSTTRACE is built with strict modular isolation across 4 specialized engineering tracks:

```text
Decision Vocabulary & Safety Policy
                 │
                 ▼
       Worker 02 (Schemas & Evidence Contracts)
        ├──► Observation schema
        ├──► Finding schema
        └──► Report schema
                 │
  ┌──────────────┼───────────────────────────┐
  ▼              ▼                           ▼
Worker 01      Worker 03                   Worker 04
(Safe URL &   (Decision policy            (Interactive UI &
 Collectors)   & triage rules)             User Journey)
  │              │                           │
  └──────────────┴──────────────┬────────────┘
                                ▼
                   Integrated Web Platform
                                │
                                ▼
                 Tester 01 (Functional Tests)
                 Tester 02 (Security Signoff)
```

| Workstream | Key Responsibilities | Codebase Location |
| :--- | :--- | :--- |
| **Worker 01**<br>Safe Intake & Bounded Collectors | URL canonicalization, credential blocking, IDNA punycode handling, RFC1918/loopback/cloud-metadata SSRF guards, DNS rebinding mitigation, bounded TLS/DNS/HTTP collectors, 64 KB response body cap, sliding-window rate limiting. | [`src/trusttrace/intake/`](file:///src/trusttrace/intake/)<br>[`src/trusttrace/collectors/`](file:///src/trusttrace/collectors/) |
| **Worker 02**<br>Evidence & Collaborative Intel | Pydantic v2 schemas, SQLAlchemy 2.0 ORM models, coverage arithmetic invariant enforcement, SHA-256 fingerprinting, community report lifecycle state machine, source deduplication, Alembic migrations, REST APIs. | [`src/trusttrace/evidence/`](file:///src/trusttrace/evidence/)<br>[`src/trusttrace/api/`](file:///src/trusttrace/api/)<br>[`alembic/`](file:///alembic/) |
| **Worker 03**<br>Decision Policy & Evaluation | 18-signal taxonomy across 4 dimensions, deterministic triage engine with 6 named rules, 7 golden evaluation fixtures, automated pitch claim auditor (`CLAIM-001`). | [`src/trusttrace/policy/`](file:///src/trusttrace/policy/) |
| **Worker 04**<br>UI, Workflow & Launch System | Interactive single-page Evidence Passport dashboard, scenario fixture selectors, application launcher (`run_app.py`, `launch.bat`), and project documentation. | [`src/trusttrace/web/`](file:///src/trusttrace/web/)<br>[`run_app.py`](file:///run_app.py)<br>[`launch.bat`](file:///launch.bat) |
| **Testers**<br>QA & Security Assurance | 127 automated unit, integration, and security tests. Security audit covering SSRF, redirect boundaries, header stripping, and XSS sanitization. | [`tests/`](file:///tests/) |

---

## 5. Verification & Testing

The repository includes a comprehensive automated test suite and boundary verification system.

### Running the Test Suite
```bash
python run_tests.py
```
*Current test results:* **127 tests passed** (0 errors, 0 failures) + **8 JSON schema and negative invariant checks passed**.

### Enforcing Worker Boundaries & "Ask Twice" Protocol
To ensure team members develop in parallel without unauthorized cross-boundary file modifications, run:
```bash
# Verify all working changes adhere to locked domain rules:
python scripts/check_worker_boundaries.py

# Verify changes for a specific assigned track:
python scripts/check_worker_boundaries.py --worker worker_01
```

---

## 6. Project Documentation & Research Brain

All architectural specifications, threat models, research papers, and competition playbooks are located in the [`.brain/`](file:///.brain/README.md) directory:
- [Competition Playbook](file:///.brain/COMPETITION_PLAYBOOK.md) — Rubric alignment and judge Q&A strategies.
- [Winning Execution Runbook](file:///.brain/WINNING_EXECUTION_RUNBOOK.md) — Timeboxed build strategy and vertical slice rules.
- [Worker Boundary Protocol](file:///.brain/.work/shared/worker_boundary_protocol.md) — Two-confirmation access governance.
- [Interface Contracts](file:///.brain/.work/shared/interface_contracts.md) — Canonical v1 JSON schemas for requests, evidence, and reports.
- [Research Synthesis](file:///.brain/.research/research_synthesis.md) — Theoretical grounding and empirical literature citations.

---

## 7. Submission Checklist & Rubric Alignment

- [x] **Working Local & Live Demo:** One-click launch with zero external dependencies required (`launch.bat`).
- [x] **Truthful Claim Boundary:** No fabricated accuracy numbers; all simulated fixtures are clearly labeled.
- [x] **Security & Egress Controls:** Live network scanning is bounded by strict SSRF and redirect limits.
- [x] **Traceability:** 100% of findings reference verifiable evidence IDs and policy rule versions.
- [x] **Clean Setup:** Requirements pinned in `requirements.txt`, clean database migrations via Alembic.
