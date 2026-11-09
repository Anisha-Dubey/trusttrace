# Worker Boundary Lock & Two-Confirmation Protocol

**Enacted:** 10 November 2026  
**Objective:** Strict isolation of worker codebases and responsibilities. No worker or contributor may enter, edit, refactor, or delete files belonging to another worker without completing the mandatory **Two-Confirmation ("Ask Twice") Protocol**.

---

## 1. Locked Domain Directory & File Mapping

Each track is locked to its designated paths. Any file within these paths is considered private to that worker:

| Worker Track | Dedicated Scope | Locked Paths & Files |
| :--- | :--- | :--- |
| **Worker 01** | Safe Intake & Bounded Collectors | • `src/trusttrace/intake/` (all files)<br>• `src/trusttrace/collectors/` (all files)<br>• `tests/test_url_policy.py`<br>• `tests/test_ssrf_boundary.py`<br>• `tests/test_redirect_boundary.py`<br>• `tests/test_bounded_collectors.py`<br>• `.brain/.work/webapp/worker_01/`<br>• `.brain/.report/worker_01_*` |
| **Worker 02** | Evidence Engine, DB & Community Intel | • `src/trusttrace/evidence/` (all files)<br>• `src/trusttrace/api/` (all files)<br>• `alembic/` (all migrations)<br>• `alembic.ini`<br>• `tests/test_evidence_intelligence.py`<br>• `tests/test_evidence_adapters.py`<br>• `tests/test_community_intelligence.py`<br>• `tests/test_api_endpoints.py`<br>• `tests/test_reliability_and_hardening.py`<br>• `.brain/.work/webapp/worker_02/`<br>• `.brain/.report/worker_02_*` |
| **Worker 03** | Triage Engine, Policy & Evaluation | • `src/trusttrace/policy/` (all files)<br>• `tests/test_triage_policy.py`<br>• `.brain/.work/webapp/worker_03/`<br>• `.brain/.report/worker_03_*` |
| **Worker 04** | UI, Integration & Demo Workflow | • `src/trusttrace/web/` or UI frontend directories<br>• User-facing presentation scripts and demo harnesses<br>• `.brain/.demo/`<br>• `.brain/.work/webapp/worker_04/`<br>• `.brain/.report/worker_04_*` |
| **Tester 01 / 02** | Independent QA & Security Assurance | • `tests/test_security_audit.py`<br>• `.brain/.work/testers/`<br>• `.brain/.report/tester_*`<br>• `.brain/.report/security_gate_report.md`<br>• `.brain/.report/release_gate_report.md` |
| **Shared / System Gates** *(Consensus Required)* | Shared Contracts, Configs & Tooling | • `.brain/.work/contracts/` (JSON schemas)<br>• `.brain/.work/shared/` (shared governance)<br>• `pyproject.toml`<br>• `pyrightconfig.json`<br>• `run_tests.py` |

---

## 2. The Mandatory "Ask Twice" (Two-Confirmation) Rule

Before ANY developer, AI agent, or collaborator edits or modifies files outside their assigned scope:

### **Step 1: First Ask — Intent & Justification (Why Cross?)**
The requesting worker must post a formal justification entry in [`.brain/.work/shared/cross_boundary_log.md`](cross_boundary_log.md) answering:
1. What exact file(s) outside your scope need modification?
2. Why can this requirement NOT be fulfilled using public interfaces, domain adapters, or mocks (e.g. `Worker01EvidenceAdapter`, `FixtureEvidenceAdapter`)?
3. What is the minimal change proposed?

### **Step 2: Second Ask — Explicit Owner Sign-Off (Approval Granted)**
The owner of the locked domain must review the request and explicitly approve:
1. Review the proposed diff or contract impact.
2. Sign off with an affirmative statement in [`.brain/.work/shared/cross_boundary_log.md`](cross_boundary_log.md) (or PR comment): `APPROVED BY @<DomainOwner> on <TIMESTAMP>`.
3. If the owner rejects or is unavailable, the requesting worker **MUST NOT TOUCH** the file and must fallback to an adapter or mock.

---

## 3. Enforcement & Verification

1. **Automated Verification:**
   Before staging, committing, or pushing code, run:
   ```powershell
   python scripts/check_worker_boundaries.py
   ```
   If a change touches paths owned by another worker, the tool halts and queries whether the change was double-confirmed and logged in `cross_boundary_log.md`.

2. **PR / Branch Protection:**
   - GitHub CODEOWNERS ([`.github/CODEOWNERS`](../../../../.github/CODEOWNERS)) automatically requests review from the domain owner.
   - Any commit violating domain boundaries without a corresponding signed entry in `cross_boundary_log.md` is subject to immediate rejection/reversion.

3. **Adapter First Principle:**
   Direct imports of another worker's internal modules are strictly banned (enforced by `test_no_worker01_internal_modules_imported_in_worker02`). Use typed adapters and JSON contracts instead.

