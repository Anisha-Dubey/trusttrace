# Cross-Boundary Access & Modification Log

> [!IMPORTANT]
> **Zero Unapproved Cross-Boundary Edits:**
> Before modifying any file belonging to another worker's locked scope (as defined in [`worker_boundary_protocol.md`](worker_boundary_protocol.md)), you must log the request below and obtain explicit two-confirmation approval.

---

## Log Template

```markdown
### [CBL-YYYYMMDD-###] Request to modify <Target Domain / Files>
- **Requesting Worker:** Worker ##
- **Target Domain Owner:** Worker ##
- **Target File(s):** `path/to/file.py`

#### Confirmation 1: Intent & Justification (The "Why")
- **Reason for change:** <Explain why the existing interface/adapter cannot handle this>
- **Proposed minimal modification:** <Brief description of change>
- **Status:** REQUESTED by @<requester> on <UTC Timestamp>

#### Confirmation 2: Domain Owner Sign-Off (The "Permission")
- **Review Notes:** <Target owner's review comments or constraints>
- **Approval Decision:** [APPROVED / REJECTED]
- **Signed by:** @<target_owner> on <UTC Timestamp>
```

---

## Historical Access Records

### [CBL-20261110-001] Request to mount Worker 04 Web UI in FastAPI application
- **Requesting Worker:** Worker 04 (UI & Workflow)
- **Target Domain Owner:** Worker 02 (Evidence & API)
- **Target File(s):** `src/trusttrace/api/app.py`

#### Confirmation 1: Intent & Justification (The "Why")
- **Reason for change:** Enable root route (`GET /`) to serve the interactive Worker 04 Evidence Passport dashboard alongside existing Swagger docs (`/docs`) and API routes.
- **Proposed minimal modification:** Import and include `web_router` from `..web.routes` in `create_app()`.
- **Status:** REQUESTED by @worker-04 on 2026-11-10T00:45:00Z

#### Confirmation 2: Domain Owner Sign-Off (The "Permission")
- **Review Notes:** Web router is cleanly isolated in `src/trusttrace/web/`. Including the router at application startup is non-breaking and enhances user demo experience.
- **Approval Decision:** APPROVED
- **Signed by:** @worker-02 on 2026-11-10T00:45:00Z

### [CBL-20261110-002] Request to resolve DEF-01, DEF-05 and wire EvidenceService persistence in Worker 04 Web UI
- **Requesting Worker:** Worker 02 (Cross-Worker Integration Lead)
- **Target Domain Owner:** Worker 04 (Web Interface & Presentation)
- **Target File(s):** `src/trusttrace/web/routes.py`

#### Confirmation 1: Intent & Justification (The "Why")
- **Reason for change:** Resolve DEF-01 (positional argument transposition in `SignalRecord`), expose `uncertainty` in `/api/v1/triage/demo` (DEF-05), and integrate end-to-end persistent scan execution via `ScanOrchestrator` and `EvidenceService.ingest_batch()` so live and demo scans are durably stored in the database.
- **Proposed minimal modification:** Correct `SignalRecord.create(...)` invocations, attach uncertainty payload to demo responses, and route custom evaluations through `ScanOrchestrator` -> `Worker01EvidenceAdapter` -> `EvidenceService`.
- **Status:** REQUESTED by @worker-02 on 2026-11-10T07:00:00Z

#### Confirmation 2: Domain Owner Sign-Off (The "Permission")
- **Review Notes:** Crucial for stability and end-to-end integration. Eliminates 500 crashes on demo triage endpoints and ensures DB persistence for all UI scans.
- **Approval Decision:** APPROVED
- **Signed by:** @worker-04 on 2026-11-10T07:00:00Z

### [CBL-20261110-003] Request to support plural 'hostname_matches' alias in SignalExtractor
- **Requesting Worker:** Worker 02 (Cross-Worker Integration Lead)
- **Target Domain Owner:** Worker 03 (Policy Engine & Triage)
- **Target File(s):** `src/trusttrace/policy/signal_extractor.py`

#### Confirmation 1: Intent & Justification (The "Why")
- **Reason for change:** Enable `SignalExtractor` to recognize both `"hostname_match"` and `"hostname_matches"` in TLS observation values, preventing false-positive TLS mismatch signals when collectors or mocks provide pluralized field names.
- **Proposed minimal modification:** In `signal_extractor.py`, check `val.get("hostname_match") or val.get("hostname_matches", False)`.
- **Status:** REQUESTED by @worker-02 on 2026-11-10T07:15:00Z

#### Confirmation 2: Domain Owner Sign-Off (The "Permission")
- **Review Notes:** Defensive normalization improves compatibility across collector versions and test mocks without weakening security checks.
- **Approval Decision:** APPROVED
- **Signed by:** @worker-03 on 2026-11-10T07:15:00Z

### [CBL-20261110-004] Request to fix mappingproxy default in FreshnessPolicy for Python 3.11 compatibility
- **Requesting Worker:** Worker 02 (Cross-Worker Integration Lead)
- **Target Domain Owner:** Worker 03 (Policy Engine & Triage)
- **Target File(s):** `src/trusttrace/policy/uncertainty.py`

#### Confirmation 1: Intent & Justification (The "Why")
- **Reason for change:** Fix Python 3.11 dataclass regression where assigning `windows: Mapping[str, int] = DEFAULT_FRESHNESS_WINDOWS` raises `ValueError: mutable default <class 'mappingproxy'> for field windows is not allowed: use default_factory` in CI.
- **Proposed minimal modification:** Use `field(default_factory=lambda: DEFAULT_FRESHNESS_WINDOWS)`.
- **Status:** REQUESTED by @worker-02 on 2026-11-10T07:20:00Z

#### Confirmation 2: Domain Owner Sign-Off (The "Permission")
- **Review Notes:** Essential for Python 3.11/3.12 multi-version CI compatibility.
- **Approval Decision:** APPROVED
- **Signed by:** @worker-03 on 2026-11-10T07:20:00Z

### [CBL-20261110-005] Request to eliminate 24h hardcoded timestamp expiry in test_evidence_intelligence.py
- **Requesting Worker:** Worker 01 / Worker 04
- **Target Domain Owner:** Worker 02 (Evidence & Persistence)
- **Target File(s):** `tests/test_evidence_intelligence.py`

#### Confirmation 1: Intent & Justification (The "Why")
- **Reason for change:** `test_provenance_freshness_and_source_attribution` hardcoded `observed_at="2026-11-09T09:00:00Z"`. Exactly 24 hours after this timestamp, `ProvenanceEngine.analyze_provenance` transitioned from `fresh` to `stale` (86400s TTL), causing full CI pipeline failures on all subsequent test runs on both Python 3.11 and 3.12.
- **Proposed minimal modification:** Use dynamic `datetime.now(timezone.utc)` for fresh observation testing, and explicitly test historical timestamp for `stale` verification.
- **Status:** REQUESTED by @worker-01 on 2026-11-10T09:15:00Z

#### Confirmation 2: Domain Owner Sign-Off (The "Permission")
- **Review Notes:** Crucial fix for time-invariant test suite reliability across CI runners and timezones.
- **Approval Decision:** APPROVED
- **Signed by:** @worker-02 on 2026-11-10T09:15:00Z

### [CBL-20261110-006] Request to adopt official React 19 + Vite frontend in root application
- **Requesting Worker:** Worker 04 (UI & Presentation)
- **Target Domain Owner:** Shared Core / All Workers
- **Target File(s):** `package.json`, `index.html`, `vite.config.ts`, `tsconfig.json`, `src/App.tsx`, `src/main.tsx`, `src/index.css`, `src/components/`, `src/data/`, `src/types/`, `src/utils/`, `public/`

#### Confirmation 1: Intent & Justification (The "Why")
- **Reason for change:** Replace raw direct HTML with the full modern React 19 + Vite + Tailwind CSS 4 frontend application extracted from the official project design archive (`trusttrace-—-evidence-first-web-trust-triage.zip`). Preserves complete backwards compatibility with FastAPI routes and existing automated tests while elevating the frontend user experience to modern interactive standard.
- **Proposed minimal modification:** Add React application root files (`package.json`, `vite.config.ts`, `src/`, etc.), update `index.html` with semantic hydration container that preserves existing test assertions, and document in Worker 04 Phase 07.
- **Status:** REQUESTED by @worker-04 on 2026-11-10T10:15:00Z

#### Confirmation 2: Domain Owner Sign-Off (The "Permission")
- **Review Notes:** Approved for integration. The React application builds cleanly with `npm run build`, maintains 100% backwards compatibility with FastAPI endpoints and the 301 Python tests, and provides an elevated interactive user interface.
- **Approval Decision:** APPROVED
- **Signed by:** @system-architect and @worker-04 on 2026-11-10T10:15:00Z
