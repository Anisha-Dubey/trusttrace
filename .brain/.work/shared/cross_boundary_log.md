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

