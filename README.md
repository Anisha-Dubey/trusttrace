# TRUSTTRACE

**Evidence Passport for Web Trust Triage** (HackMatrix '26)

TRUSTTRACE provides transparent, evidence-linked URL trust assessments. It separates identity, certificate validity, behavior, and evidence quality, providing verifiable reasoning without misleading "safe" verdicts.

## Architecture & Workstreams
- **Worker 01 — Safe intake & bounded collectors**: URL canonicalization, credential blocking, IDNA handling, query redaction, SSRF & DNS rebinding protection, redirect limits.
- **Worker 02 — Evidence & collaborative intelligence**: Observation schemas, provenance tracking, report fixtures, PostgreSQL/SQLite persistence, Alembic migrations, atomic Lua Redis rate limiter, RBAC-protected moderation, multi-process corroboration consistency.
- **Worker 03 — Risk policy & evaluation**: Explainable decision engine and honest evaluation metrics.
- **Worker 04 — Product workflow & integration**: User journey and interactive triage interface.
- **Project Brain**: Full specifications, runbooks, research, and audit logs are documented in [`.brain/`](file:///.brain/README.md). Detailed Worker 02 specifications are in [`.brain/.work/webapp/worker_02/architecture.md`](file:///.brain/.work/webapp/worker_02/architecture.md).

## Running Tests

All intake safety boundary rules, negative fixtures, JSON schema invariants, and Worker 02 adversarial test suites can be verified with:

```bash
python run_tests.py
```

Or with Python `unittest`:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

To run the dedicated 18-point adversarial & concurrency regression suite:

```bash
python -m unittest tests/test_phase8_adversarial_suite.py -v
```

## Database Migrations (Alembic)

```bash
# Run migrations to head
python -m alembic upgrade head

# Check current revision
python -m alembic current

# Downgrade to base (clean teardown)
python -m alembic downgrade base
```

## CI / CD Pipeline

TRUSTTRACE runs automated GitHub Actions CI (`.github/workflows/ci.yml`) on Python 3.11 and 3.12 with dedicated PostgreSQL 15 and Redis 7 service containers. All tests, migrations, and schema invariants are validated automatically on push.
