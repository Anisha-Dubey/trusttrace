# TRUSTTRACE

**Evidence Passport for Web Trust Triage** (HackMatrix '26)

TRUSTTRACE provides transparent, evidence-linked URL trust assessments. It separates identity, certificate validity, behavior, and evidence quality, providing verifiable reasoning without misleading "safe" verdicts.

## Architecture & Workstreams
- **Worker 01 — Safe intake & bounded collectors**: URL canonicalization, credential blocking, IDNA handling, query redaction, SSRF & DNS rebinding protection, redirect limits.
- **Worker 02 — Evidence & collaborative intelligence**: Observation schemas, provenance tracking, report fixtures.
- **Worker 03 — Risk policy & evaluation**: Explainable decision engine and honest evaluation metrics.
- **Worker 04 — Product workflow & integration**: User journey and interactive triage interface.
- **Project Brain**: Full specifications, runbooks, research, and audit logs are documented in [`.brain/`](file:///.brain/README.md).

## Running Tests

All intake safety boundary rules, negative fixtures, and JSON schema invariants can be verified with:

```bash
python run_tests.py
```

Or with Python `unittest`:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```
