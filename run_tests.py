#!/usr/bin/env python3
"""Run all TRUSTTRACE test suites, database integration tests, and contract validations."""

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from trusttrace.evidence.persistence.database import default_db


def run():
    print("=" * 60)
    print("TRUSTTRACE Test Suite Runner")
    print(f"Active Database Dialect: {default_db.get_dialect_name()}")
    print(f"Sanitized Database Target: {default_db.get_sanitized_url()}")
    redis_url = os.environ.get("TRUSTTRACE_REDIS_URL")
    if redis_url:
        print(f"Configured Redis: {redis_url}")
    else:
        print("Configured Redis: None (In-Memory Limiter for Test/Dev)")
    print("=" * 60)

    # Fail-safe check: If PostgreSQL was explicitly targeted, verify it connects
    if os.environ.get("TRUSTTRACE_PG_URL") or "postgres" in os.environ.get("TRUSTTRACE_DB_URL", ""):
        if not default_db.is_postgres():
            sys.exit(
                f"FATAL: PostgreSQL was requested via environment, but active dialect is '{default_db.get_dialect_name()}'"
            )
        try:
            default_db.verify_connection()
            print("[Diagnostic] Verified connection to PostgreSQL service.")
        except Exception as e:
            sys.exit(f"FATAL: Failed to connect to requested PostgreSQL service: {e}")

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(ROOT / "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print("Running Contract & Fixture Invariants Check...")
    print("=" * 60)
    import subprocess
    proc = subprocess.run([
        sys.executable,
        str(ROOT / ".brain/.work/contracts/v1/validate_fixtures.py")
    ])

    if not result.wasSuccessful() or proc.returncode != 0:
        sys.exit(1)
    print("\nALL WORKER 01, WORKER 02 & WORKER 03 TESTS & CONTRACT INVARIANTS PASSED!")


if __name__ == "__main__":
    run()
