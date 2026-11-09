#!/usr/bin/env python3
"""Run all TRUSTTRACE test suites and contract validations."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

def run():
    print("=" * 60)
    print("TRUSTTRACE Test Suite Runner")
    print("=" * 60)
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
    print("\nALL WORKER 01 PHASE 01 TESTS & CONTRACT INVARIANTS PASSED!")

if __name__ == "__main__":
    run()

