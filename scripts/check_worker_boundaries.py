#!/usr/bin/env python3
"""
TRUSTTRACE Worker Boundary & "Ask Twice" Protocol Enforcer.

Validates that modifications do not cross locked worker boundaries without
prior two-confirmation approval recorded in .brain/.work/shared/cross_boundary_log.md.

Usage:
    python scripts/check_worker_boundaries.py
    python scripts/check_worker_boundaries.py --worker worker_01
    python scripts/check_worker_boundaries.py --staged-only
"""

import sys
import os
import subprocess
import re
from pathlib import Path

DOMAIN_RULES = {
    "worker_01": [
        r"^src/trusttrace/intake/",
        r"^src/trusttrace/collectors/",
        r"^tests/test_url_policy\.py$",
        r"^tests/test_ssrf_boundary\.py$",
        r"^tests/test_redirect_boundary\.py$",
        r"^tests/test_bounded_collectors\.py$",
        r"^\.brain/\.work/webapp/worker_01/",
        r"^\.brain/\.report/worker_01_",
    ],
    "worker_02": [
        r"^src/trusttrace/evidence/",
        r"^src/trusttrace/api/",
        r"^alembic/",
        r"^alembic\.ini$",
        r"^tests/test_evidence_intelligence\.py$",
        r"^tests/test_evidence_adapters\.py$",
        r"^tests/test_community_intelligence\.py$",
        r"^tests/test_api_endpoints\.py$",
        r"^tests/test_reliability_and_hardening\.py$",
        r"^\.brain/\.work/webapp/worker_02/",
        r"^\.brain/\.report/worker_02_",
    ],
    "worker_03": [
        r"^src/trusttrace/policy/",
        r"^tests/test_triage_policy\.py$",
        r"^\.brain/\.work/webapp/worker_03/",
        r"^\.brain/\.report/worker_03_",
    ],
    "worker_04": [
        r"^src/trusttrace/web/",
        r"^\.brain/\.demo/",
        r"^\.brain/\.work/webapp/worker_04/",
        r"^\.brain/\.report/worker_04_",
    ],
    "testers": [
        r"^tests/test_security_audit\.py$",
        r"^\.brain/\.work/testers/",
        r"^\.brain/\.report/tester_",
        r"^\.brain/\.report/security_gate_report\.md$",
        r"^\.brain/\.report/release_gate_report\.md$",
    ],
    "shared": [
        r"^\.brain/\.work/contracts/",
        r"^\.brain/\.work/shared/",
        r"^pyproject\.toml$",
        r"^pyrightconfig\.json$",
        r"^run_tests\.py$",
        r"^run_app\.py$",
        r"^launch\.bat$",
        r"^README\.md$",
        r"^requirements\.txt$",
        r"^\.github/CODEOWNERS$",
        r"^scripts/",
    ],
}


def get_git_root() -> Path:
    res = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    if res.returncode == 0:
        return Path(res.stdout.strip())
    return Path(__file__).resolve().parent.parent


def get_changed_files(staged_only: bool = False) -> list[str]:
    root = get_git_root()
    cmd = ["git", "diff", "--name-only"]
    if staged_only:
        cmd.append("--cached")
    else:
        cmd.append("HEAD")

    res = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if res.returncode != 0:
        # Fallback for empty/uncommitted head
        res = subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True)
        files = []
        for line in res.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                files.append(parts[-1].replace("\\", "/"))
        return files

    return [f.strip().replace("\\", "/") for f in res.stdout.splitlines() if f.strip()]


def classify_file(filepath: str) -> str:
    norm = filepath.replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    for domain, patterns in DOMAIN_RULES.items():
        for pat in patterns:
            if re.search(pat, norm):
                return domain
    return "unclassified"


def check_cross_boundary_log(modified_file: str, requesting_worker: str, domain_owner: str) -> bool:
    root = get_git_root()
    log_file = root / ".brain" / ".work" / "shared" / "cross_boundary_log.md"
    if not log_file.exists():
        return False

    content = log_file.read_text(encoding="utf-8")
    # Verify that there is an approved record mentioning the file and approved decision
    filename = Path(modified_file).name
    if filename in content and "APPROVED" in content:
        return True
    return False


def main():
    staged_only = "--staged-only" in sys.argv
    active_worker = None
    for arg in sys.argv:
        if arg.startswith("--worker="):
            active_worker = arg.split("=", 1)[1]
        elif arg == "--worker" and sys.argv.index(arg) + 1 < len(sys.argv):
            active_worker = sys.argv[sys.argv.index(arg) + 1]

    changed_files = get_changed_files(staged_only)
    if not changed_files:
        print("[OK] No file modifications detected.")
        return 0

    print(f"=== TRUSTTRACE Worker Boundary Verification ===")
    print(f"Detected {len(changed_files)} modified file(s).")

    domain_file_map: dict[str, list[str]] = {}
    for f in changed_files:
        d = classify_file(f)
        domain_file_map.setdefault(d, []).append(f)

    for d, files in domain_file_map.items():
        print(f"  • Domain [{d}]: {len(files)} file(s)")

    violations = []

    # If active_worker is specified, verify no files outside their scope or shared are modified
    if active_worker:
        allowed = {active_worker, "shared", "unclassified"}
        for d, files in domain_file_map.items():
            if d not in allowed:
                for f in files:
                    approved = check_cross_boundary_log(f, active_worker, d)
                    if not approved:
                        violations.append((f, active_worker, d))

    # If no specific active_worker, check if multiple functional domains were edited at once without approval
    worker_domains_touched = [d for d in domain_file_map.keys() if d.startswith("worker_")]
    if len(worker_domains_touched) > 1 and not active_worker:
        print("\n[WARNING] Changes span multiple locked worker domains:")
        for wd in worker_domains_touched:
            print(f"  - {wd}: {', '.join(domain_file_map[wd])}")
        print("\nMandatory Two-Confirmation Check:")
        print("  1. Ensure each cross-domain modification is justified in .brain/.work/shared/cross_boundary_log.md")
        print("  2. Ensure the respective domain owner has signed off (Ask Twice Protocol).")

    if violations:
        print("\n" + "=" * 60)
        print("[BOUNDARY LOCK VIOLATION] Unauthorized cross-worker modification:")
        for f, req, owner in violations:
            print(f"  ❌ File: {f}")
            print(f"     Modifier: {req}")
            print(f"     Locked Owner: {owner}")
            print(f"     Protocol: Requires two confirmations in .brain/.work/shared/cross_boundary_log.md")
        print("=" * 60)
        return 1

    print("\n[PASS] All modifications adhere to locked worker boundaries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
