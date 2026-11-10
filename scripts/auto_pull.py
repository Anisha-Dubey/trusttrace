#!/usr/bin/env python3
"""
TRUSTTRACE Continuous Auto-Pull & Repository Synchronization Watcher.

Monitors the remote Git repository for new commits pushed by any team member
and automatically pulls and synchronizes local workspace using safe rebase
and autostash to protect in-progress working tree changes.

Usage:
    python scripts/auto_pull.py                # Run continuously (polls every 10s)
    python scripts/auto_pull.py --interval 15  # Custom poll interval (15s)
    python scripts/auto_pull.py --once         # Perform single check and exit
"""

import sys
import os
import time
import argparse
import subprocess
from datetime import datetime
from pathlib import Path


def get_git_root() -> Path:
    res = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    if res.returncode == 0:
        return Path(res.stdout.strip())
    return Path(__file__).resolve().parent.parent


def run_git(args: list[str], cwd: Path) -> tuple[int, str, str]:
    res = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True)
    return res.returncode, res.stdout.strip(), res.stderr.strip()


def check_and_pull(remote: str = "origin", branch: str = "main", cwd: Path = None, verbose: bool = False) -> bool:
    if cwd is None:
        cwd = get_git_root()

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Fetch remote changes silently
    code, _, err = run_git(["fetch", remote, branch, "--quiet"], cwd=cwd)
    if code != 0:
        if verbose:
            print(f"[{now_str}] [AUTO-PULL] ⚠️ Network / git fetch notice: {err}")
        return False

    # 2. Get local HEAD and remote commit SHAs
    code_local, local_sha, _ = run_git(["rev-parse", "HEAD"], cwd=cwd)
    code_remote, remote_sha, _ = run_git(["rev-parse", f"{remote}/{branch}"], cwd=cwd)

    if code_local != 0 or code_remote != 0:
        return False

    if local_sha == remote_sha:
        if verbose:
            print(f"[{now_str}] [AUTO-PULL] Up to date at {local_sha[:7]}.")
        return False

    # 3. Check how many commits remote is ahead of local
    code_count, count_str, _ = run_git(["rev-list", "--count", f"HEAD..{remote}/{branch}"], cwd=cwd)
    incoming_count = int(count_str) if code_count == 0 and count_str.isdigit() else 0

    if incoming_count == 0:
        # Local might be ahead of remote (unpushed local commits); no pull needed
        if verbose:
            print(f"[{now_str}] [AUTO-PULL] Local is ahead of {remote}/{branch}. Nothing to pull.")
        return False

    print(f"\n[{now_str}] [AUTO-PULL] 🔔 Team member pushed {incoming_count} new commit(s) to {remote}/{branch}!")

    # Show summary of incoming commits
    _, log_summary, _ = run_git(["log", "--oneline", f"-{min(incoming_count, 5)}", f"{remote}/{branch}"], cwd=cwd)
    if log_summary:
        for line in log_summary.splitlines():
            print(f"    • {line}")

    # 4. Safely pull with autostash and rebase
    print(f"[{now_str}] [AUTO-PULL] 🔄 Pulling changes (git pull --rebase --autostash {remote} {branch})...")
    pull_code, pull_out, pull_err = run_git(["pull", "--rebase", "--autostash", remote, branch], cwd=cwd)

    if pull_code == 0:
        code_new, new_sha, _ = run_git(["rev-parse", "HEAD"], cwd=cwd)
        print(f"[{now_str}] [AUTO-PULL] ✅ Successfully synchronized! Local HEAD is now {new_sha[:7]}.\n")
        return True
    else:
        print(f"[{now_str}] [AUTO-PULL] ❌ Rebase conflict or error detected:")
        print(pull_err or pull_out)
        print(f"[{now_str}] [AUTO-PULL] 🛡️ Aborting rebase to preserve local modifications...")
        run_git(["rebase", "--abort"], cwd=cwd)
        return False


def main():
    parser = argparse.ArgumentParser(description="TRUSTTRACE Auto-Pull Synchronization Service")
    parser.add_argument("--interval", type=int, default=10, help="Poll interval in seconds (default: 10s)")
    parser.add_argument("--remote", type=str, default="origin", help="Remote name (default: origin)")
    parser.add_argument("--branch", type=str, default="main", help="Branch name (default: main)")
    parser.add_argument("--once", action="store_true", help="Check once and exit")
    parser.add_argument("--verbose", action="store_true", help="Print status even when no new commits")
    args = parser.parse_args()

    git_root = get_git_root()
    print(f"=== TRUSTTRACE Auto-Pull Watcher ===")
    print(f"Root: {git_root}")
    print(f"Target: {args.remote}/{args.branch}")
    print(f"Polling Interval: {args.interval}s")
    print(f"Press Ctrl+C to stop.\n")

    if args.once:
        check_and_pull(remote=args.remote, branch=args.branch, cwd=git_root, verbose=True)
        return 0

    heartbeat_counter = 0
    try:
        while True:
            heartbeat_counter += 1
            # Verbose log every 60 seconds (6 * 10s)
            show_verbose = args.verbose or (heartbeat_counter % max(1, (60 // args.interval)) == 0)
            check_and_pull(remote=args.remote, branch=args.branch, cwd=git_root, verbose=show_verbose)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[AUTO-PULL] Watcher stopped by user.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
