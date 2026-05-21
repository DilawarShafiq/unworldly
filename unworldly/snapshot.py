"""Git-aware snapshot for Unworldly.

Records the git state of a directory before and after an agent run,
then diffs to show exactly what the agent changed at the git level.
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone


_SNAPSHOT_DIR = ".unworldly"
_BEFORE_FILE = "snapshot-before.json"
_AFTER_FILE = "snapshot-after.json"


def _run(cmd: list[str], cwd: str) -> str:
    """Run a command and return stdout, empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=10)
        return result.stdout.strip()
    except Exception:
        return ""


def _git_state(directory: str) -> dict:  # type: ignore[type-arg]
    """Capture current git state of a directory."""
    abs_dir = os.path.abspath(directory)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "directory": abs_dir,
        "commit": _run(["git", "rev-parse", "HEAD"], abs_dir),
        "branch": _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], abs_dir),
        "status": _run(["git", "status", "--porcelain"], abs_dir),
        "diff_stat": _run(["git", "diff", "--stat"], abs_dir),
        "staged_stat": _run(["git", "diff", "--cached", "--stat"], abs_dir),
        "untracked": _run(["git", "ls-files", "--others", "--exclude-standard"], abs_dir),
    }


def _snapshot_path(directory: str, filename: str) -> str:
    abs_dir = os.path.abspath(directory)
    snap_dir = os.path.join(abs_dir, _SNAPSHOT_DIR)
    os.makedirs(snap_dir, exist_ok=True)
    return os.path.join(snap_dir, filename)


def snapshot_before(directory: str) -> None:
    """Record git state before an agent run."""
    state = _git_state(directory)
    path = _snapshot_path(directory, _BEFORE_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

    green = "\033[32m"
    gray = "\033[90m"
    white_bold = "\033[1;37m"
    reset = "\033[0m"

    print(f"\n  {green}✓ Snapshot recorded{reset}  (before agent run)")
    print(f"  {white_bold}Branch:{reset} {gray}{state['branch']}{reset}")
    print(f"  {white_bold}Commit:{reset} {gray}{state['commit'][:12] or 'none'}{reset}")
    print(f"  {gray}Run your agent now, then: unworldly snapshot after{reset}\n")


def snapshot_after(directory: str) -> None:
    """Record git state after an agent run and diff against before."""
    before_path = _snapshot_path(directory, _BEFORE_FILE)
    if not os.path.exists(before_path):
        red = "\033[31m"
        reset = "\033[0m"
        print(f"\n  {red}✗ No 'before' snapshot found.{reset}")
        print("  Run `unworldly snapshot before` before starting your agent.\n")
        return

    with open(before_path, encoding="utf-8") as f:
        before = json.load(f)

    after = _git_state(directory)
    path = _snapshot_path(directory, _AFTER_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(after, f, indent=2)

    _print_diff(before, after, directory)


def _print_diff(before: dict, after: dict, directory: str) -> None:  # type: ignore[type-arg]
    red_bold = "\033[1;31m"
    yellow = "\033[33m"
    green_bold = "\033[1;32m"
    gray = "\033[90m"
    white_bold = "\033[1;37m"
    reset = "\033[0m"

    abs_dir = os.path.abspath(directory)

    print(f"\n  {white_bold}Agent Run Snapshot Diff{reset}\n")
    print(f"  {white_bold}Branch:{reset} {gray}{before['branch']} → {after['branch']}{reset}")

    before_commit = before["commit"][:12] or "none"
    after_commit = after["commit"][:12] or "none"
    commit_changed = before["commit"] != after["commit"]
    commit_color = yellow if commit_changed else gray
    print(f"  {white_bold}Commit:{reset} {commit_color}{before_commit} → {after_commit}{reset}")

    # New commits
    if commit_changed and before["commit"]:
        new_commits = _run(
            ["git", "log", f"{before['commit']}..HEAD", "--oneline"],
            abs_dir,
        )
        if new_commits:
            print(f"\n  {white_bold}New Commits:{reset}")
            for line in new_commits.splitlines():
                print(f"    {green_bold}+{reset} {line}")

    # Status changes
    before_files = set(before["status"].splitlines()) if before["status"] else set()
    after_files = set(after["status"].splitlines()) if after["status"] else set()
    new_changes = after_files - before_files
    resolved = before_files - after_files

    if new_changes:
        print(f"\n  {white_bold}New Changes (agent added):{reset}")
        for line in sorted(new_changes):
            flag = line[:2].strip()
            fpath = line[3:].strip()
            color = red_bold if flag in ("D", "!!") else yellow if flag in ("M", "MM") else green_bold
            print(f"    {color}{flag or '?'}{reset}  {fpath}")

    if resolved:
        print(f"\n  {white_bold}Resolved Changes (agent cleaned):{reset}")
        for line in sorted(resolved):
            print(f"    {gray}{line}{reset}")

    # Diff stat
    if after["diff_stat"]:
        print(f"\n  {white_bold}Diff Stat (unstaged):{reset}")
        for line in after["diff_stat"].splitlines():
            print(f"    {gray}{line}{reset}")

    # Untracked
    new_untracked = set(after["untracked"].splitlines()) - set(before["untracked"].splitlines())
    if new_untracked:
        print(f"\n  {white_bold}New Untracked Files:{reset}")
        for f in sorted(new_untracked):
            print(f"    {green_bold}+{reset} {f}")

    print(f"\n  {gray}Full git diff: git diff {before['commit'][:12]}..HEAD{reset}\n")
