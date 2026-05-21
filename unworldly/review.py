"""Interactive session review TUI for Unworldly.

Like `git add -p` but for AI agent sessions.
Navigate events and mark each as approved, flagged, or skipped.
Saves a review JSON you can attach to your PR.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from .display import banner, format_event
from .session import load_session
from .types import EventType, RiskLevel, WatchEvent


# ── Cross-platform single-char read ──────────────────────────────────────────

def _getch() -> str:
    """Read one keypress without waiting for Enter."""
    if sys.platform == "win32":
        import msvcrt
        ch = msvcrt.getch()
        return ch.decode("utf-8", errors="replace")
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            return sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


# ── Review logic ─────────────────────────────────────────────────────────────

def _format_time(iso_string: str) -> str:
    dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
    return dt.strftime("%H:%M:%S")


def review_command(
    session_path: str,
    output: str | None = None,
    show_all: bool = False,
) -> None:
    """Interactively review session events with keypress decisions."""
    session = load_session(session_path)

    red_bold = "\033[1;31m"
    yellow = "\033[33m"
    green_bold = "\033[1;32m"
    gray = "\033[90m"
    white_bold = "\033[1;37m"
    cyan = "\033[36m"
    reset = "\033[0m"

    # Filter events to review
    if show_all:
        to_review = session.events
    else:
        to_review = [e for e in session.events if e.risk in (RiskLevel.DANGER, RiskLevel.CAUTION)]

    if not to_review:
        print(f"\n  {green_bold}✓ Nothing to review{reset} — no danger or caution events.\n")
        return

    print(banner())
    agent_name = session.agent.name if session.agent else "Unknown Agent"
    print(
        f"  {white_bold}Interactive Review{reset}  {cyan}{agent_name}{reset}"
        f"  {gray}Session {session.id}{reset}\n"
    )
    print(
        f"  {gray}Reviewing {len(to_review)} event(s)."
        f"  Keys: {reset}"
        f"{green_bold}(a)pprove{reset}  "
        f"{red_bold}(f)lag{reset}  "
        f"{gray}(s)kip{reset}  "
        f"{yellow}(n)ote{reset}  "
        f"{gray}(q)uit{reset}\n"
    )
    print(f"  {gray}{'─' * 66}{reset}\n")

    decisions: list[dict[str, Any]] = []
    reviewed = 0

    for i, event in enumerate(to_review):
        idx = f"{i + 1}/{len(to_review)}"

        # Print event
        time_str = _format_time(event.timestamp)
        print(f"  {gray}[{idx}]{reset}  {format_event(time_str, event.type, event.path, event.risk, event.reason)}")
        print(f"\n  {gray}Decision > {reset}", end="", flush=True)

        while True:
            key = _getch().lower()
            if key == "a":
                decision = "approved"
                color = green_bold
                label = "✓ Approved"
                break
            elif key == "f":
                decision = "flagged"
                color = red_bold
                label = "✗ Flagged"
                break
            elif key == "s":
                decision = "skipped"
                color = gray
                label = "→ Skipped"
                break
            elif key == "n":
                print(f"\n  {yellow}Note: {reset}", end="", flush=True)
                # Switch back to line mode for note input
                if sys.platform != "win32":
                    import termios
                    fd = sys.stdin.fileno()
                    old = termios.tcgetattr(fd)
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
                note = input()
                decisions.append({
                    "event_index": session.events.index(event),
                    "timestamp": event.timestamp,
                    "path": event.path,
                    "risk": event.risk.value,
                    "type": event.type.value,
                    "decision": "noted",
                    "note": note,
                })
                reviewed += 1
                print(f"  {yellow}→ Noted{reset}\n")
                print(f"  {gray}{'─' * 66}{reset}\n")
                continue
            elif key in ("q", "\x03", "\x1b"):  # q, Ctrl-C, Esc
                print(f"\n\n  {gray}Review aborted at [{idx}]{reset}\n")
                break
            # ignore unknown keys
            continue
        else:
            # inner while completed without break (note path hits continue)
            pass

        if key in ("q", "\x03", "\x1b"):
            break

        print(f"{color}{label}{reset}\n")
        decisions.append({
            "event_index": session.events.index(event),
            "timestamp": event.timestamp,
            "path": event.path,
            "risk": event.risk.value,
            "type": event.type.value,
            "decision": decision,
        })
        reviewed += 1
        print(f"  {gray}{'─' * 66}{reset}\n")

    # ── Summary ───────────────────────────────────────────────────────────────
    approved = sum(1 for d in decisions if d["decision"] == "approved")
    flagged  = sum(1 for d in decisions if d["decision"] == "flagged")
    skipped  = sum(1 for d in decisions if d["decision"] == "skipped")
    noted    = sum(1 for d in decisions if d["decision"] == "noted")

    print(
        f"  {white_bold}Review complete{reset}  "
        f"{green_bold}✓ {approved} approved{reset}  "
        f"{red_bold}✗ {flagged} flagged{reset}  "
        f"{gray}→ {skipped} skipped{reset}  "
        f"{yellow}✎ {noted} noted{reset}\n"
    )

    # ── Save review JSON ──────────────────────────────────────────────────────
    if not decisions:
        return

    review_data: dict[str, Any] = {
        "session_id": session.id,
        "agent": session.agent.name if session.agent else None,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "reviewer": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        "summary": {
            "total_reviewed": reviewed,
            "approved": approved,
            "flagged": flagged,
            "skipped": skipped,
            "noted": noted,
        },
        "decisions": decisions,
    }

    out_path = output or f".unworldly/review-{session.id}.json"
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(review_data, f, indent=2)

    print(f"  {green_bold}Review saved:{reset} {gray}{out_path}{reset}")
    if flagged:
        print(f"  {red_bold}⚠ {flagged} flagged event(s) need attention before merging.{reset}")
    print()
