"""Session replay and listing for Unworldly.

Replays recorded sessions with timing and color-coded display,
and lists all available sessions.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime

from .types import EventType, RiskLevel, Session
from .session import load_session
from .integrity import verify_session
from .display import (
    banner,
    format_event,
    replay_header,
    session_summary,
    agent_badge,
    verify_display,
)


def _format_time(iso_string: str) -> str:
    """Format an ISO timestamp as HH:MM:SS."""
    dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
    return dt.strftime("%H:%M:%S")


def replay(
    session_path: str,
    speed: float = 1.0,
) -> None:
    """Replay a recorded session in the terminal with timing.

    Args:
        session_path: Path to the session file or session ID.
        speed: Playback speed multiplier (higher = faster).
    """
    session = load_session(session_path)

    print(banner())
    print(replay_header(session.id, session.directory, session.start_time))
    if session.agent:
        print(agent_badge(session.agent))

    # Show integrity status before replaying
    integrity = verify_session(session)
    if not integrity.valid:
        red_bold = "\033[1;31m"
        reset = "\033[0m"
        print(
            f"{red_bold}  ⚠ WARNING: Session integrity check failed "
            f"— events may have been tampered with{reset}"
        )
        print("")

    if not session.events:
        gray = "\033[90m"
        reset = "\033[0m"
        print(f"{gray}  No events recorded in this session.{reset}")
        return

    for i, event in enumerate(session.events):
        # Calculate delay between events
        if i > 0:
            prev_time = datetime.fromisoformat(
                session.events[i - 1].timestamp.replace("Z", "+00:00")
            ).timestamp()
            curr_time = datetime.fromisoformat(
                event.timestamp.replace("Z", "+00:00")
            ).timestamp()
            delay = min((curr_time - prev_time) / speed, 2.0)  # Cap at 2s
            if delay > 0:
                time.sleep(delay)

        print(format_event(
            _format_time(event.timestamp),
            event.type,
            event.path,
            event.risk,
            event.reason,
        ))

    print(session_summary(session.summary, session_path))


def list_command(base_dir: str) -> None:
    """List all recorded sessions."""
    sessions_dir = os.path.join(base_dir, ".unworldly/sessions")
    gray = "\033[90m"
    white_bold = "\033[1;37m"
    cyan = "\033[36m"
    green = "\033[32m"
    yellow = "\033[33m"
    red = "\033[31m"
    reset = "\033[0m"

    if not os.path.exists(sessions_dir):
        print(f"{gray}  No sessions found. Run `unworldly watch` first.{reset}")
        return

    files = [f for f in os.listdir(sessions_dir) if f.endswith(".json")]
    files.sort(reverse=True)

    if not files:
        print(f"{gray}  No sessions found. Run `unworldly watch` first.{reset}")
        return

    print(banner())
    print(f"{white_bold}  Recorded Sessions\n{reset}")

    for filename in files:
        filepath = os.path.join(sessions_dir, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        from .types import Session as SessionType
        session = SessionType.from_dict(data)

        if session.summary.risk_score >= 7:
            risk_color = red
        elif session.summary.risk_score >= 4:
            risk_color = yellow
        else:
            risk_color = green

        dt = datetime.fromisoformat(session.start_time.replace("Z", "+00:00"))
        date_str = dt.strftime("%b %d, %Y %I:%M %p")

        agent_tag = f"{cyan} [{session.agent.name}]{reset}" if session.agent else ""
        integrity_tag = (
            f"{green} ✓{reset}" if session.integrity_hash
            else f"{gray} ○{reset}"
        )

        print(
            f"  {white_bold}{session.id}{reset}"
            f"  {gray}{date_str}{reset}"
            f"  {gray}{session.summary.total_events} events{reset}"
            f"  Risk: {risk_color}{session.summary.risk_score}/10{reset}"
            f"{integrity_tag}"
            f"{agent_tag}"
        )

    print("")
