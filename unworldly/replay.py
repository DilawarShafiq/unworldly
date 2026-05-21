"""Session replay, listing, and touched summary for Unworldly."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .display import (
    agent_badge,
    banner,
    format_event,
    replay_header,
    session_summary,
)
from .integrity import verify_session
from .session import load_session
from .types import EventType, RiskLevel, Session


# ── Sparkline ────────────────────────────────────────────────────────────────

_SPARK = "▁▂▃▄▅▆▇█"


def _sparkline(session: Session, buckets: int = 12) -> str:
    if not session.events:
        return " " * buckets
    start = datetime.fromisoformat(session.start_time.replace("Z", "+00:00")).timestamp()
    end_str = session.end_time or session.start_time
    end = datetime.fromisoformat(end_str.replace("Z", "+00:00")).timestamp()
    duration = max(end - start, 1.0)
    counts = [0] * buckets
    for e in session.events:
        t = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")).timestamp()
        idx = min(int((t - start) / duration * buckets), buckets - 1)
        counts[idx] += 1
    peak = max(counts)
    if peak == 0:
        return "▁" * buckets
    return "".join(_SPARK[min(int(c / peak * 7), 7)] if c > 0 else " " for c in counts)


# ── Since parser ─────────────────────────────────────────────────────────────

def _parse_since(since: str) -> datetime | None:
    m = re.match(r"^(\d+)([mhd])$", since.strip().lower())
    if not m:
        return None
    v, u = int(m.group(1)), m.group(2)
    delta = {"m": timedelta(minutes=v), "h": timedelta(hours=v), "d": timedelta(days=v)}[u]
    return datetime.now(timezone.utc) - delta


# ── Replay ───────────────────────────────────────────────────────────────────

def _format_time(iso_string: str) -> str:
    dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
    return dt.strftime("%H:%M:%S")


def replay(session_path: str, speed: float = 1.0) -> None:
    """Replay a recorded session in the terminal with timing."""
    session = load_session(session_path)

    print(banner())
    print(replay_header(session.id, session.directory, session.start_time))
    if session.agent:
        print(agent_badge(session.agent))

    integrity = verify_session(session)
    if not integrity.valid:
        red_bold = "\033[1;31m"
        reset = "\033[0m"
        print(f"{red_bold}  ⚠ WARNING: Session integrity check failed — events may have been tampered with{reset}\n")

    if not session.events:
        gray = "\033[90m"
        reset = "\033[0m"
        print(f"{gray}  No events recorded in this session.{reset}")
        return

    for i, event in enumerate(session.events):
        if i > 0:
            prev_t = datetime.fromisoformat(session.events[i - 1].timestamp.replace("Z", "+00:00")).timestamp()
            curr_t = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00")).timestamp()
            delay = min((curr_t - prev_t) / speed, 2.0)
            if delay > 0:
                time.sleep(delay)
        print(format_event(_format_time(event.timestamp), event.type, event.path, event.risk, event.reason))

    print(session_summary(session.summary, session_path))


# ── List ─────────────────────────────────────────────────────────────────────

def list_command(
    base_dir: str,
    risk: str | None = None,
    agent: str | None = None,
    since: str | None = None,
    tag: str | None = None,
) -> None:
    """List all recorded sessions with optional filters."""
    sessions_dir = os.path.join(base_dir, ".unworldly/sessions")

    gray = "\033[90m"
    white_bold = "\033[1;37m"
    cyan = "\033[36m"
    green = "\033[32m"
    yellow = "\033[33m"
    red = "\033[31m"
    magenta = "\033[35m"
    reset = "\033[0m"

    if not os.path.exists(sessions_dir):
        print(f"{gray}  No sessions found. Run `unworldly watch` first.{reset}")
        return

    files = sorted([f for f in os.listdir(sessions_dir) if f.endswith(".json")], reverse=True)
    if not files:
        print(f"{gray}  No sessions found. Run `unworldly watch` first.{reset}")
        return

    since_dt = _parse_since(since) if since else None

    sessions: list[tuple[str, Session]] = []
    for filename in files:
        filepath = os.path.join(sessions_dir, filename)
        with open(filepath, encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)
        session = Session.from_dict(data)

        # --- filters ---
        if risk:
            max_risk = (
                "danger" if session.summary.danger > 0
                else "caution" if session.summary.caution > 0
                else "safe"
            )
            if max_risk != risk:
                continue
        if agent and session.agent and agent.lower() not in session.agent.name.lower():
            continue
        if agent and not session.agent:
            continue
        if since_dt:
            session_dt = datetime.fromisoformat(session.start_time.replace("Z", "+00:00"))
            if session_dt < since_dt:
                continue
        if tag and session.tag != tag:
            continue

        sessions.append((filepath, session))

    print(banner())
    filter_parts = []
    if risk:
        filter_parts.append(f"risk={risk}")
    if agent:
        filter_parts.append(f"agent={agent}")
    if since:
        filter_parts.append(f"since={since}")
    if tag:
        filter_parts.append(f"tag={tag}")
    filter_str = f"  {gray}(filtered: {', '.join(filter_parts)}){reset}" if filter_parts else ""
    print(f"{white_bold}  Recorded Sessions{reset}{filter_str}\n")

    if not sessions:
        print(f"{gray}  No sessions match the given filters.{reset}\n")
        return

    for filepath, session in sessions:
        if session.summary.risk_score >= 7:
            risk_color = red
        elif session.summary.risk_score >= 4:
            risk_color = yellow
        else:
            risk_color = green

        dt = datetime.fromisoformat(session.start_time.replace("Z", "+00:00"))
        date_str = dt.strftime("%b %d %H:%M")
        spark = _sparkline(session)
        agent_tag = f"{cyan} [{session.agent.name}]{reset}" if session.agent else ""
        integrity_tag = f"{green} ✓{reset}" if session.integrity_hash else f"{gray} ○{reset}"
        tag_badge = f"{magenta} #{session.tag}{reset}" if session.tag else ""

        print(
            f"  {white_bold}{session.id}{reset}"
            f"  {gray}{date_str}{reset}"
            f"  {gray}{spark}{reset}"
            f"  {gray}{session.summary.total_events:3d} events{reset}"
            f"  Risk: {risk_color}{session.summary.risk_score}/10{reset}"
            f"{integrity_tag}{agent_tag}{tag_badge}"
        )

    print("")


# ── Touched ──────────────────────────────────────────────────────────────────

def touched_command(session_path: str) -> None:
    """Show a per-file summary of what an agent touched in a session."""
    session = load_session(session_path)

    red = "\033[31m"
    red_bold = "\033[1;31m"
    yellow = "\033[33m"
    green = "\033[32m"
    gray = "\033[90m"
    white_bold = "\033[1;37m"
    cyan = "\033[36m"
    reset = "\033[0m"

    # Group file events by path (exclude pure command events)
    files: dict[str, list[Any]] = {}
    for event in session.events:
        if event.type == EventType.COMMAND:
            continue
        if event.path not in files:
            files[event.path] = []
        files[event.path].append(event)

    # Risk order for sorting
    _risk_order = {RiskLevel.DANGER: 2, RiskLevel.CAUTION: 1, RiskLevel.SAFE: 0}

    def _sort_key(item: tuple[str, list[Any]]) -> tuple[int, int]:
        evts = item[1]
        max_r = max(_risk_order[e.risk] for e in evts)
        return (-max_r, -len(evts))

    sorted_files = sorted(files.items(), key=_sort_key)

    agent_name = session.agent.name if session.agent else "Unknown Agent"

    print(banner())
    print(f"  {white_bold}Files Touched{reset}  {cyan}{agent_name}{reset}  {gray}Session {session.id}{reset}\n")
    print(f"  {gray}{'─' * 66}{reset}")

    danger_count = 0
    caution_count = 0

    for path, evts in sorted_files:
        max_risk = max(evts, key=lambda e: _risk_order[e.risk]).risk
        touch_count = len(evts)
        types_used = sorted({e.type.value for e in evts})
        type_str = "/".join(t.upper() for t in types_used)
        reasons = list({e.reason for e in evts if e.reason and e.risk != RiskLevel.SAFE})

        if max_risk == RiskLevel.DANGER:
            icon = f"{red_bold}🚨{reset}"
            path_str = f"{red_bold}{path}{reset}"
            danger_count += 1
        elif max_risk == RiskLevel.CAUTION:
            icon = f"{yellow}⚠️ {reset}"
            path_str = f"{yellow}{path}{reset}"
            caution_count += 1
        else:
            icon = f"{green}✅{reset}"
            path_str = f"{gray}{path}{reset}"

        count_str = f"{gray}×{touch_count}{reset}" if touch_count > 1 else ""
        reason_str = f"  {gray}— {', '.join(reasons[:2])}{reset}" if reasons else ""

        print(f"  {icon}  {path_str}  {gray}{type_str}{reset} {count_str}{reason_str}")

    safe_count = len(sorted_files) - danger_count - caution_count
    print(f"\n  {gray}{'─' * 66}{reset}")
    print(
        f"  {white_bold}{len(sorted_files)} files{reset}"
        f"  {red}🚨 {danger_count} danger{reset}"
        f"  {yellow}⚠️  {caution_count} caution{reset}"
        f"  {green}✅ {safe_count} safe{reset}"
        f"  Risk: {white_bold}{session.summary.risk_score}/10{reset}\n"
    )
