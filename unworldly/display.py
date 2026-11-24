"""Terminal display formatting for Unworldly.

Uses `rich` for color-coded terminal output with risk badges,
event formatting, and session summaries.
"""

from __future__ import annotations

from ._version import __version__
from .integrity import VerifyResult
from .types import AgentInfo, EventType, RiskLevel, SessionSummary, WatchEvent


def _risk_badge(level: RiskLevel) -> str:
    """Get a colored risk badge string."""
    if level == RiskLevel.SAFE:
        return "\033[32m  safe  \033[0m"
    elif level == RiskLevel.CAUTION:
        return "\033[33m caution\033[0m"
    else:
        return "\033[1;31m DANGER \033[0m"


def _event_icon(event_type: EventType) -> str:
    """Get a colored event type indicator."""
    if event_type == EventType.CREATE:
        return "\033[32mCREATE \033[0m"
    elif event_type == EventType.MODIFY:
        return "\033[34mMODIFY \033[0m"
    elif event_type == EventType.DELETE:
        return "\033[31mDELETE \033[0m"
    else:
        return "\033[35m$> CMD \033[0m"


def banner() -> str:
    """Generate the Unworldly banner."""
    red_bold = "\033[1;31m"
    white_bold = "\033[1;37m"
    gray = "\033[90m"
    reset = "\033[0m"

    # Compute padding from the border width so the box stays aligned for any
    # version length (single source of truth: unworldly._version).
    inner = 51
    title_plain = f"  UNWORLDLY v{__version__}"
    subtitle_plain = "  The Flight Recorder for AI Agents"
    title_pad = " " * max(0, inner - len(title_plain))
    subtitle_pad = " " * max(0, inner - len(subtitle_plain))

    lines = [
        "",
        f"{red_bold}  ╔{'═' * inner}╗{reset}",
        f"{red_bold}  ║{reset}{white_bold}  UNWORLDLY{reset}{gray} v{__version__}{reset}{title_pad}{red_bold}║{reset}",
        f"{red_bold}  ║{reset}{gray}{subtitle_plain}{reset}{subtitle_pad}{red_bold}║{reset}",
        f"{red_bold}  ╚{'═' * inner}╝{reset}",
        "",
    ]
    return "\n".join(lines)


def watch_header(directory: str) -> str:
    """Generate the watch mode header."""
    red = "\033[31m"
    white_bold = "\033[1;37m"
    gray = "\033[90m"
    reset = "\033[0m"

    return "\n".join(
        [
            f"{red}  ●{reset}{white_bold} REC{reset}{gray} — Watching: {directory}{reset}",
            f"{gray}  Press Ctrl+C to stop recording{reset}",
            f"{gray}  {'─' * 56}{reset}",
            "",
        ]
    )


def format_event(
    timestamp: str,
    event_type: EventType,
    file_path: str,
    risk: RiskLevel,
    reason: str | None = None,
) -> str:
    """Format a single event for terminal display."""
    gray = "\033[90m"
    red_bold = "\033[1;31m"
    yellow = "\033[33m"
    white = "\033[37m"
    reset = "\033[0m"

    time_str = f"{gray}{timestamp}{reset}"
    event_str = _event_icon(event_type)
    risk_str = _risk_badge(risk)

    if risk == RiskLevel.DANGER:
        file_str = f"{red_bold}{file_path}{reset}"
    elif risk == RiskLevel.CAUTION:
        file_str = f"{yellow}{file_path}{reset}"
    else:
        file_str = f"{white}{file_path}{reset}"

    line = f"  {time_str}  {event_str}  {file_str}  {risk_str}"

    if reason:
        if risk == RiskLevel.DANGER:
            reason_line = f"{red_bold}  ┗━ {reason}!{reset}"
        else:
            reason_line = f"{yellow}  ┗━ {reason}{reset}"
        line += "\n" + reason_line

    return line


def session_summary(summary: SessionSummary, session_path: str) -> str:
    """Format a session summary for terminal display."""
    gray = "\033[90m"
    white_bold = "\033[1;37m"
    green = "\033[32m"
    yellow = "\033[33m"
    red = "\033[31m"
    reset = "\033[0m"

    if summary.risk_score >= 7:
        score_color = "\033[1;31m"
    elif summary.risk_score >= 4:
        score_color = "\033[1;33m"
    else:
        score_color = "\033[1;32m"

    return "\n".join(
        [
            "",
            f"{gray}  {'─' * 56}{reset}",
            f"{white_bold}  Session Summary{reset}",
            "",
            (
                f"  Events: {white_bold}{summary.total_events}{reset}"
                f"  {green}●{reset} Safe: {summary.safe}"
                f"  {yellow}●{reset} Caution: {summary.caution}"
                f"  {red}●{reset} Danger: {summary.danger}"
            ),
            "",
            f"  Risk Score: {score_color}{summary.risk_score}/10{reset}",
            "",
            f"{gray}  Session saved: {session_path}{reset}",
            "",
        ]
    )


def replay_header(session_id: str, directory: str, start_time: str) -> str:
    """Format the replay mode header."""
    blue_bold = "\033[1;34m"
    gray = "\033[90m"
    reset = "\033[0m"

    return "\n".join(
        [
            f"{blue_bold}  ▶ REPLAY{reset}{gray} — Session: {session_id}{reset}",
            f"{gray}  Directory: {directory}{reset}",
            f"{gray}  Recorded: {start_time}{reset}",
            f"{gray}  {'─' * 56}{reset}",
            "",
        ]
    )


def report_divider() -> str:
    """Return a horizontal divider line."""
    gray = "\033[90m"
    reset = "\033[0m"
    return f"{gray}{'─' * 56}{reset}"


def agent_badge(agent: AgentInfo) -> str:
    """Format an agent detection badge."""
    cyan = "\033[36m"
    white_bold = "\033[1;37m"
    gray = "\033[90m"
    reset = "\033[0m"

    lines = [
        f"{cyan}  ◉ Agent Detected: {reset}{white_bold}{agent.name}{reset}",
        f"{gray}    via {agent.detected_via}{reset}",
    ]
    details = [f"model {agent.model}" if agent.model else "", f"version {agent.version}" if agent.version else ""]
    if any(details):
        lines.append(f"{gray}    {' · '.join(d for d in details if d)}{reset}")
    lines.append("")
    return "\n".join(lines)


def diff_stats(diff: str) -> tuple[int, int]:
    """(+added, -removed) line counts of a unified diff, ignoring the file headers."""
    added = sum(1 for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---"))
    return added, removed


def event_details(event: WatchEvent) -> list[str]:
    """Extra replay lines for an event: who ran a command, and a diff summary."""
    gray = "\033[90m"
    green = "\033[32m"
    red = "\033[31m"
    reset = "\033[0m"
    out: list[str] = []
    cmd = event.command
    if cmd is not None and cmd.actor == "other":
        via = f" (started by {cmd.parents[0]})" if cmd.parents else ""
        out.append(f"{gray}     ┗━ not run by the agent{via}{reset}")
    if event.diff:
        added, removed = diff_stats(event.diff)
        out.append(f"{gray}     ┗━ {green}+{added}{reset} {red}-{removed}{reset}{gray} lines{reset}")
    return out


def verify_display(result: VerifyResult) -> str:
    """Format integrity verification results."""
    white_bold = "\033[1;37m"
    gray = "\033[90m"
    green = "\033[32m"
    green_bold = "\033[1;32m"
    red = "\033[31m"
    red_bold = "\033[1;31m"
    white = "\033[37m"
    reset = "\033[0m"

    lines: list[str] = [
        "",
        f"{white_bold}  Integrity Verification{reset}",
        f"{gray}  {'─' * 56}{reset}",
        "",
    ]

    yellow = "\033[33m"
    yellow_bold = "\033[1;33m"
    if result.valid:
        if result.status == "VERIFIED":
            lines.append(f"{green_bold}  ✓ SESSION VERIFIED — signed and complete{reset}")
        elif result.status == "VERIFIED_WITH_GAPS":
            lines.append(f"{yellow_bold}  ✓ SESSION VERIFIED WITH GAPS — no tampering, but see below{reset}")
        else:
            lines.append(f"{green_bold}  ✓ SESSION INTEGRITY VERIFIED (legacy, unsigned){reset}")
        lines.append(f"{green}    All {result.total_events} events have a valid hash chain{reset}")
        if result.signed:
            lines.append(f"{green}    Every record's forward-secure signature is valid{reset}")
        else:
            lines.append(
                f"{yellow}    Unsigned session: tamper-evident only — an editor who recomputes every hash "
                f"could pass this check{reset}"
            )
        if result.abnormal_end:
            lines.append(
                f"{yellow}    • No clean end: still recording, or the recorder was stopped abruptly "
                f"(nothing after that point was recorded){reset}"
            )
        for gap in result.gaps:
            lines.append(f"{yellow}    • {gap}{reset}")
    else:
        lines.append(f"{red_bold}  ✗ TAMPERED — INTEGRITY VERIFICATION FAILED{reset}")
        lines.append("")
        lines.append(f"  Events verified: {white}{result.valid_events}/{result.total_events}{reset}")
        if result.broken_at is not None:
            lines.append(f"{red}  Chain broken at event: #{result.broken_at}{reset}")
        session_hash_str = f"{green}✓ valid{reset}" if result.session_hash_valid else f"{red}✗ invalid{reset}"
        lines.append(f"  Session hash: {session_hash_str}")
        lines.append("")
        lines.append(f"{red_bold}  Errors:{reset}")
        for error in result.errors:
            lines.append(f"{red}    • {error}{reset}")

    if result.signed:
        lines.append("")
        lines.append(
            f"{gray}  Signed by identity {result.identity_fingerprint} (key stored in: {result.key_store}){reset}"
        )

    lines.append("")
    return "\n".join(lines)
