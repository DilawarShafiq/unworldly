"""Session diff for Unworldly — compare two recorded sessions."""

from __future__ import annotations

from datetime import datetime

from .session import load_session
from .types import RiskLevel, Session, WatchEvent


def _file_events(session: Session) -> dict[str, list[WatchEvent]]:
    """Group non-command events by file path."""
    result: dict[str, list[WatchEvent]] = {}
    for e in session.events:
        if e.type.value != "command":
            result.setdefault(e.path, []).append(e)
    return result


def _commands(session: Session) -> list[str]:
    return [e.path for e in session.events if e.type.value == "command"]


def diff_command(session_a_path: str, session_b_path: str) -> None:
    """Compare two sessions and print a diff report."""
    sa = load_session(session_a_path)
    sb = load_session(session_b_path)

    red_bold = "\033[1;31m"
    yellow = "\033[33m"
    green = "\033[32m"
    green_bold = "\033[1;32m"
    gray = "\033[90m"
    white_bold = "\033[1;37m"
    cyan = "\033[36m"
    blue = "\033[34m"
    reset = "\033[0m"

    def _label(s: Session, letter: str) -> str:
        agent = f" [{s.agent.name}]" if s.agent else ""
        return f"{letter}: {s.id}{agent}"

    print(f"\n  {white_bold}Session Diff{reset}\n")
    print(f"  {cyan}A{reset}  {_label(sa, 'A')}")
    print(f"  {blue}B{reset}  {_label(sb, 'B')}")
    print(f"\n  {gray}{'─' * 66}{reset}\n")

    # ── Risk comparison ───────────────────────────────────────────────────────
    def _risk_color(score: float) -> str:
        if score >= 7:
            return red_bold
        if score >= 4:
            return yellow
        return green_bold

    delta = sb.summary.risk_score - sa.summary.risk_score
    delta_str = f"{'+' if delta >= 0 else ''}{delta:.1f}"
    delta_color = red_bold if delta > 0 else green_bold if delta < 0 else gray

    print(f"  {white_bold}Risk Score{reset}")
    print(
        f"    A: {_risk_color(sa.summary.risk_score)}{sa.summary.risk_score}/10{reset}"
        f"   →   B: {_risk_color(sb.summary.risk_score)}{sb.summary.risk_score}/10{reset}"
        f"   ({delta_color}{delta_str}{reset})"
    )
    print(
        f"    {gray}danger  A:{sa.summary.danger}  B:{sb.summary.danger}"
        f"   caution  A:{sa.summary.caution}  B:{sb.summary.caution}"
        f"   safe  A:{sa.summary.safe}  B:{sb.summary.safe}{reset}\n"
    )

    # ── File diff ─────────────────────────────────────────────────────────────
    files_a = _file_events(sa)
    files_b = _file_events(sb)
    all_paths = sorted(set(files_a) | set(files_b))

    only_a = [p for p in all_paths if p in files_a and p not in files_b]
    only_b = [p for p in all_paths if p not in files_a and p in files_b]
    both   = [p for p in all_paths if p in files_a and p in files_b]

    _risk_order = {RiskLevel.DANGER: 2, RiskLevel.CAUTION: 1, RiskLevel.SAFE: 0}

    def _max_risk(evts: list[WatchEvent]) -> RiskLevel:
        return max(evts, key=lambda e: _risk_order[e.risk]).risk

    def _risk_icon(r: RiskLevel) -> str:
        return {RiskLevel.DANGER: f"{red_bold}🚨{reset}", RiskLevel.CAUTION: f"{yellow}⚠️ {reset}", RiskLevel.SAFE: f"{green}✅{reset}"}[r]

    print(f"  {white_bold}File Changes{reset}  {gray}({len(all_paths)} total paths){reset}")

    if only_a:
        print(f"\n  {cyan}Only in A:{reset}")
        for p in only_a:
            r = _max_risk(files_a[p])
            print(f"    {_risk_icon(r)} {gray}{p}{reset}  {gray}×{len(files_a[p])}{reset}")

    if only_b:
        print(f"\n  {blue}Only in B:{reset}")
        for p in only_b:
            r = _max_risk(files_b[p])
            print(f"    {_risk_icon(r)} {p}  {gray}×{len(files_b[p])}{reset}")

    if both:
        changed = [(p, _max_risk(files_a[p]), _max_risk(files_b[p])) for p in both
                   if _risk_order[_max_risk(files_a[p])] != _risk_order[_max_risk(files_b[p])]]
        if changed:
            print(f"\n  {white_bold}Risk Changed:{reset}")
            for p, ra, rb in changed:
                arrow = f"{red_bold}↑{reset}" if _risk_order[rb] > _risk_order[ra] else f"{green_bold}↓{reset}"
                print(f"    {arrow} {p}  {_risk_icon(ra)}→{_risk_icon(rb)}")

    # ── Command diff ──────────────────────────────────────────────────────────
    cmds_a = set(_commands(sa))
    cmds_b = set(_commands(sb))
    new_cmds = cmds_b - cmds_a
    dropped_cmds = cmds_a - cmds_b

    if new_cmds or dropped_cmds:
        print(f"\n  {white_bold}Commands{reset}")
        for c in sorted(new_cmds):
            print(f"    {green}+{reset} {c}")
        for c in sorted(dropped_cmds):
            print(f"    {red_bold}-{reset} {gray}{c}{reset}")

    # ── Verdict ───────────────────────────────────────────────────────────────
    print(f"\n  {gray}{'─' * 66}{reset}")
    if delta < 0:
        print(f"  {green_bold}✓ Session B is safer than A (risk ↓{abs(delta):.1f}){reset}\n")
    elif delta > 0:
        print(f"  {red_bold}⚠ Session B is riskier than A (risk ↑{delta:.1f}){reset}\n")
    else:
        print(f"  {gray}Sessions have equal risk scores.{reset}\n")
