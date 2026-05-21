"""Tests for session diff (unworldly/diff.py)."""

from __future__ import annotations

import io
import sys
from datetime import datetime, timezone

import pytest

from unworldly.diff import _file_events, _commands
from unworldly.types import EventType, RiskLevel, Session, SessionSummary, WatchEvent


def _make_session(sid: str, events: list[WatchEvent]) -> Session:
    now = datetime.now(timezone.utc).isoformat()
    summary = SessionSummary(
        total_events=len(events),
        safe=sum(1 for e in events if e.risk == RiskLevel.SAFE),
        caution=sum(1 for e in events if e.risk == RiskLevel.CAUTION),
        danger=sum(1 for e in events if e.risk == RiskLevel.DANGER),
        risk_score=float(sum(1 for e in events if e.risk == RiskLevel.DANGER) * 2),
    )
    return Session(version="0.5.0", id=sid, start_time=now, end_time=now,
                   directory="/tmp", events=events, summary=summary)


def _evt(path: str, risk: RiskLevel, etype: EventType = EventType.MODIFY) -> WatchEvent:
    return WatchEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        type=etype,
        path=path,
        risk=risk,
        reason="test",
    )


def test_file_events_excludes_commands() -> None:
    events = [
        _evt("src/main.py", RiskLevel.SAFE),
        _evt("git add .", RiskLevel.SAFE, EventType.COMMAND),
    ]
    sa = _make_session("a1", events)
    fe = _file_events(sa)
    assert "src/main.py" in fe
    assert "git add ." not in fe


def test_commands_returns_command_paths() -> None:
    events = [
        _evt("src/main.py", RiskLevel.SAFE),
        _evt("npm install", RiskLevel.CAUTION, EventType.COMMAND),
        _evt("rm -rf /", RiskLevel.DANGER, EventType.COMMAND),
    ]
    sa = _make_session("a2", events)
    cmds = _commands(sa)
    assert "npm install" in cmds
    assert "rm -rf /" in cmds
    assert "src/main.py" not in cmds


def test_diff_command_runs_without_error(tmp_path: object, capsys: pytest.CaptureFixture[str]) -> None:
    from unworldly.diff import diff_command
    import json, os

    sessions_dir = str(tmp_path) + "/.unworldly/sessions"
    os.makedirs(sessions_dir, exist_ok=True)

    sa = _make_session("aaaa0001", [_evt(".env", RiskLevel.DANGER)])
    sb = _make_session("bbbb0002", [_evt("README.md", RiskLevel.SAFE)])

    for s in [sa, sb]:
        with open(f"{sessions_dir}/{s.id}.json", "w") as f:
            json.dump(s.to_dict(), f)

    diff_command(f"{sessions_dir}/aaaa0001.json", f"{sessions_dir}/bbbb0002.json")
    out = capsys.readouterr().out
    assert "aaaa0001" in out
    assert "bbbb0002" in out
