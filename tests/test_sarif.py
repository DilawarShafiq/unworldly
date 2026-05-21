"""Tests for SARIF 2.1.0 export (unworldly/sarif.py)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

from unworldly.sarif import _to_sarif, export_sarif
from unworldly.types import EventType, RiskLevel, Session, SessionSummary, WatchEvent


def _make_session(events: list[WatchEvent]) -> Session:
    now = datetime.now(timezone.utc).isoformat()
    danger = sum(1 for e in events if e.risk == RiskLevel.DANGER)
    caution = sum(1 for e in events if e.risk == RiskLevel.CAUTION)
    return Session(
        version="0.5.0", id="sarif001", start_time=now, end_time=now,
        directory="/tmp", events=events,
        summary=SessionSummary(total_events=len(events), danger=danger, caution=caution,
                               safe=len(events) - danger - caution, risk_score=float(danger * 2)),
    )


def _evt(path: str, risk: RiskLevel, etype: EventType = EventType.MODIFY, reason: str = "test") -> WatchEvent:
    return WatchEvent(timestamp=datetime.now(timezone.utc).isoformat(),
                      type=etype, path=path, risk=risk, reason=reason)


def test_sarif_version() -> None:
    sarif = _to_sarif(_make_session([]))
    assert sarif["version"] == "2.1.0"


def test_sarif_tool_name() -> None:
    sarif = _to_sarif(_make_session([]))
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Unworldly"


def test_safe_events_excluded() -> None:
    events = [_evt("README.md", RiskLevel.SAFE)]
    sarif = _to_sarif(_make_session(events))
    assert len(sarif["runs"][0]["results"]) == 0


def test_danger_event_maps_to_error() -> None:
    events = [_evt(".env", RiskLevel.DANGER, reason="credential file")]
    sarif = _to_sarif(_make_session(events))
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"
    assert results[0]["ruleId"] == "UW001"


def test_caution_event_maps_to_warning() -> None:
    events = [_evt("package.json", RiskLevel.CAUTION, reason="dependency file")]
    sarif = _to_sarif(_make_session(events))
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "warning"


def test_command_danger_maps_uw002() -> None:
    events = [_evt("rm -rf /", RiskLevel.DANGER, etype=EventType.COMMAND, reason="dangerous: rm -rf")]
    sarif = _to_sarif(_make_session(events))
    results = sarif["runs"][0]["results"]
    assert results[0]["ruleId"] == "UW002"


def test_export_sarif_creates_file(tmp_path: pytest.TempPathFactory) -> None:
    session = _make_session([_evt(".env", RiskLevel.DANGER, reason="credential file")])
    session_path = str(tmp_path) + "/test.json"
    import json as _json
    with open(session_path, "w") as f:
        _json.dump(session.to_dict(), f)

    out_path = str(tmp_path) + "/out.sarif"
    export_sarif(session_path, output=out_path)
    assert os.path.exists(out_path)
    with open(out_path) as f:
        data = json.load(f)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1


def test_sarif_has_five_rules() -> None:
    from unworldly.sarif import _RULES
    assert len(_RULES) == 5
