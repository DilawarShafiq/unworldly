"""Tests for OWASP Agentic AI Top 10 mapping (unworldly/owasp.py)."""

from __future__ import annotations

from datetime import datetime, timezone

from unworldly.owasp import OWASP_RULES, map_session, owasp_terminal_report, owasp_markdown_section
from unworldly.types import EventType, RiskLevel, Session, SessionSummary, WatchEvent


def _make_session(events: list[WatchEvent]) -> Session:
    now = datetime.now(timezone.utc).isoformat()
    return Session(
        version="0.5.0", id="test0001", start_time=now, end_time=now,
        directory="/tmp", events=events,
        summary=SessionSummary(total_events=len(events), danger=len(events)),
    )


def _evt(path: str, reason: str, risk: RiskLevel = RiskLevel.DANGER, etype: EventType = EventType.MODIFY) -> WatchEvent:
    return WatchEvent(timestamp=datetime.now(timezone.utc).isoformat(),
                      type=etype, path=path, risk=risk, reason=reason)


def test_credential_triggers_aa05() -> None:
    events = [_evt(".env", "credential file")]
    findings = map_session(_make_session(events))
    aa05 = next(f for f in findings if f.rule.id == "AA05")
    assert aa05.triggered
    assert len(aa05.events) == 1


def test_sudo_triggers_aa04() -> None:
    events = [_evt("sudo make install", "dangerous: sudo", etype=EventType.COMMAND)]
    findings = map_session(_make_session(events))
    aa04 = next(f for f in findings if f.rule.id == "AA04")
    assert aa04.triggered


def test_rm_rf_triggers_aa03() -> None:
    events = [_evt("rm -rf /tmp", "dangerous: rm -rf", etype=EventType.COMMAND)]
    findings = map_session(_make_session(events))
    aa03 = next(f for f in findings if f.rule.id == "AA03")
    assert aa03.triggered


def test_npm_install_triggers_aa10() -> None:
    events = [_evt("npm install lodash", "caution: npm install", risk=RiskLevel.CAUTION, etype=EventType.COMMAND)]
    findings = map_session(_make_session(events))
    aa10 = next(f for f in findings if f.rule.id == "AA10")
    assert aa10.triggered


def test_safe_event_triggers_nothing() -> None:
    events = [_evt("README.md", "safe file", risk=RiskLevel.SAFE)]
    findings = map_session(_make_session(events))
    triggered = [f for f in findings if f.triggered]
    assert len(triggered) == 0


def test_ten_rules_defined() -> None:
    assert len(OWASP_RULES) == 10


def test_terminal_report_contains_rule_ids() -> None:
    events = [_evt(".env", "credential file")]
    findings = map_session(_make_session(events))
    report = owasp_terminal_report(findings)
    assert "AA05" in report
    assert "Data Exfiltration" in report


def test_markdown_section_contains_table() -> None:
    events = [_evt(".env", "credential file")]
    findings = map_session(_make_session(events))
    md = owasp_markdown_section(findings)
    assert "| AA05 |" in md
    assert "triggered" in md.lower()
