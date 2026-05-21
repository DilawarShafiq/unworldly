"""Tests for danger alert system (unworldly/alerts.py)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from unittest.mock import MagicMock, patch

import pytest

from unworldly.alerts import _webhook, fire_alert
from unworldly.types import EventType, RiskLevel, Session, SessionSummary, WatchEvent


def _make_event(path: str = ".env", reason: str = "credential file") -> WatchEvent:
    return WatchEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        type=EventType.MODIFY, path=path, risk=RiskLevel.DANGER, reason=reason,
    )


def _make_session() -> Session:
    now = datetime.now(timezone.utc).isoformat()
    return Session(version="0.5.0", id="alert001", start_time=now, end_time=now,
                   directory="/tmp", events=[], summary=SessionSummary(danger=1, risk_score=8.0))


# ── Webhook ───────────────────────────────────────────────────────────────────

class _CaptureHandler(BaseHTTPRequestHandler):
    received: list[dict] = []  # type: ignore[assignment]

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _CaptureHandler.received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass  # suppress test output


def test_webhook_posts_json() -> None:
    _CaptureHandler.received.clear()
    server = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    port = server.server_address[1]
    t = Thread(target=server.handle_request)
    t.start()

    event = _make_event()
    session = _make_session()
    _webhook(f"http://127.0.0.1:{port}/hook", event, session)
    t.join(timeout=3)
    server.server_close()

    assert len(_CaptureHandler.received) == 1
    payload = _CaptureHandler.received[0]
    assert payload["source"] == "unworldly"
    assert payload["session_id"] == "alert001"
    assert payload["event"]["risk"] == "danger"
    assert payload["event"]["path"] == ".env"


def test_webhook_ignores_unreachable_url() -> None:
    event = _make_event()
    session = _make_session()
    # Should not raise — unreachable URLs are silently ignored
    _webhook("http://127.0.0.1:1/nonexistent", event, session)


# ── fire_alert dispatch ───────────────────────────────────────────────────────

def test_fire_alert_dispatches_webhook() -> None:
    event = _make_event()
    session = _make_session()
    with patch("unworldly.alerts._webhook") as mock_wh:
        fire_alert("https://hooks.example.com/abc", event, session)
        mock_wh.assert_called_once()


def test_fire_alert_dispatches_desktop() -> None:
    event = _make_event()
    session = _make_session()
    with patch("unworldly.alerts._desktop") as mock_dt:
        fire_alert("desktop", event, session)
        mock_dt.assert_called_once()


def test_fire_alert_unknown_target_silent() -> None:
    event = _make_event()
    session = _make_session()
    # Unknown target should not raise
    fire_alert("ftp://whatever", event, session)


def test_fire_alert_http_url_uses_webhook() -> None:
    event = _make_event()
    session = _make_session()
    with patch("unworldly.alerts._webhook") as mock_wh:
        fire_alert("http://example.com/hook", event, session)
        mock_wh.assert_called_once()
