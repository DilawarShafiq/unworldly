"""Tests for session management."""

import os
import re
import shutil
import tempfile

import pytest

from unworldly.session import (
    add_event,
    create_session,
    ensure_sessions_dir,
    generate_id,
    get_latest_session,
    list_sessions,
    load_session,
    save_session,
)
from unworldly.types import EventType, RiskLevel, WatchEvent


class TestGenerateId:
    def test_return_8_character_hex_string(self):
        id_ = generate_id()
        assert re.match(r"^[0-9a-f]{8}$", id_)

    def test_generate_unique_ids(self):
        ids = set(generate_id() for _ in range(100))
        assert len(ids) == 100


class TestSession:
    def setup_method(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="unworldly-session-test-")

    def teardown_method(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_ensure_sessions_dir_creates_directory(self):
        dir_path = ensure_sessions_dir(self.tmp_dir)
        assert os.path.exists(dir_path)
        assert ".unworldly" in dir_path
        assert "sessions" in dir_path

    def test_ensure_sessions_dir_is_idempotent(self):
        ensure_sessions_dir(self.tmp_dir)
        ensure_sessions_dir(self.tmp_dir)
        assert os.path.exists(os.path.join(self.tmp_dir, ".unworldly", "sessions"))

    def test_create_session_correct_structure(self):
        session = create_session("/test/dir")
        assert session.version == "0.3.0"
        assert re.match(r"^[0-9a-f]{8}$", session.id)
        assert session.start_time
        assert session.end_time == ""
        assert session.directory == "/test/dir"
        assert session.events == []
        assert session.summary.total_events == 0
        assert session.summary.safe == 0
        assert session.summary.caution == 0
        assert session.summary.danger == 0
        assert session.summary.risk_score == 0

    def test_add_event_updates_summary_counts(self):
        session = create_session("/test")
        event = WatchEvent(
            timestamp="2026-01-01T00:00:00Z",
            type=EventType.CREATE,
            path="src/index.ts",
            risk=RiskLevel.SAFE,
        )

        add_event(session, event)
        assert len(session.events) == 1
        assert session.summary.total_events == 1
        assert session.summary.safe == 1

    def test_add_event_increments_danger_count(self):
        session = create_session("/test")
        event = WatchEvent(
            timestamp="2026-01-01T00:00:00Z",
            type=EventType.MODIFY,
            path=".env",
            risk=RiskLevel.DANGER,
            reason="Credential file accessed",
        )

        add_event(session, event)
        assert session.summary.danger == 1
        assert session.summary.risk_score > 0

    def test_add_event_updates_risk_score(self):
        session = create_session("/test")

        add_event(
            session,
            WatchEvent(
                timestamp="2026-01-01T00:00:00Z",
                type=EventType.CREATE,
                path="a.ts",
                risk=RiskLevel.SAFE,
            ),
        )
        score_after_safe = session.summary.risk_score

        add_event(
            session,
            WatchEvent(
                timestamp="2026-01-01T00:00:01Z",
                type=EventType.MODIFY,
                path=".env",
                risk=RiskLevel.DANGER,
                reason="test",
            ),
        )
        assert session.summary.risk_score > score_after_safe

    def test_save_and_load_session(self):
        session = create_session(self.tmp_dir)
        add_event(
            session,
            WatchEvent(
                timestamp="2026-01-01T00:00:00Z",
                type=EventType.CREATE,
                path="test.ts",
                risk=RiskLevel.SAFE,
            ),
        )

        filepath = save_session(session, self.tmp_dir)
        assert os.path.exists(filepath)

        loaded = load_session(filepath)
        assert loaded.id == session.id
        assert len(loaded.events) == 1
        assert loaded.summary.total_events == 1

    def test_save_session_sets_end_time(self):
        session = create_session(self.tmp_dir)
        assert session.end_time == ""

        save_session(session, self.tmp_dir)
        assert session.end_time != ""

    def test_load_nonexistent_session_throws(self):
        with pytest.raises(FileNotFoundError, match="Session not found"):
            load_session("nonexistent-id-12345")

    def test_list_sessions_empty(self):
        assert list_sessions(self.tmp_dir) == []

    def test_list_sessions_returns_saved_sessions(self):
        s1 = create_session(self.tmp_dir)
        s2 = create_session(self.tmp_dir)
        save_session(s1, self.tmp_dir)
        save_session(s2, self.tmp_dir)

        sessions = list_sessions(self.tmp_dir)
        assert len(sessions) == 2

    def test_get_latest_session_returns_none_when_empty(self):
        assert get_latest_session(self.tmp_dir) is None

    def test_get_latest_session_returns_path(self):
        session = create_session(self.tmp_dir)
        save_session(session, self.tmp_dir)

        latest = get_latest_session(self.tmp_dir)
        assert latest is not None
        assert session.id in latest
