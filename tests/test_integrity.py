"""Tests for cryptographic integrity (SHA-256 hash chain)."""

import re
import pytest

from unworldly.integrity import (
    hash_event,
    compute_session_hash,
    sign_event,
    get_last_hash,
    genesis_hash,
    verify_session,
)
from unworldly.session import create_session, add_event
from unworldly.types import WatchEvent, EventType, RiskLevel


class TestIntegrity:
    class TestGenesisHash:
        def test_return_64_char_hex_string(self):
            h = genesis_hash("abc123")
            assert re.match(r"^[0-9a-f]{64}$", h)

        def test_deterministic_for_same_session_id(self):
            assert genesis_hash("test") == genesis_hash("test")

        def test_differ_for_different_session_ids(self):
            assert genesis_hash("a") != genesis_hash("b")

    class TestHashEvent:
        def test_return_64_char_hex_string(self):
            event = WatchEvent(
                timestamp="2026-01-01T00:00:00Z",
                type=EventType.CREATE,
                path="test.ts",
                risk=RiskLevel.SAFE,
            )
            h = hash_event(event, "prev-hash")
            assert re.match(r"^[0-9a-f]{64}$", h)

        def test_deterministic(self):
            event = WatchEvent(
                timestamp="2026-01-01T00:00:00Z",
                type=EventType.MODIFY,
                path="file.ts",
                risk=RiskLevel.CAUTION,
                reason="test",
            )
            assert hash_event(event, "abc") == hash_event(event, "abc")

        def test_change_when_previous_hash_changes(self):
            event = WatchEvent(
                timestamp="2026-01-01T00:00:00Z",
                type=EventType.CREATE,
                path="test.ts",
                risk=RiskLevel.SAFE,
            )
            assert hash_event(event, "hash1") != hash_event(event, "hash2")

        def test_change_when_event_data_changes(self):
            event1 = WatchEvent(
                timestamp="2026-01-01T00:00:00Z",
                type=EventType.CREATE,
                path="test.ts",
                risk=RiskLevel.SAFE,
            )
            event2 = WatchEvent(
                timestamp="2026-01-01T00:00:00Z",
                type=EventType.DELETE,
                path="test.ts",
                risk=RiskLevel.SAFE,
            )
            assert hash_event(event1, "same") != hash_event(event2, "same")

    class TestSignEvent:
        def test_add_hash_to_event(self):
            event = WatchEvent(
                timestamp="2026-01-01T00:00:00Z",
                type=EventType.CREATE,
                path="test.ts",
                risk=RiskLevel.SAFE,
            )
            assert event.hash is None
            sign_event(event, "prev")
            assert event.hash is not None
            assert re.match(r"^[0-9a-f]{64}$", event.hash)

    class TestGetLastHash:
        def test_return_genesis_hash_for_empty_session(self):
            session = create_session("/test")
            h = get_last_hash(session)
            assert h == genesis_hash(session.id)

        def test_return_last_event_hash_when_events_exist(self):
            session = create_session("/test")
            event = WatchEvent(
                timestamp="2026-01-01T00:00:00Z",
                type=EventType.CREATE,
                path="test.ts",
                risk=RiskLevel.SAFE,
            )
            add_event(session, event)
            assert get_last_hash(session) == session.events[0].hash

    class TestVerifySession:
        def test_verify_valid_session(self):
            session = create_session("/test")
            events = [
                WatchEvent(timestamp="2026-01-01T00:00:01Z", type=EventType.CREATE, path="a.ts", risk=RiskLevel.SAFE),
                WatchEvent(timestamp="2026-01-01T00:00:02Z", type=EventType.MODIFY, path="b.ts", risk=RiskLevel.CAUTION, reason="test"),
                WatchEvent(timestamp="2026-01-01T00:00:03Z", type=EventType.DELETE, path="c.ts", risk=RiskLevel.DANGER, reason="rm"),
            ]
            for e in events:
                add_event(session, e)
            # Seal the session
            from datetime import datetime, timezone
            session.end_time = datetime.now(timezone.utc).isoformat()
            session.integrity_hash = compute_session_hash(session)

            result = verify_session(session)
            assert result.valid is True
            assert result.total_events == 3
            assert result.valid_events == 3
            assert result.session_hash_valid is True
            assert result.errors == []

        def test_detect_tampered_event(self):
            session = create_session("/test")
            add_event(session, WatchEvent(
                timestamp="2026-01-01T00:00:01Z", type=EventType.CREATE,
                path="a.ts", risk=RiskLevel.SAFE,
            ))
            add_event(session, WatchEvent(
                timestamp="2026-01-01T00:00:02Z", type=EventType.MODIFY,
                path="b.ts", risk=RiskLevel.CAUTION,
            ))

            from datetime import datetime, timezone
            session.end_time = datetime.now(timezone.utc).isoformat()
            session.integrity_hash = compute_session_hash(session)

            # Tamper with event
            session.events[0].path = "TAMPERED.ts"

            result = verify_session(session)
            assert result.valid is False
            assert result.broken_at == 0
            assert len(result.errors) > 0

        def test_detect_missing_integrity_hash(self):
            session = create_session("/test")
            add_event(session, WatchEvent(
                timestamp="2026-01-01T00:00:01Z", type=EventType.CREATE,
                path="a.ts", risk=RiskLevel.SAFE,
            ))

            result = verify_session(session)
            assert result.valid is False
            assert result.session_hash_valid is False
            assert "No session integrity hash present (legacy session format)" in result.errors

        def test_handle_empty_session(self):
            session = create_session("/test")
            result = verify_session(session)
            assert result.total_events == 0
            assert result.valid_events == 0

        def test_detect_tampered_session_hash(self):
            session = create_session("/test")
            add_event(session, WatchEvent(
                timestamp="2026-01-01T00:00:01Z", type=EventType.CREATE,
                path="a.ts", risk=RiskLevel.SAFE,
            ))
            from datetime import datetime, timezone
            session.end_time = datetime.now(timezone.utc).isoformat()
            session.integrity_hash = "fake-hash-that-does-not-match"

            result = verify_session(session)
            assert result.valid is False
            assert result.session_hash_valid is False
