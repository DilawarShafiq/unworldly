"""Forward-secure session signing: every acceptance check from specs/signed-sessions/spec.md."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from unworldly.cli import cli
from unworldly.integrity import (
    LEGACY,
    TAMPERED,
    VERIFIED,
    VERIFIED_WITH_GAPS,
    compute_session_hash,
    genesis_hash,
    hash_event,
    verify_session,
)
from unworldly.session import add_checkpoint, add_event, close_session, create_session, load_session, save_session
from unworldly.signing import load_identity, record_payload
from unworldly.types import EventType, RiskLevel, Session, WatchEvent


def _event(path: str, risk: RiskLevel = RiskLevel.SAFE) -> WatchEvent:
    return WatchEvent(timestamp=datetime.now(timezone.utc).isoformat(), type=EventType.MODIFY, path=path, risk=risk)


def _session(tmp_path: Path, n: int = 4, close: bool = True, **kwargs: object) -> Session:
    session = create_session(str(tmp_path), **kwargs)  # type: ignore[arg-type]
    for i in range(n):
        add_event(session, _event(f"file{i}.py", RiskLevel.DANGER if i == 1 else RiskLevel.SAFE))
    if close:
        close_session(session, str(tmp_path))
    return session


def _rehash(session: Session) -> None:
    """What today's bypass does: recompute every SHA-256 hash and the session hash."""
    previous = genesis_hash(session.id)
    for event in session.events:
        event.hash = hash_event(event, previous)
        previous = event.hash
    session.integrity_hash = compute_session_hash(session)


def _reload(tmp_path: Path, session: Session) -> Session:
    return load_session(str(tmp_path / ".unworldly" / "sessions" / f"{session.id}.json"))


class TestHappyPath:
    def test_closed_session_verifies(self, tmp_path: Path) -> None:
        result = verify_session(_session(tmp_path))
        assert result.status == VERIFIED and result.valid and result.signed

    def test_round_trip_from_disk_verifies(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        assert verify_session(_reload(tmp_path, session)).status == VERIFIED

    def test_unclosed_session_reports_abnormal_end(self, tmp_path: Path) -> None:
        session = _session(tmp_path, close=False)
        save_session(session, str(tmp_path))
        result = verify_session(_reload(tmp_path, session))
        assert result.valid and result.status == VERIFIED_WITH_GAPS and result.abnormal_end

    def test_unsigned_session_is_legacy(self, tmp_path: Path) -> None:
        result = verify_session(_session(tmp_path, sign=False))
        assert result.valid and result.status == LEGACY and not result.signed

    def test_close_is_idempotent(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        close_session(session, str(tmp_path))
        assert verify_session(session).status == VERIFIED

    def test_heartbeats_are_not_shown_as_activity(self, tmp_path: Path) -> None:
        session = _session(tmp_path, close=False)
        add_checkpoint(session, "heartbeat")
        close_session(session, str(tmp_path))
        assert len(session.events) == 4 and len(session.checkpoints) == 2
        assert verify_session(session).status == VERIFIED


class TestTampering:
    def test_edited_event(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        session.events[1].path = "innocent.txt"
        assert verify_session(session).status == TAMPERED

    def test_edit_with_all_hashes_recomputed(self, tmp_path: Path) -> None:
        """The bypass that defeats an unsigned session must fail on a signed one."""
        session = _session(tmp_path)
        session.events[1].path = "innocent.txt"
        session.events[1].risk = RiskLevel.SAFE
        _rehash(session)
        result = verify_session(session)
        assert result.status == TAMPERED
        assert any("signature invalid" in e for e in result.errors)

    def test_deleted_event(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        del session.events[1]
        _rehash(session)
        assert verify_session(session).status == TAMPERED

    def test_reordered_events(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        session.events[0], session.events[2] = session.events[2], session.events[0]
        session.events[0].seq, session.events[2].seq = session.events[2].seq, session.events[0].seq
        _rehash(session)
        assert verify_session(session).status == TAMPERED

    def test_truncation_is_never_a_clean_verify(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        del session.events[-2:]
        session.checkpoints.clear()
        session.end_seal = None
        _rehash(session)
        result = verify_session(session)
        assert result.status != VERIFIED
        assert result.abnormal_end

    def test_end_seal_removed(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        session.end_seal = None
        assert verify_session(session).status == TAMPERED

    def test_event_added_after_close(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        add_event(session, _event("late.py"))
        save_session(session, str(tmp_path))
        assert verify_session(_reload(tmp_path, session)).status == TAMPERED

    def test_checkpoint_time_edited(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        session.checkpoints[0].timestamp = "2020-01-01T00:00:00+00:00"
        assert verify_session(session).status == TAMPERED

    def test_header_edited(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        session.start_time = "2020-01-01T00:00:00+00:00"
        assert verify_session(session).status == TAMPERED

    def test_stolen_current_key_cannot_forge_earlier_events(self, tmp_path: Path) -> None:
        """An attacker holding the recorder's live key re-signs an earlier event."""
        session = _session(tmp_path, close=False)
        stolen = session.signer._current  # the only private key still in existence
        target = session.events[0]
        target.path = "innocent.txt"
        _rehash(session)
        assert target.seq is not None and target.hash is not None and target.next_public_key is not None
        target.signature = stolen.sign(
            record_payload(session.id, target.seq, target.hash, target.next_public_key)
        ).hex()
        assert verify_session(session).status == TAMPERED


class TestGapsAndKeys:
    def test_recording_gap_is_reported(self, tmp_path: Path) -> None:
        session = create_session(str(tmp_path), heartbeat_seconds=0.05)
        add_event(session, _event("a.py"))
        time.sleep(0.3)
        add_event(session, _event("b.py"))
        close_session(session, str(tmp_path))
        result = verify_session(session)
        assert result.valid and result.status == VERIFIED_WITH_GAPS and result.gaps

    def test_identity_key_file_fallback(self, tmp_path: Path) -> None:
        identity = load_identity()
        assert identity.store == "file"
        assert _session(tmp_path).signing["keyStore"] == "file"  # type: ignore[index]

    def test_keychain_unavailable_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring

        from unworldly import signing

        monkeypatch.setattr(keyring, "get_keyring", lambda: FailKeyring())
        assert signing._load_from_keychain() is None

    def test_signing_failure_never_stops_recording(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from unworldly import signing

        def broken() -> None:
            raise RuntimeError("no key")

        monkeypatch.setattr(signing, "load_identity", broken)
        session = create_session(str(tmp_path))
        add_event(session, _event("a.py"))
        close_session(session, str(tmp_path))
        assert session.signer is None and verify_session(session).status == LEGACY


class TestVerifyCli:
    def _write(self, tmp_path: Path, **kwargs: object) -> str:
        session = _session(tmp_path, **kwargs)
        save_session(session, str(tmp_path)) if not kwargs.get("close", True) else None
        return str(tmp_path / ".unworldly" / "sessions" / f"{session.id}.json")

    def test_exit_codes(self, tmp_path: Path) -> None:
        runner = CliRunner()
        verified = self._write(tmp_path / "a")
        unclosed = self._write(tmp_path / "b", close=False)
        legacy = self._write(tmp_path / "c", sign=False)
        assert runner.invoke(cli, ["verify", verified]).exit_code == 0
        assert runner.invoke(cli, ["verify", "--strict", verified]).exit_code == 0
        assert runner.invoke(cli, ["verify", unclosed]).exit_code == 0
        assert runner.invoke(cli, ["verify", "--strict", unclosed]).exit_code == 2
        assert runner.invoke(cli, ["verify", legacy]).exit_code == 0
        assert runner.invoke(cli, ["verify", "--strict", legacy]).exit_code == 3
