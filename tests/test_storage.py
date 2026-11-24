"""0.8.2 storage: constant-cost saving with a crash journal (spec: specs/record-0.8/spec.md, R5)."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from unworldly.integrity import TAMPERED, VERIFIED, VERIFIED_WITH_GAPS, verify_session
from unworldly.session import (
    FLUSH_INTERVAL_SECONDS,
    add_event,
    close_session,
    create_session,
    journal_path,
    load_session,
    save_session,
)
from unworldly.types import EventType, RiskLevel, Session, WatchEvent


def _event(i: int) -> WatchEvent:
    return WatchEvent(datetime.now(timezone.utc).isoformat(), EventType.MODIFY, f"src/f{i}.py", RiskLevel.SAFE)


def _record(session: Session, base: Path, n: int, start: int = 0) -> str:
    path = ""
    for i in range(start, start + n):
        add_event(session, _event(i))
        path = save_session(session, str(base))
    return path


def _on_disk(path: str) -> int:
    return len(json.loads(Path(path).read_text(encoding="utf-8"))["events"])


def _stop_timer(session: Session) -> None:
    """Simulate a crash: the deferred full save never happens."""
    if session.persistence is not None and session.persistence.timer is not None:
        session.persistence.timer.cancel()
        session.persistence.timer = None


def test_long_session_saves_fast(tmp_path: Path) -> None:
    session = create_session(str(tmp_path))
    started = time.perf_counter()
    _record(session, tmp_path, 2000)
    elapsed = time.perf_counter() - started
    close_session(session, str(tmp_path))
    assert elapsed < 8.0, f"2000 events took {elapsed:.1f}s (was ~38s before 0.8.2)"
    assert verify_session(session).status == VERIFIED


def test_deferred_flush_writes_everything(tmp_path: Path) -> None:
    session = create_session(str(tmp_path))
    path = _record(session, tmp_path, 20)
    deadline = time.monotonic() + FLUSH_INTERVAL_SECONDS + 3
    while time.monotonic() < deadline and _on_disk(path) < 20:
        time.sleep(0.1)
    assert _on_disk(path) == 20
    assert not Path(journal_path(path)).exists()


def test_close_leaves_no_journal_and_verifies(tmp_path: Path) -> None:
    session = create_session(str(tmp_path))
    path = _record(session, tmp_path, 10)
    close_session(session, str(tmp_path))
    assert not Path(journal_path(path)).exists()
    assert not Path(path + ".tmp").exists()
    assert verify_session(load_session(path)).status == VERIFIED


def test_crash_recovery_replays_the_journal(tmp_path: Path) -> None:
    session = create_session(str(tmp_path))
    path = _record(session, tmp_path, 1)  # first save is a full write
    _record(session, tmp_path, 5, start=1)  # these land in the journal
    _stop_timer(session)
    assert _on_disk(path) < 6 and Path(journal_path(path)).exists()

    loaded = load_session(path)
    assert len(loaded.events) == 6 and loaded.recovered_records >= 1
    assert loaded.summary.total_events == 6
    result = verify_session(loaded)
    assert result.valid and result.status == VERIFIED_WITH_GAPS
    assert any("crash journal" in g for g in result.gaps)


def test_forged_journal_record_is_tampering(tmp_path: Path) -> None:
    session = create_session(str(tmp_path))
    path = _record(session, tmp_path, 1)
    _record(session, tmp_path, 2, start=1)
    _stop_timer(session)
    journal = Path(journal_path(path))
    lines = journal.read_text(encoding="utf-8").splitlines()
    forged = json.loads(lines[0])
    forged["event"]["path"] = "innocent.txt"
    journal.write_text("\n".join([json.dumps(forged), *lines[1:]]) + "\n", encoding="utf-8")
    assert verify_session(load_session(path)).status == TAMPERED


def test_truncated_journal_line_is_ignored(tmp_path: Path) -> None:
    session = create_session(str(tmp_path))
    path = _record(session, tmp_path, 1)
    _record(session, tmp_path, 2, start=1)
    _stop_timer(session)
    with open(journal_path(path), "a", encoding="utf-8") as fh:
        fh.write('{"event": {"timest')  # cut off mid-write by the crash
    loaded = load_session(path)
    assert len(loaded.events) == 3 and verify_session(loaded).valid


def test_unsigned_sessions_write_in_full_every_time(tmp_path: Path) -> None:
    session = create_session(str(tmp_path), sign=False)
    path = _record(session, tmp_path, 5)
    assert _on_disk(path) == 5 and not Path(journal_path(path)).exists()
