"""Session management for Unworldly.

Handles creation, saving, loading, and listing of recording sessions.
Sessions are stored as JSON files in .unworldly/sessions/.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any

from ._version import __version__
from .integrity import compute_session_hash, get_last_hash, sign_event
from .risk import calculate_risk_score
from .types import Checkpoint, Session, SessionSummary, WatchEvent

SESSIONS_DIR = ".unworldly/sessions"


def generate_id() -> str:
    """Generate a random 8-character hex session ID."""
    return secrets.token_hex(4)


def ensure_sessions_dir(base_dir: str) -> str:
    """Ensure the sessions directory exists and return its path."""
    dir_path = os.path.join(base_dir, SESSIONS_DIR)
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


def create_session(
    directory: str,
    tag: str | None = None,
    sign: bool = True,
    heartbeat_seconds: float | None = None,
) -> Session:
    """Create a new empty session.

    With ``sign=True`` (default) the session is forward-secure signed (see
    ``signing.py``). If no signing key can be loaded, the session is still
    recorded, unsigned — recording never fails because of signing.
    ``heartbeat_seconds`` declares how often the recorder writes heartbeats, so
    ``verify`` can report recording gaps; None means no heartbeats.
    """
    session = Session(
        version=__version__,
        id=generate_id(),
        start_time=datetime.now(timezone.utc).isoformat(),
        end_time="",
        directory=directory,
        events=[],
        summary=SessionSummary(
            total_events=0,
            safe=0,
            caution=0,
            danger=0,
            risk_score=0.0,
        ),
        tag=tag,
    )
    if sign:
        try:
            from .signing import SessionSigner, load_identity

            signer = SessionSigner(session.id, session.start_time, directory, load_identity(), heartbeat_seconds)
            session.signer = signer
            session.signing = signer.header
        except Exception:
            session.signer = None  # unsigned (verifies as LEGACY); recording continues
    return session


def _lock(session: Session) -> Any:
    return session.signer.lock if session.signer is not None else contextlib.nullcontext()


def add_event(session: Session, event: WatchEvent) -> None:
    """Add an event to a session, updating the hash chain, signature and summary."""
    with _lock(session):
        _add_event_locked(session, event)


def _add_event_locked(session: Session, event: WatchEvent) -> None:
    # Hash chain: sign event with previous hash for tamper-evidence
    previous_hash = get_last_hash(session)
    sign_event(event, previous_hash)
    if session.signer is not None and event.hash is not None:
        event.seq, event.signature, event.next_public_key = session.signer.sign(event.hash)

    session.events.append(event)
    session.summary.total_events += 1

    # Increment the appropriate risk counter
    risk_value = event.risk.value if hasattr(event.risk, "value") else event.risk
    if risk_value == "safe":
        session.summary.safe += 1
    elif risk_value == "caution":
        session.summary.caution += 1
    elif risk_value == "danger":
        session.summary.danger += 1

    session.summary.risk_score = calculate_risk_score(
        session.summary.safe,
        session.summary.caution,
        session.summary.danger,
    )


def checkpoint_digest(session_id: str, kind: str, timestamp: str) -> str:
    payload = json.dumps({"session": session_id, "kind": kind, "timestamp": timestamp}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def add_checkpoint(session: Session, kind: str) -> Checkpoint | None:
    """Append a signed checkpoint ("heartbeat" or "end"); no-op for unsigned sessions."""
    if session.signer is None:
        return None
    with session.signer.lock:
        timestamp = datetime.now(timezone.utc).isoformat()
        digest = checkpoint_digest(session.id, kind, timestamp)
        seq, signature, next_pk = session.signer.sign(digest)
        checkpoint = Checkpoint(kind, timestamp, seq, digest, signature, next_pk)
        session.checkpoints.append(checkpoint)
        return checkpoint


# Signed sessions are rewritten in full at most this often; in between, new records
# are appended to a small crash journal next to the session file.
FLUSH_INTERVAL_SECONDS = 1.0


class _Persistence:
    """In-memory bookkeeping for one session's saves (never serialized)."""

    def __init__(self) -> None:
        self.last_full = 0.0
        self.full_events = 0  # records in the last full write of the session file
        self.full_checkpoints = 0
        self.journaled_events = 0  # records written to the file or the journal so far
        self.journaled_checkpoints = 0
        self.timer: threading.Timer | None = None


def _persistence(session: Session) -> _Persistence:
    if session.persistence is None:
        session.persistence = _Persistence()
    state: _Persistence = session.persistence
    return state


def _session_file(base_dir: str, session_id: str) -> str:
    return os.path.join(ensure_sessions_dir(base_dir), f"{session_id}.json")


def journal_path(session_file: str) -> str:
    return (
        session_file[: -len(".json")] + ".journal.jsonl"
        if session_file.endswith(".json")
        else session_file + ".journal.jsonl"
    )


def save_session(session: Session, base_dir: str) -> str:
    """Save a session to disk and return the file path.

    Unsigned sessions are rewritten in full every time. Signed sessions are
    rewritten in full at most once per ``FLUSH_INTERVAL_SECONDS``; records added
    in between go to an append-only crash journal immediately, and a deferred
    flush writes the full file shortly after. This keeps saving cheap on long
    sessions (constant per event instead of growing with the session) while
    losing nothing on a crash — ``load_session`` replays the journal, and every
    journaled record is still checked against its forward-secure signature.
    """
    with _lock(session):
        if session.signer is None:
            return _full_save(session, base_dir)
        state = _persistence(session)
        if time.monotonic() - state.last_full >= FLUSH_INTERVAL_SECONDS:
            return _full_save(session, base_dir)
        _append_journal(session, base_dir, state)
        if state.timer is None:
            state.timer = threading.Timer(FLUSH_INTERVAL_SECONDS, _deferred_flush, (session, base_dir))
            state.timer.daemon = True
            state.timer.start()
        return _session_file(base_dir, session.id)


def _deferred_flush(session: Session, base_dir: str) -> None:
    with _lock(session):
        state = _persistence(session)
        state.timer = None
        if state.full_events != len(session.events) or state.full_checkpoints != len(session.checkpoints):
            # Never crash the recorder; if this fails the journal still holds the records.
            with contextlib.suppress(Exception):
                _full_save(session, base_dir)


def _full_save(session: Session, base_dir: str) -> str:
    session.end_time = datetime.now(timezone.utc).isoformat()
    # Compute session-level integrity hash (seal the session)
    session.integrity_hash = compute_session_hash(session)
    path = _write(session, base_dir)
    if session.signer is not None:
        state = _persistence(session)
        state.last_full = time.monotonic()
        state.full_events = state.journaled_events = len(session.events)
        state.full_checkpoints = state.journaled_checkpoints = len(session.checkpoints)
        with contextlib.suppress(FileNotFoundError, PermissionError):
            os.remove(journal_path(path))
    return path


def _append_journal(session: Session, base_dir: str, state: _Persistence) -> None:
    lines = [json.dumps({"event": e.to_dict()}) for e in session.events[state.journaled_events :]]
    lines += [json.dumps({"checkpoint": c.to_dict()}) for c in session.checkpoints[state.journaled_checkpoints :]]
    if not lines:
        return
    with open(journal_path(_session_file(base_dir, session.id)), "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    state.journaled_events = len(session.events)
    state.journaled_checkpoints = len(session.checkpoints)


def _write(session: Session, base_dir: str) -> str:
    """Write the full session file atomically (a reader never sees a half-written file)."""
    filepath = _session_file(base_dir, session.id)
    tmp = f"{filepath}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(session.to_dict(), f, indent=2)
    for attempt in range(5):
        try:
            os.replace(tmp, filepath)
            break
        except PermissionError:  # Windows: a reader has the file open for a moment
            if attempt == 4:
                raise
            time.sleep(0.05)
    return filepath


def close_session(session: Session, base_dir: str) -> str:
    """Finish a session cleanly: signed ``end`` checkpoint + identity-signed seal.

    Safe to call more than once. A session that is never closed (recorder
    killed, machine crashed) still verifies, but is reported as ended abnormally.
    """
    with _lock(session):
        if session.persistence is not None and session.persistence.timer is not None:
            session.persistence.timer.cancel()
            session.persistence.timer = None
        if session.signer is None or session.end_seal is not None:
            return _full_save(session, base_dir)
        end = add_checkpoint(session, "end")
        _full_save(session, base_dir)
        if end is not None and session.integrity_hash is not None:
            session.end_seal = session.signer.seal(session.integrity_hash, end.signature)
        return _write(session, base_dir)


def load_session(session_path: str) -> Session:
    """Load a session from disk by path or ID, replaying any crash-journal records."""
    resolved = resolve_session_path(session_path)
    with open(resolved, encoding="utf-8") as f:
        data = json.load(f)
    session = Session.from_dict(data)
    _replay_journal(session, journal_path(resolved))
    return session


def _replay_journal(session: Session, path: str) -> None:
    """Merge records the recorder journaled but never wrote in full (it stopped first).

    Only signed sessions journal. Recovered records are verified like any other:
    each still has to carry a valid forward-secure signature.
    """
    if session.signing is None or not os.path.exists(path):
        return
    have = {e.seq for e in session.events} | {c.seq for c in session.checkpoints}
    recovered = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue  # a line cut off by the crash
            if "event" in item:
                event = WatchEvent.from_dict(item["event"])
                if event.seq not in have:
                    session.events.append(event)
                    have.add(event.seq)
                    recovered += 1
            elif "checkpoint" in item:
                checkpoint = Checkpoint.from_dict(item["checkpoint"])
                if checkpoint.seq not in have:
                    session.checkpoints.append(checkpoint)
                    have.add(checkpoint.seq)
                    recovered += 1
    if recovered:
        session.recovered_records = recovered
        session.summary = SessionSummary()
        for event in session.events:
            session.summary.total_events += 1
            level = event.risk.value
            if level == "safe":
                session.summary.safe += 1
            elif level == "caution":
                session.summary.caution += 1
            elif level == "danger":
                session.summary.danger += 1
        session.summary.risk_score = calculate_risk_score(
            session.summary.safe, session.summary.caution, session.summary.danger
        )
        # The unkeyed session hash was never written for these records; the per-record
        # signatures are what prove them, so recompute it rather than report a false alarm.
        session.integrity_hash = compute_session_hash(session)


def resolve_session_path(input_path: str) -> str:
    """Resolve a session ID or path to an absolute file path.

    Accepts:
    - Full path to a .json file
    - Session ID (looks in .unworldly/sessions/)
    - Relative path
    """
    # If it's already a full path to a JSON file
    if input_path.endswith(".json") and os.path.exists(input_path):
        return input_path

    # If it's a session ID, look in the sessions directory
    sessions_dir = os.path.join(os.getcwd(), SESSIONS_DIR)
    by_id = os.path.join(sessions_dir, f"{input_path}.json")
    if os.path.exists(by_id):
        return by_id

    # Try as relative path
    relative = os.path.abspath(input_path)
    if os.path.exists(relative):
        return relative

    raise FileNotFoundError(f"Session not found: {input_path}")


def list_sessions(base_dir: str) -> list[str]:
    """List all session filenames in reverse order (newest first)."""
    dir_path = os.path.join(base_dir, SESSIONS_DIR)
    if not os.path.exists(dir_path):
        return []
    files = [f for f in os.listdir(dir_path) if f.endswith(".json")]
    files.sort(reverse=True)
    return files


def get_latest_session(base_dir: str) -> str | None:
    """Get the path to the most recent session, or None."""
    sessions = list_sessions(base_dir)
    if not sessions:
        return None
    return os.path.join(base_dir, SESSIONS_DIR, sessions[0])
