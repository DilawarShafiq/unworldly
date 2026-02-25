"""Session management for Unworldly.

Handles creation, saving, loading, and listing of recording sessions.
Sessions are stored as JSON files in .unworldly/sessions/.
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from typing import Optional

from .types import Session, SessionSummary, WatchEvent
from .risk import calculate_risk_score
from .integrity import sign_event, get_last_hash, compute_session_hash

SESSIONS_DIR = ".unworldly/sessions"


def generate_id() -> str:
    """Generate a random 8-character hex session ID."""
    return secrets.token_hex(4)


def ensure_sessions_dir(base_dir: str) -> str:
    """Ensure the sessions directory exists and return its path."""
    dir_path = os.path.join(base_dir, SESSIONS_DIR)
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


def create_session(directory: str) -> Session:
    """Create a new empty session."""
    return Session(
        version="0.3.0",
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
    )


def add_event(session: Session, event: WatchEvent) -> None:
    """Add an event to a session, updating the hash chain and summary."""
    # Hash chain: sign event with previous hash for tamper-evidence
    previous_hash = get_last_hash(session)
    sign_event(event, previous_hash)

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


def save_session(session: Session, base_dir: str) -> str:
    """Save a session to disk and return the file path.

    Sets the end time and computes the session integrity hash (seal).
    """
    session.end_time = datetime.now(timezone.utc).isoformat()
    # Compute session-level integrity hash (seal the session)
    session.integrity_hash = compute_session_hash(session)
    dir_path = ensure_sessions_dir(base_dir)
    filename = f"{session.id}.json"
    filepath = os.path.join(dir_path, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(session.to_dict(), f, indent=2)
    return filepath


def load_session(session_path: str) -> Session:
    """Load a session from disk by path or ID."""
    resolved = resolve_session_path(session_path)
    with open(resolved, "r", encoding="utf-8") as f:
        data = json.load(f)
    return Session.from_dict(data)


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


def get_latest_session(base_dir: str) -> Optional[str]:
    """Get the path to the most recent session, or None."""
    sessions = list_sessions(base_dir)
    if not sessions:
        return None
    return os.path.join(base_dir, SESSIONS_DIR, sessions[0])
