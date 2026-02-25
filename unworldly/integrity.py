"""Cryptographic integrity for Unworldly sessions.

Implements SHA-256 hash chains on events and session-level seals
for tamper-evident audit trails.

ISO 42001 A.6.2.8: Defensible, immutable event logs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .types import Session, WatchEvent


def hash_event(event: WatchEvent, previous_hash: str) -> str:
    """Compute SHA-256 hash of an event, chaining to the previous event's hash.

    This creates a tamper-evident chain -- modifying any event invalidates
    all subsequent hashes and the session integrity hash.
    """
    payload = json.dumps(
        {
            "timestamp": event.timestamp,
            "type": event.type.value if hasattr(event.type, "value") else event.type,
            "path": event.path,
            "risk": event.risk.value if hasattr(event.risk, "value") else event.risk,
            "reason": event.reason,
            "command": event.command.to_dict() if event.command else None,
            "previousHash": previous_hash,
        },
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_session_hash(session: Session) -> str:
    """Compute the session-level integrity hash from all event hashes.

    This is the "seal" on the session -- if any event was tampered with,
    this hash won't match on verification.
    """
    payload = json.dumps(
        {
            "id": session.id,
            "startTime": session.start_time,
            "directory": session.directory,
            "agent": session.agent.to_dict() if session.agent else None,
            "eventHashes": [e.hash for e in session.events],
            "summary": session.summary.to_dict(),
        },
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sign_event(event: WatchEvent, previous_hash: str) -> WatchEvent:
    """Add hash to an event and return it. Mutates the event."""
    event.hash = hash_event(event, previous_hash)
    return event


def get_last_hash(session: Session) -> str:
    """Get the last hash in the event chain, or the genesis hash."""
    if len(session.events) == 0:
        return genesis_hash(session.id)
    last_hash = session.events[-1].hash
    return last_hash if last_hash is not None else genesis_hash(session.id)


def genesis_hash(session_id: str) -> str:
    """Genesis hash -- the starting point for the hash chain, derived from session ID."""
    return hashlib.sha256(f"unworldly:genesis:{session_id}".encode()).hexdigest()


@dataclass
class VerifyResult:
    """Result of session integrity verification."""

    valid: bool = True
    total_events: int = 0
    valid_events: int = 0
    broken_at: int | None = None
    session_hash_valid: bool = False
    errors: list[str] = field(default_factory=list)


def verify_session(session: Session) -> VerifyResult:
    """Verify the integrity of an entire session.

    Checks every event hash in the chain and the session integrity hash.
    Returns detailed results showing exactly where tampering occurred (if any).
    """
    errors: list[str] = []
    previous_hash = genesis_hash(session.id)
    valid_events = 0
    broken_at: int | None = None

    for i, event in enumerate(session.events):
        if event.hash is None:
            # Legacy session without hashes -- can't verify but not necessarily tampered
            errors.append(f"Event {i}: No hash present (legacy session format)")
            if broken_at is None:
                broken_at = i
            continue

        expected_hash = hash_event(event, previous_hash)
        if event.hash != expected_hash:
            errors.append(f"Event {i}: Hash mismatch -- event may have been tampered with")
            if broken_at is None:
                broken_at = i
        else:
            valid_events += 1

        previous_hash = event.hash

    # Verify session integrity hash
    session_hash_valid = False
    if session.integrity_hash:
        expected_session_hash = compute_session_hash(session)
        session_hash_valid = session.integrity_hash == expected_session_hash
        if not session_hash_valid:
            errors.append("Session integrity hash mismatch -- session metadata may have been tampered with")
    else:
        errors.append("No session integrity hash present (legacy session format)")

    return VerifyResult(
        valid=len(errors) == 0,
        total_events=len(session.events),
        valid_events=valid_events,
        broken_at=broken_at,
        session_hash_valid=session_hash_valid,
        errors=errors,
    )
