"""Cryptographic integrity for Unworldly sessions.

Implements SHA-256 hash chains on events and session-level seals
for tamper-evident audit trails.

ISO 42001 A.6.2.8: Defensible, tamper-evident event logs.
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
    fields: dict[str, object] = {
        "timestamp": event.timestamp,
        "type": event.type.value if hasattr(event.type, "value") else event.type,
        "path": event.path,
        "risk": event.risk.value if hasattr(event.risk, "value") else event.risk,
        "reason": event.reason,
        "command": event.command.to_dict() if event.command else None,
        "previousHash": previous_hash,
    }
    # Fields added in 0.8 are hashed only when present, so older sessions still verify.
    for key, value in (("beforeHash", event.before_hash), ("afterHash", event.after_hash), ("diff", event.diff)):
        if value is not None:
            fields[key] = value
    payload = json.dumps(fields, separators=(",", ":"))
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


# Verification outcomes
VERIFIED = "VERIFIED"  # signed, complete, every check passes
VERIFIED_WITH_GAPS = "VERIFIED_WITH_GAPS"  # signed and untampered, but gaps / abnormal end
TAMPERED = "TAMPERED"  # a hash, signature, sequence or seal check failed
LEGACY = "LEGACY"  # unsigned session: hash chain only (tamper-evident, not tamper-resistant)


@dataclass
class VerifyResult:
    """Result of session integrity verification."""

    valid: bool = True
    total_events: int = 0
    valid_events: int = 0
    broken_at: int | None = None
    session_hash_valid: bool = False
    errors: list[str] = field(default_factory=list)
    status: str = LEGACY
    signed: bool = False
    gaps: list[str] = field(default_factory=list)
    abnormal_end: bool = False
    key_store: str | None = None
    identity_fingerprint: str | None = None


def verify_session(session: Session) -> VerifyResult:
    """Verify the integrity of an entire session.

    Checks every event hash in the chain and the session integrity hash and, for
    signed sessions, every forward-secure signature, the record sequence, the
    identity-signed header and end seal, and recording gaps. Returns detailed
    results showing exactly where tampering occurred (if any).
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

    result = VerifyResult(
        total_events=len(session.events),
        valid_events=valid_events,
        broken_at=broken_at,
        session_hash_valid=session_hash_valid,
        errors=errors,
    )
    if session.signing is not None:
        _verify_signed(session, result)
    result.valid = len(result.errors) == 0
    if not result.valid:
        result.status = TAMPERED
    elif not result.signed:
        result.status = LEGACY
    elif result.gaps or result.abnormal_end:
        result.status = VERIFIED_WITH_GAPS
    else:
        result.status = VERIFIED
    return result


def _verify_signed(session: Session, result: VerifyResult) -> None:
    """Check the forward-secure signature chain of a signed session (see signing.py)."""
    from datetime import datetime

    from .session import checkpoint_digest
    from .signing import SCHEME, fingerprint, header_payload, record_payload, seal_payload, verify_signature

    hdr = session.signing or {}
    result.signed = True
    result.key_store = hdr.get("keyStore")
    errors = result.errors
    if hdr.get("scheme") != SCHEME:
        errors.append(f"Unknown signing scheme: {hdr.get('scheme')!r}")
        return
    pk0, identity = str(hdr.get("pk0", "")), str(hdr.get("identityKey", ""))
    try:
        result.identity_fingerprint = fingerprint(identity)
    except ValueError:
        errors.append("Signing header has a malformed identity key")
        return
    header = header_payload(session.id, session.start_time, session.directory, pk0, identity)
    if not verify_signature(identity, str(hdr.get("identitySignature", "")), header):
        errors.append("Session header signature invalid -- start time, directory or first key were altered")

    # One signed sequence across activity events and checkpoints.
    records: list[tuple[int, str, str, str, str, str]] = []  # seq, label, digest, signature, next key, time
    for i, event in enumerate(session.events):
        if event.seq is None or event.signature is None or event.next_public_key is None or event.hash is None:
            errors.append(f"Event {i}: unsigned event inside a signed session")
            continue
        records.append((event.seq, f"Event {i}", event.hash, event.signature, event.next_public_key, event.timestamp))
    for cp in session.checkpoints:
        label = f"{cp.kind.capitalize()} checkpoint"
        if checkpoint_digest(session.id, cp.kind, cp.timestamp) != cp.digest:
            errors.append(f"{label} (seq {cp.seq}): content altered")
        records.append((cp.seq, label, cp.digest, cp.signature, cp.next_public_key, cp.timestamp))
    records.sort(key=lambda r: r[0])

    key = pk0
    for expected_seq, (seq, label, digest, signature, next_key, _ts) in enumerate(records):
        if seq != expected_seq:
            errors.append(f"Record sequence broken at #{expected_seq} -- records were removed, added or duplicated")
            break
        if not verify_signature(key, signature, record_payload(session.id, seq, digest, next_key)):
            errors.append(f"{label} (seq {seq}): signature invalid -- altered, reordered or forged")
            break
        key = next_key

    # Clean end: an `end` checkpoint must be the last record, sealed by the identity key.
    ends = [cp for cp in session.checkpoints if cp.kind == "end"]
    if not ends:
        result.abnormal_end = True
        if session.end_seal is not None:
            errors.append("End seal present but the end checkpoint is missing")
    else:
        end = ends[-1]
        if len(ends) > 1 or (records and records[-1][0] != end.seq):
            errors.append("Records found after the end of the session")
        seal = session.end_seal
        if seal is None:
            errors.append("End seal missing -- the session's final seal was removed")
        else:
            payload = seal_payload(
                session.id, session.integrity_hash or "", int(seal.get("records", -1)), end.signature
            )
            if seal.get("records") != len(records) or not verify_signature(
                identity, str(seal.get("signature")), payload
            ):
                errors.append("End seal invalid -- the session was changed after it was closed")

    # Recording gaps: time between consecutive records longer than 2x the heartbeat.
    heartbeat = hdr.get("heartbeatSeconds")
    if heartbeat:
        times = [datetime.fromisoformat(r[5].replace("Z", "+00:00")) for r in records]
        for before, after in zip(times, times[1:], strict=False):
            seconds = (after - before).total_seconds()
            if seconds > 2 * float(heartbeat):
                minutes, secs = divmod(int(seconds), 60)
                result.gaps.append(f"Recording gap of {minutes} min {secs} s starting {before.isoformat()}")
