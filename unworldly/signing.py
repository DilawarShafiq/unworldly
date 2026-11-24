"""Forward-secure session signing for Unworldly.

Every record in a session (activity events and checkpoints) is signed with a
one-time Ed25519 key. Before a record is signed, the next key pair is generated
and its public key is committed inside that record's signed payload; the
current private key is then dropped and never written to disk. Verification
needs only the first public key (``pk0``), so whoever later steals the live
key cannot forge, alter, remove or reorder any record made before the theft.

A long-lived identity key (OS keychain, falling back to an owner-only file)
signs the session header (``pk0``) at the start and the final seal at the end.

Honest limits (see README): an attacker who controls the recorder *while* it
records can forge records from that point on; someone holding the identity key
can fabricate an entirely new session.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SCHEME = "ed25519-fs-v1"
KEYRING_SERVICE = "unworldly-recorder"
KEYRING_USERNAME = "identity-key"
DEFAULT_HEARTBEAT_SECONDS = 30.0

# Environment overrides (tests, CI, headless machines):
#   UNWORLDLY_KEY_STORE=file  -> skip the OS keychain, use the key file
#   UNWORLDLY_HOME=<dir>      -> where the key file lives (default ~/.unworldly)
_ENV_KEY_STORE = "UNWORLDLY_KEY_STORE"
_ENV_HOME = "UNWORLDLY_HOME"


def canonical(data: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding used for every signed payload."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def public_hex(key: Ed25519PublicKey) -> str:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def fingerprint(public_key_hex: str) -> str:
    """Short, human-comparable identity fingerprint."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


def verify_signature(public_key_hex: str, signature_hex: str, payload: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(bytes.fromhex(signature_hex), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


# ── Identity key ──────────────────────────────────────────────────────────────


@dataclass
class IdentityKey:
    """The machine/user identity key and where it is stored ("keychain" or "file")."""

    private_key: Ed25519PrivateKey
    store: str

    @property
    def public_hex(self) -> str:
        return public_hex(self.private_key.public_key())

    def sign(self, payload: bytes) -> str:
        return self.private_key.sign(payload).hex()


def _key_file() -> Path:
    home = os.environ.get(_ENV_HOME)
    base = Path(home) if home else Path.home() / ".unworldly"
    return base / "identity.key"


def _from_hex(value: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value.strip()))


def _new_private_hex() -> str:
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def _load_from_keychain() -> IdentityKey | None:
    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring

        if isinstance(keyring.get_keyring(), FailKeyring):
            return None
        stored = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        if stored is None:
            stored = _new_private_hex()
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, stored)
        return IdentityKey(_from_hex(stored), "keychain")
    except Exception:
        return None  # no usable keychain backend: fall back to the key file


def _load_from_file() -> IdentityKey:
    path = _key_file()
    if path.exists():
        return IdentityKey(_from_hex(path.read_text(encoding="utf-8")), "file")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # owner-only
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(_new_private_hex())
    return IdentityKey(_from_hex(path.read_text(encoding="utf-8")), "file")


_identity_cache: IdentityKey | None = None
_identity_lock = threading.Lock()


def load_identity() -> IdentityKey:
    """Load (creating on first use) this user's identity key."""
    global _identity_cache
    with _identity_lock:
        if _identity_cache is None:
            identity = None
            if os.environ.get(_ENV_KEY_STORE, "").lower() != "file":
                identity = _load_from_keychain()
            _identity_cache = identity or _load_from_file()
        return _identity_cache


def reset_identity_cache() -> None:
    """Forget the cached identity (tests, or after changing key-store settings)."""
    global _identity_cache
    with _identity_lock:
        _identity_cache = None


# ── Per-session forward-secure signer ─────────────────────────────────────────


def header_payload(session_id: str, start_time: str, directory: str, pk0: str, identity_key: str) -> bytes:
    return canonical(
        {
            "scheme": SCHEME,
            "session": session_id,
            "startTime": start_time,
            "directory": directory,
            "pk0": pk0,
            "identityKey": identity_key,
        }
    )


def record_payload(session_id: str, seq: int, digest: str, next_public_key: str) -> bytes:
    return canonical({"session": session_id, "seq": seq, "digest": digest, "next": next_public_key})


def seal_payload(session_id: str, integrity_hash: str, records: int, end_signature: str) -> bytes:
    return canonical(
        {"session": session_id, "integrityHash": integrity_hash, "records": records, "endSignature": end_signature}
    )


class SessionSigner:
    """Signs a session's records with an evolving one-time key. Thread-safe.

    Lives only in memory; it is never serialized.
    """

    def __init__(
        self,
        session_id: str,
        start_time: str,
        directory: str,
        identity: IdentityKey,
        heartbeat_seconds: float | None,
    ) -> None:
        self.session_id = session_id
        self.identity = identity
        self.lock = threading.RLock()
        self._current = Ed25519PrivateKey.generate()
        self._seq = 0
        pk0 = public_hex(self._current.public_key())
        self.header: dict[str, Any] = {
            "scheme": SCHEME,
            "pk0": pk0,
            "identityKey": identity.public_hex,
            "identitySignature": identity.sign(
                header_payload(session_id, start_time, directory, pk0, identity.public_hex)
            ),
            "keyStore": identity.store,
            "heartbeatSeconds": heartbeat_seconds,
        }

    def sign(self, digest: str) -> tuple[int, str, str]:
        """Sign the next record; returns (seq, signature, next_public_key).

        The key that produced the signature is dropped immediately afterwards.
        """
        with self.lock:
            nxt = Ed25519PrivateKey.generate()
            next_pk = public_hex(nxt.public_key())
            seq = self._seq
            signature = self._current.sign(record_payload(self.session_id, seq, digest, next_pk)).hex()
            self._current = nxt  # previous private key is now unreachable
            self._seq += 1
            return seq, signature, next_pk

    @property
    def records(self) -> int:
        return self._seq

    def seal(self, integrity_hash: str, end_signature: str) -> dict[str, Any]:
        """Identity-sign the final seal (called once, at clean shutdown)."""
        with self.lock:
            records = self._seq
            return {
                "records": records,
                "signature": self.identity.sign(seal_payload(self.session_id, integrity_hash, records, end_signature)),
            }
