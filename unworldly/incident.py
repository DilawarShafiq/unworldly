"""Signed incident packets (spec: specs/forensics-0.10/spec.md, L3).

``unworldly incident`` bundles everything about one session into a single zip that someone
else can verify without trusting the sender or their machine:

- ``session.json`` (+ ``session.journal.jsonl`` if the recorder stopped before its last save)
- ``report.md``, ``flags.json``, ``verify.json``, ``credentials.json`` (fingerprints only)
- ``README.txt`` with verification instructions
- ``manifest.json``: SHA-256 of every file, signed by the packager's identity key

``unworldly incident --verify packet.zip`` checks the manifest signature, every file hash,
that nothing was added or removed, and re-runs full session verification. The zip is read
in memory and never extracted.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ._version import __version__
from .flags import find_flags
from .integrity import verify_session
from .session import journal_path, load_session, resolve_session_path
from .signing import canonical, fingerprint, load_identity, verify_signature

MANIFEST = "manifest.json"
PACKET_FORMAT = "unworldly-incident-v1"

_README = """UNWORLDLY INCIDENT PACKET
=========================

This packet is a signed, self-contained record of one AI agent session.

Verify it (needs only Unworldly: pip install unworldly-recorder):

    unworldly incident --verify {name}

Verification checks that:
  1. manifest.json is signed by the packager's identity key ({packager})
  2. every file matches the SHA-256 listed in the manifest, and none was added or removed
  3. the session's own forward-secure signatures, record sequence and seal are intact

Contents:
  session.json      the recorded session (events, signatures, custody, credential fingerprints)
  report.md         human-readable report (what happened, flags, credential lineage, custody)
  flags.json        behaviour flags computed from the session
  verify.json       session verification result at packaging time
  credentials.json  credential lineage (names, sources, fingerprints; never values)
  manifest.json     file hashes, signed

Session {session_id}, packaged {created} with Unworldly {version}.
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_payload(manifest: dict[str, Any]) -> bytes:
    return canonical({k: manifest[k] for k in ("format", "created", "session", "files", "packager")})


def create_packet(session_ref: str, output: str | None = None) -> str:
    """Write the signed incident packet for a session and return its path."""
    from .report import _generate_markdown

    session_path = resolve_session_path(session_ref)
    session = load_session(session_path)
    result = verify_session(session)
    findings = find_flags(session)

    uses: dict[str, list[int]] = {}
    for number, event in enumerate(session.events, start=1):
        for ref in event.credentials or []:
            uses.setdefault(ref, []).append(number)

    with open(session_path, "rb") as fh:
        files: dict[str, bytes] = {"session.json": fh.read()}
    journal = journal_path(session_path)
    if os.path.exists(journal):
        with open(journal, "rb") as fh:
            files["session.journal.jsonl"] = fh.read()
    files["report.md"] = _generate_markdown(session).encode("utf-8")
    files["flags.json"] = json.dumps([f.to_dict() for f in findings], indent=2).encode("utf-8")
    files["verify.json"] = json.dumps(
        {
            "status": result.status,
            "valid": result.valid,
            "signed": result.signed,
            "errors": result.errors,
            "gaps": result.gaps,
            "identityFingerprint": result.identity_fingerprint,
        },
        indent=2,
    ).encode("utf-8")
    files["credentials.json"] = json.dumps({"index": session.credential_index or {}, "uses": uses}, indent=2).encode(
        "utf-8"
    )

    identity = load_identity()
    created = datetime.now(timezone.utc).isoformat()
    name = os.path.basename(output) if output else f"unworldly-incident-{session.id}.zip"
    files["README.txt"] = _README.format(
        name=name,
        packager=fingerprint(identity.public_hex),
        session_id=session.id,
        created=created,
        version=__version__,
    ).encode("utf-8")

    manifest: dict[str, Any] = {
        "format": PACKET_FORMAT,
        "created": created,
        "session": session.id,
        "files": {fname: _sha256(data) for fname, data in sorted(files.items())},
        "packager": {"identityKey": identity.public_hex, "keyStore": identity.store, "unworldly": __version__},
    }
    manifest["signature"] = identity.sign(_manifest_payload(manifest))

    out_path = output or name
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, data in sorted(files.items()):
            zf.writestr(fname, data)
        zf.writestr(MANIFEST, json.dumps(manifest, indent=2))
    return out_path


@dataclass
class PacketCheck:
    ok: bool = True
    packager_fingerprint: str | None = None
    session_status: str | None = None
    messages: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def verify_packet(path: str) -> PacketCheck:
    """Verify an incident packet without extracting it."""
    check = PacketCheck()

    def fail(msg: str) -> PacketCheck:
        check.ok = False
        check.problems.append(msg)
        return check

    try:
        zf = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        return fail(f"Not a readable zip file: {exc}")
    with zf:
        names = set(zf.namelist())
        if MANIFEST not in names:
            return fail("manifest.json is missing")
        try:
            manifest = json.loads(zf.read(MANIFEST))
            files: dict[str, str] = manifest["files"]
            key = manifest["packager"]["identityKey"]
        except (KeyError, ValueError, TypeError):
            return fail("manifest.json is malformed")
        if manifest.get("format") != PACKET_FORMAT:
            return fail(f"Unknown packet format: {manifest.get('format')!r}")

        if verify_signature(key, str(manifest.get("signature", "")), _manifest_payload(manifest)):
            check.packager_fingerprint = fingerprint(key)
            check.messages.append(f"Manifest signature valid (packager identity {check.packager_fingerprint})")
        else:
            fail("Manifest signature invalid: the manifest was altered or not signed by this key")

        extra = names - set(files) - {MANIFEST}
        missing = set(files) - names
        if extra:
            fail(f"Files added after packaging: {', '.join(sorted(extra))}")
        if missing:
            fail(f"Files removed after packaging: {', '.join(sorted(missing))}")
        for fname, digest in sorted(files.items()):
            if fname in names and _sha256(zf.read(fname)) != digest:
                fail(f"{fname} was modified after packaging")
        if check.ok:
            check.messages.append(f"All {len(files)} files match their signed hashes")

        if "session.json" in names:
            with tempfile.TemporaryDirectory() as tmp:
                session_file = os.path.join(tmp, "session.json")
                with open(session_file, "wb") as fh:
                    fh.write(zf.read("session.json"))
                if "session.journal.jsonl" in names:
                    with open(journal_path(session_file), "wb") as fh:
                        fh.write(zf.read("session.journal.jsonl"))
                try:
                    result = verify_session(load_session(session_file))
                except Exception as exc:
                    return fail(f"session.json could not be read: {exc}")
                check.session_status = result.status
                if result.valid:
                    check.messages.append(f"Session verification: {result.status.replace('_', ' ')}")
                    check.messages.extend(f"  {gap}" for gap in result.gaps)
                else:
                    fail(f"Session verification failed: {'; '.join(result.errors[:3])}")
        else:
            fail("session.json is missing")
    return check
