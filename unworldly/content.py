"""What changed inside files: before/after hashes and a redacted, size-capped diff.

Privacy rules (spec: specs/record-0.8/spec.md, R3):
- Danger-level files (credentials, keys, ``.env``, PHI…) get hashes only, never a diff.
- Binaries and files over the size caps get hashes only.
- Secrets in diff lines are redacted before anything is written to disk.
"""

from __future__ import annotations

import difflib
import hashlib
import os
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .agent_trace import find_secret, redact_text
from .types import EventType, RiskLevel

if TYPE_CHECKING:
    from .credentials import CredentialIndex

MAX_HASH_BYTES = 5 * 1024 * 1024  # larger files are recorded as "tooLarge"
MAX_TEXT_BYTES = 256 * 1024  # only text files up to this size are diffed
MAX_DIFF_LINES = 200
MAX_DIFF_CHARS = 16 * 1024
TOO_LARGE = "tooLarge"


@dataclass
class FileChange:
    before_hash: str | None = None
    after_hash: str | None = None
    diff: str | None = None
    secret: str | None = None  # kind of credential found in added lines (before redaction)
    canary: bool = False  # a planted canary value appeared in added lines
    credentials: list[str] = field(default_factory=list)  # refs of indexed credentials written into the file


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _as_text(data: bytes) -> str | None:
    if len(data) > MAX_TEXT_BYTES or b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _cap(diff_lines: list[str]) -> str:
    out: list[str] = []
    size = 0
    for i, line in enumerate(diff_lines):
        if i >= MAX_DIFF_LINES or size + len(line) > MAX_DIFF_CHARS:
            out.append(f"… diff truncated ({len(diff_lines) - i} more lines)\n")
            break
        out.append(line)
        size += len(line)
    return "".join(out)


class ContentTracker:
    """Remembers the last seen version of each file in a session to describe changes."""

    def __init__(
        self, abs_dir: str, canaries: list[str] | None = None, credentials: CredentialIndex | None = None
    ) -> None:
        self.abs_dir = abs_dir
        self.canaries = [c for c in (canaries or []) if c]
        self.credentials = credentials
        self._last: dict[str, tuple[str, str | None]] = {}  # rel path -> (hash, text or None)
        self._in_git: bool | None = None

    def _git_head(self, rel: str) -> bytes | None:
        """The file's last committed version, if the project is a git repo and it's tracked."""
        if self._in_git is False:
            return None
        try:
            if self._in_git is None:
                probe = subprocess.run(
                    ["git", "-C", self.abs_dir, "rev-parse", "--is-inside-work-tree"],
                    capture_output=True,
                    timeout=3,
                )
                self._in_git = probe.returncode == 0
                if not self._in_git:
                    return None
            shown = subprocess.run(
                ["git", "-C", self.abs_dir, "show", f"HEAD:./{rel.replace(os.sep, '/')}"],
                capture_output=True,
                timeout=3,
            )
            return shown.stdout if shown.returncode == 0 else None
        except Exception:
            self._in_git = False
            return None

    def describe(self, rel: str, event_type: EventType, risk: RiskLevel) -> FileChange:
        """Describe one file event. Never raises: on any error, records what it safely can."""
        change = FileChange()
        previous = self._last.get(rel)
        if event_type == EventType.DELETE:
            change.before_hash = previous[0] if previous else None
            self._last.pop(rel, None)
            return change
        path = os.path.join(self.abs_dir, rel)
        try:
            if os.path.getsize(path) > MAX_HASH_BYTES:
                change.after_hash = TOO_LARGE
                self._last.pop(rel, None)
                return change
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return change  # file vanished or is locked: record the event without content details
        change.after_hash = _sha256(data)
        text = _as_text(data)

        label = "previous"
        if previous is None and event_type == EventType.MODIFY:
            head = self._git_head(rel)
            if head is not None and len(head) <= MAX_HASH_BYTES:
                previous = (_sha256(head), _as_text(head))
                label = "last commit"
        if previous is not None:
            change.before_hash = previous[0]

        diffable = risk != RiskLevel.DANGER and text is not None
        if diffable and change.before_hash != change.after_hash:
            old_text = previous[1] if previous is not None else ("" if event_type == EventType.CREATE else None)
            if old_text is not None:
                lines = list(
                    difflib.unified_diff(
                        old_text.splitlines(keepends=True),
                        text.splitlines(keepends=True),  # type: ignore[union-attr]
                        fromfile=f"a/{rel} ({label})" if previous is not None else "/dev/null",
                        tofile=f"b/{rel}",
                        n=2,
                    )
                )
                if lines:
                    added = "".join(ln for ln in lines if ln.startswith("+") and not ln.startswith("+++"))
                    change.secret = find_secret(added)
                    change.canary = any(value in added for value in self.canaries)
                    if self.credentials is not None:
                        change.credentials = [c.ref for c in self.credentials.used_values(added)]
                    diff_text = _cap([ln if ln.endswith("\n") else ln + "\n" for ln in lines])
                    if self.credentials is not None:
                        diff_text = self.credentials.redact(diff_text)
                    change.diff = redact_text(diff_text)
        self._last[rel] = (change.after_hash, text if risk != RiskLevel.DANGER else None)
        return change
