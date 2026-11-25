"""Credential lineage (spec: specs/forensics-0.10/spec.md, L1).

Answers "which credential did the agent use, and where did it come from?" without ever
writing a secret down. At session start the recorder indexes credential values found in
credential files (in the project and well-known places in the home folder). Raw values
stay in memory for the session only; the session stores a random salt plus, per credential,
``{source, name, fingerprint}`` (HMAC-SHA256 of the value, truncated). When an indexed value
or variable name later shows up in a command, a tool call or a file the agent writes, the
event says which credential it was and where it came from.

Honest limit: a tool that reads a credential by itself (from its own config file or an env
var) without the value or name appearing in its command line can't be seen.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass
from typing import Any

from .agent_trace import SECRET_PATTERNS
from .risk import assess_risk, should_ignore
from .types import EventType, RiskLevel

MIN_VALUE_LENGTH = 12
MAX_FILE_BYTES = 256 * 1024
MAX_PROJECT_FILES = 200

HOME_SOURCES = [
    ".aws/credentials",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".docker/config.json",
    ".kube/config",
    ".config/gh/hosts.yml",
]
_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".unworldly",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
}

_SENSITIVE_NAME = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth|"
    r"client[_-]?secret|dsn|database[_-]?url|conn(ection)?[_-]?string)"
)
_ASSIGN = re.compile(r"""^\s*(?:export\s+)?["']?([A-Za-z_][\w.\-]*)["']?\s*[:=]\s*["']?([^"'\s#,]+)""")
_PLACEHOLDER = re.compile(r"(?i)(\$\{|<|your|example|changeme|placeholder|xxxx|dummy|\*\*\*|^true$|^false$|^null$)")


@dataclass
class Credential:
    source: str  # "path/in/project" or "~/.aws/credentials"
    name: str
    value: str  # in memory only, never serialized

    @property
    def ref(self) -> str:
        return f"{self.source}#{self.name}"


def _plausible(value: str) -> bool:
    return len(value) >= MIN_VALUE_LENGTH and not _PLACEHOLDER.search(value)


def extract(text: str, source: str) -> list[Credential]:
    """Credential values in one file's text: sensitive-named assignments and known key formats."""
    found: dict[str, Credential] = {}
    for line in text.splitlines():
        match = _ASSIGN.match(line)
        if match and _SENSITIVE_NAME.search(match.group(1)) and _plausible(match.group(2)):
            found.setdefault(match.group(2), Credential(source, match.group(1), match.group(2)))
        for kind, pattern in SECRET_PATTERNS:
            for hit in pattern.finditer(line):
                value = hit.group(0)
                if _plausible(value) and kind != "private key":
                    found.setdefault(value, Credential(source, kind, value))
    return list(found.values())


def _read(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


def _is_credential_file(rel: str) -> bool:
    result = assess_risk(rel, EventType.MODIFY)
    return result.level == RiskLevel.DANGER


class CredentialIndex:
    """In-memory index of this session's credentials. Thread-safe enough for appends."""

    def __init__(self, project: str, home: str | None = None, salt: str | None = None) -> None:
        self.project = project
        self.home = home if home is not None else os.path.expanduser("~")
        self.salt = salt or secrets.token_hex(16)
        self._by_value: dict[str, Credential] = {}
        self._names: dict[str, Credential] = {}
        self._mtimes: dict[str, float] = {}  # indexed project file -> mtime when read

    # -- building -----------------------------------------------------------------

    def add_text(self, text: str, source: str) -> None:
        for cred in extract(text, source):
            self._by_value.setdefault(cred.value, cred)
            self._names.setdefault(cred.name.upper(), cred)

    def index_file(self, rel: str) -> None:
        """(Re-)index one project file (call when a credential file changes)."""
        path = os.path.join(self.project, rel)
        text = _read(path)
        if text is not None:
            self.add_text(text, rel.replace(os.sep, "/"))
            with contextlib.suppress(OSError):
                self._mtimes[rel] = os.path.getmtime(path)

    def refresh(self) -> bool:
        """Cheaply pick up credential files created or changed since they were indexed.

        Called before each command is checked, so a credential written and used straight
        away is still recognised (the file watcher may not have delivered its event yet).
        Re-reads known credential files whose mtime changed, and looks for new credential
        files at the project root, where `.env` files live. Returns True if anything new
        was indexed.
        """
        before = len(self._by_value)
        candidates = set(self._mtimes)
        try:
            with os.scandir(self.project) as entries:
                for entry in entries:
                    if entry.is_file() and _is_credential_file(entry.name):
                        candidates.add(entry.name)
        except OSError:
            pass
        for rel in candidates:
            try:
                mtime = os.path.getmtime(os.path.join(self.project, rel))
            except OSError:
                continue
            if self._mtimes.get(rel) != mtime:
                self.index_file(rel)
        return len(self._by_value) != before

    def build(self) -> CredentialIndex:
        scanned = 0
        for root, dirs, files in os.walk(self.project):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in files:
                rel = os.path.relpath(os.path.join(root, name), self.project)
                if should_ignore(rel) or not _is_credential_file(rel):
                    continue
                self.index_file(rel)
                scanned += 1
                if scanned >= MAX_PROJECT_FILES:
                    break
            if scanned >= MAX_PROJECT_FILES:
                break
        for rel in HOME_SOURCES:
            path = os.path.join(self.home, *rel.split("/"))
            text = _read(path) if os.path.isfile(path) else None
            if text is not None:
                self.add_text(text, "~/" + rel)
        return self

    # -- querying -----------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._by_value)

    def fingerprint(self, value: str) -> str:
        return hmac.new(bytes.fromhex(self.salt), value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def used_values(self, text: str) -> list[Credential]:
        """Credentials whose raw value appears in ``text``."""
        return [cred for value, cred in self._by_value.items() if value in text]

    def redact(self, text: str) -> str:
        """Replace every indexed credential value with its name, so no raw value is ever stored."""
        for value in sorted(self._by_value, key=len, reverse=True):
            if value in text:
                text = text.replace(value, f"***{self._by_value[value].name}***")
        return text

    def used_values_by_ref(self, refs: list[str]) -> list[Credential]:
        wanted = set(refs)
        return [c for c in self._by_value.values() if c.ref in wanted]

    def referenced_names(self, text: str) -> list[Credential]:
        """Credentials referenced by variable name: $NAME, ${NAME}, %NAME%, $env:NAME."""
        hits: list[Credential] = []
        for match in re.finditer(r"\$\{?([A-Za-z_]\w*)\}?|%([A-Za-z_]\w*)%|\$env:([A-Za-z_]\w*)", text):
            name = (match.group(1) or match.group(2) or match.group(3) or "").upper()
            cred = self._names.get(name)
            if cred is not None and cred not in hits:
                hits.append(cred)
        return hits

    def summary(self) -> dict[str, Any]:
        """What the session stores: salt and fingerprints, never values."""
        return {
            "salt": self.salt,
            "credentials": [
                {"source": c.source, "name": c.name, "fingerprint": self.fingerprint(v)}
                for v, c in sorted(self._by_value.items(), key=lambda item: item[1].ref)
            ],
        }


def describe_use(kind: str, creds: list[Credential], where: str) -> tuple[RiskLevel, str, list[str]]:
    """(level, reason, refs) for credentials found in an event. ``kind`` is "value" or "name"."""
    refs = [c.ref for c in creds]
    names = ", ".join(f"`{c.name}` from `{c.source}`" for c in creds[:3])
    more = f" (+{len(creds) - 3} more)" if len(creds) > 3 else ""
    if kind == "value":
        return RiskLevel.DANGER, f"Credential {names}{more} used in {where}", refs
    return RiskLevel.CAUTION, f"Credential {names}{more} referenced in {where}", refs
