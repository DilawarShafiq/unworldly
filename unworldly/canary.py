"""Canary tripwires (spec: specs/flag-0.9/spec.md, F5).

Opt-in only: nothing is planted unless the user runs ``unworldly canary plant``.
A decoy file with unique fake credentials is written into the project; if any of
those values later shows up in a command, a file the agent writes, or a tool call,
someone (or something) used the decoy, which nothing legitimate should do.

Honest limit: *reading* the decoy can't be seen by file watching; *using* its
values can.
"""

from __future__ import annotations

import json
import os
import secrets
import string
from datetime import datetime, timezone
from typing import Any

CANARY_FILE = ".unworldly/canaries.json"
DEFAULT_DECOY = ".env.canary"


def _random(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _registry_path(directory: str) -> str:
    return os.path.join(directory, *CANARY_FILE.split("/"))


def load(directory: str) -> list[dict[str, Any]]:
    """Planted canaries for this project: [{file, values, created}]."""
    path = _registry_path(directory)
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return [c for c in data.get("canaries", []) if isinstance(c, dict)]
    except (OSError, json.JSONDecodeError):
        return []


def canary_values(directory: str) -> list[str]:
    return [v for c in load(directory) for v in c.get("values", []) if isinstance(v, str) and len(v) >= 12]


def canary_files(directory: str) -> set[str]:
    return {str(c["file"]).replace("\\", "/") for c in load(directory) if c.get("file")}


def plant(directory: str, name: str = DEFAULT_DECOY) -> dict[str, Any]:
    """Write a decoy credentials file and register its values. Returns the canary record."""
    rel = name.replace("\\", "/")
    target = os.path.join(directory, *rel.split("/"))
    if os.path.exists(target):
        raise FileExistsError(f"{rel} already exists; choose another name with --name")
    upper = string.ascii_uppercase + string.digits
    mixed = string.ascii_letters + string.digits
    values = [
        "AKIA" + _random(upper, 16),
        _random(mixed + "/+", 40),
        "uwc_" + secrets.token_hex(16),
    ]
    content = (
        "# Production credentials (do not commit)\n"
        f"AWS_ACCESS_KEY_ID={values[0]}\n"
        f"AWS_SECRET_ACCESS_KEY={values[1]}\n"
        f"PAYMENTS_API_TOKEN={values[2]}\n"
    )
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(content)

    record = {"file": rel, "values": values, "created": datetime.now(timezone.utc).isoformat()}
    registry = load(directory) + [record]
    reg_path = _registry_path(directory)
    os.makedirs(os.path.dirname(reg_path), exist_ok=True)
    with open(reg_path, "w", encoding="utf-8") as fh:
        json.dump({"canaries": registry}, fh, indent=2)

    # Keep the decoy out of git, so pushing never trips a secret scanner.
    gitignore = os.path.join(directory, ".gitignore")
    if os.path.exists(gitignore):
        with open(gitignore, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        if rel not in lines:
            with open(gitignore, "a", encoding="utf-8") as fh:
                fh.write(("" if not lines or lines[-1] == "" else "\n") + f"{rel}\n")
    return record


def remove(directory: str) -> list[str]:
    """Delete all planted decoys and the registry. Returns the files removed."""
    removed: list[str] = []
    for c in load(directory):
        target = os.path.join(directory, *str(c.get("file", "")).split("/"))
        if c.get("file") and os.path.exists(target):
            os.remove(target)
            removed.append(str(c["file"]))
    reg_path = _registry_path(directory)
    if os.path.exists(reg_path):
        os.remove(reg_path)
    return removed


def used_in(text: str, values: list[str]) -> bool:
    return any(v in text for v in values)
