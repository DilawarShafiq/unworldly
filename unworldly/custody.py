"""Chain of custody: who ran the recording, where, and under whose authority.

Recorded once at session start as a signed checkpoint (see session.record_custody), so it
is tamper-resistant from the moment it is written. Facts only, all read locally:
- the OS user and machine,
- the process chain that started Unworldly (e.g. a terminal, an IDE, a CI runner),
- CI provenance when running in CI (who triggered the run, which workflow, which commit),
- the git identity configured for the project (who commits are attributed to),
- the agent identity as detected (name, PID, model).
"""

from __future__ import annotations

import getpass
import os
import platform
import subprocess
from typing import Any

from ._version import __version__
from .types import AgentInfo

# CI environment variables worth keeping (provenance of an automated run). Never secrets.
_CI_VARS = (
    "CI",
    "GITHUB_ACTIONS",
    "GITHUB_ACTOR",
    "GITHUB_TRIGGERING_ACTOR",
    "GITHUB_REPOSITORY",
    "GITHUB_WORKFLOW",
    "GITHUB_RUN_ID",
    "GITHUB_SHA",
    "GITHUB_REF",
    "GITLAB_CI",
    "GITLAB_USER_LOGIN",
    "CI_PIPELINE_ID",
    "CI_COMMIT_SHA",
    "BUILDKITE_BUILD_CREATOR",
    "CIRCLE_USERNAME",
    "JENKINS_URL",
    "BUILD_ID",
)


def _process_chain(limit: int = 5) -> list[str]:
    try:
        import psutil

        names: list[str] = []
        for parent in psutil.Process().parents()[:limit]:
            try:
                names.append(parent.name())
            except Exception:
                break
        return names
    except Exception:
        return []


def _git_identity(project: str) -> dict[str, str]:
    identity: dict[str, str] = {}
    for key in ("user.name", "user.email"):
        try:
            out = subprocess.run(
                ["git", "-C", project, "config", "--get", key], capture_output=True, text=True, timeout=3
            )
            if out.returncode == 0 and out.stdout.strip():
                identity[key.split(".")[1]] = out.stdout.strip()
        except Exception:
            break
    return identity


def collect_custody(project: str, agent: AgentInfo | None, capture: str | None = None) -> dict[str, Any]:
    """Custody facts for a session starting now in ``project``."""
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    custody: dict[str, Any] = {
        "osUser": user,
        "host": platform.node(),
        "platform": f"{platform.system()} {platform.release()}",
        "recorder": {"version": __version__, "pid": os.getpid(), "startedBy": _process_chain()},
        "project": project,
    }
    if capture:
        custody["capture"] = capture
    git = _git_identity(project)
    if git:
        custody["gitIdentity"] = git
    ci = {k: os.environ[k] for k in _CI_VARS if os.environ.get(k)}
    if ci:
        custody["ci"] = ci
    if agent is not None:
        custody["agent"] = agent.to_dict()
    return custody


def describe_custody(custody: dict[str, Any] | None) -> list[tuple[str, str]]:
    """Human-readable (label, value) rows for reports."""
    if not custody:
        return []
    rows: list[tuple[str, str]] = [("Run by", f"{custody.get('osUser', '?')} on {custody.get('host', '?')}")]
    started = custody.get("recorder", {}).get("startedBy") or []
    if started:
        rows.append(("Started from", " <- ".join(started)))
    git = custody.get("gitIdentity")
    if git:
        rows.append(("Git identity", f"{git.get('name', '?')} <{git.get('email', '?')}>"))
    ci = custody.get("ci")
    if ci:
        who = ci.get("GITHUB_TRIGGERING_ACTOR") or ci.get("GITHUB_ACTOR") or ci.get("GITLAB_USER_LOGIN") or "?"
        where = ci.get("GITHUB_REPOSITORY") or ci.get("CI_PIPELINE_ID") or ""
        rows.append(("CI run", f"triggered by {who} {where}".strip()))
    agent = custody.get("agent")
    if agent:
        model = f", model {agent['model']}" if agent.get("model") else ""
        pid = f", pid {agent['pid']}" if agent.get("pid") else ""
        rows.append(("Agent", f"{agent.get('name', '?')}{pid}{model}"))
    return rows
