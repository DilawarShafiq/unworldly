"""AI agent identity detection for Unworldly.

Detects which AI agent is running by checking environment variables
and active processes. Supports 8 known agents.

ISO 42001 A.3.2: Establish clear accountability -- identify the agent.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field

from .types import AgentInfo


@dataclass
class AgentSignature:
    """Known signature for detecting a specific AI agent."""

    name: str
    env_vars: list[str] = field(default_factory=list)
    process_names: list[str] = field(default_factory=list)
    parent_process_names: list[str] = field(default_factory=list)


KNOWN_AGENTS: list[AgentSignature] = [
    AgentSignature(
        name="Claude Code",
        env_vars=["CLAUDE_CODE", "ANTHROPIC_API_KEY"],
        process_names=["claude"],
        parent_process_names=["claude"],
    ),
    AgentSignature(
        name="Cursor",
        env_vars=["CURSOR_SESSION", "CURSOR_TRACE_ID"],
        process_names=["cursor", "Cursor", "Cursor.exe"],
        parent_process_names=["cursor", "Cursor"],
    ),
    AgentSignature(
        name="GitHub Copilot",
        env_vars=["GITHUB_COPILOT", "COPILOT_AGENT"],
        process_names=["copilot-agent", "copilot"],
        parent_process_names=["copilot"],
    ),
    AgentSignature(
        name="Windsurf",
        env_vars=["WINDSURF_SESSION"],
        process_names=["windsurf", "Windsurf"],
        parent_process_names=["windsurf"],
    ),
    AgentSignature(
        name="Devin",
        env_vars=["DEVIN_SESSION", "DEVIN_API"],
        process_names=["devin"],
        parent_process_names=["devin"],
    ),
    AgentSignature(
        name="Aider",
        env_vars=["AIDER_MODEL"],
        process_names=["aider"],
        parent_process_names=["aider"],
    ),
    AgentSignature(
        name="OpenClaw",
        env_vars=["OPENCLAW_SESSION"],
        process_names=["openclaw"],
        parent_process_names=["openclaw"],
    ),
    AgentSignature(
        name="Cline",
        env_vars=["CLINE_SESSION"],
        process_names=["cline"],
        parent_process_names=["cline"],
    ),
]


def detect_agent() -> AgentInfo | None:
    """Detect which AI agent is running.

    Strategy 1: Check environment variables (fastest, most reliable).
    Strategy 2: Check parent process tree.
    Strategy 3: Check running processes.

    Returns None if no known agent is detected.
    """
    # Strategy 1: Check environment variables
    for agent in KNOWN_AGENTS:
        for env_var in agent.env_vars:
            if os.environ.get(env_var):
                return AgentInfo(
                    name=agent.name,
                    detected_via=f"environment variable: {env_var}",
                )

    # Strategy 2: Check parent process tree
    try:
        parent_info = _get_parent_process_name()
        if parent_info:
            for agent in KNOWN_AGENTS:
                for name in agent.parent_process_names:
                    if name.lower() in parent_info.lower():
                        return AgentInfo(
                            name=agent.name,
                            detected_via=f"parent process: {parent_info}",
                        )
    except Exception:
        pass  # Can't read parent process -- not critical

    # Strategy 3: Check running processes
    try:
        processes = _get_running_processes()
        for agent in KNOWN_AGENTS:
            for name in agent.process_names:
                if any(name.lower() in p.lower() for p in processes):
                    return AgentInfo(
                        name=agent.name,
                        detected_via=f"running process: {name}",
                    )
    except Exception:
        pass  # Can't list processes -- not critical

    return None


def _get_parent_process_name() -> str | None:
    """Get the parent process name."""
    try:
        ppid = os.getppid()
        if not ppid:
            return None

        if sys.platform == "win32":
            output = subprocess.check_output(
                f"wmic process where ProcessId={ppid} get Name /format:csv",
                encoding="utf-8",
                timeout=2,
                stderr=subprocess.DEVNULL,
                shell=True,
            )
            lines = [line for line in output.strip().split("\n") if line.strip()]
            if len(lines) >= 2:
                parts = lines[1].strip().split(",")
                return parts[-1].strip() or None
            return None
        else:
            output = subprocess.check_output(
                ["ps", "-p", str(ppid), "-o", "comm="],
                encoding="utf-8",
                timeout=2,
                stderr=subprocess.DEVNULL,
            )
            return output.strip() or None
    except Exception:
        return None


def _get_running_processes() -> list[str]:
    """Get a list of running process names."""
    try:
        if sys.platform == "win32":
            output = subprocess.check_output(
                "tasklist /fo csv /nh",
                encoding="utf-8",
                timeout=3,
                stderr=subprocess.DEVNULL,
                shell=True,
            )
            result = []
            for line in output.split("\n"):
                parts = line.split(",")
                if parts:
                    name = parts[0].replace('"', "").strip()
                    if name:
                        result.append(name)
            return result
        else:
            output = subprocess.check_output(
                ["ps", "-eo", "comm", "--no-headers"],
                encoding="utf-8",
                timeout=2,
                stderr=subprocess.DEVNULL,
            )
            return [line.strip() for line in output.split("\n") if line.strip()]
    except Exception:
        return []
