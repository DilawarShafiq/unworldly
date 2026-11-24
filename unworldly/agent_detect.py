"""AI agent identity detection for Unworldly.

Detects which AI agent is running by checking environment variables
and active processes. Supports 8 known agents.

ISO 42001 A.3.2: Establish clear accountability -- identify the agent.
"""

from __future__ import annotations

import os
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
        env_vars=["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE"],
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


# SDK/framework agents run in-process as libraries — no env var or child
# process. The honest signal is that their module is actually imported (in use),
# checked via sys.modules. Ordered most-specific first.
SDK_AGENT_MODULES: list[tuple[str, str]] = [
    ("claude_agent_sdk", "Claude Agent SDK"),
    ("google.adk", "Google ADK"),
    ("langgraph", "LangGraph"),
    ("crewai", "CrewAI"),
    ("autogen", "AutoGen"),
    ("llama_index", "LlamaIndex"),
    ("agents", "OpenAI Agents SDK"),  # the `openai-agents` package imports as `agents`
]


def detect_sdk_agent() -> AgentInfo | None:
    """Detect an in-process SDK/framework agent via imported modules.

    Only reports a framework whose module is actually imported (in ``sys.modules``)
    — "installed" is not the same as "in use", and a false identity claim would
    undermine the audit trail. Returns None if none is in use.
    """
    for module, name in SDK_AGENT_MODULES:
        if module in sys.modules:
            return AgentInfo(name=name, detected_via=f"python module: {module}")
    return None


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
                pid_text = os.environ.get("CLAUDE_PID", "") if agent.name == "Claude Code" else ""
                return AgentInfo(
                    name=agent.name,
                    pid=int(pid_text) if pid_text.isdigit() else None,
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
        import psutil

        return psutil.Process(os.getppid()).name() or None
    except Exception:
        return None


def _get_running_processes() -> list[str]:
    """Get a list of running process names."""
    try:
        import psutil

        names: list[str] = []
        for proc in psutil.process_iter(["name"]):
            name = proc.info.get("name")
            if name:
                names.append(name)
        return names
    except Exception:
        return []


def _stem(name: str) -> str:
    base = os.path.basename(name.replace("\\", "/")).lower()
    return base[:-4] if base.endswith(".exe") else base


def find_agent_roots(agent: AgentInfo | None) -> set[int]:
    """PIDs of the detected agent's own processes, used to attribute commands.

    Uses the agent's PID when known (e.g. Claude Code's ``CLAUDE_PID``) plus any
    running process whose executable name exactly matches the agent's known
    process names. Returns an empty set when no agent is known, so commands are
    never attributed by guesswork.
    """
    if agent is None:
        return set()
    roots: set[int] = set()
    if agent.pid:
        roots.add(agent.pid)
    signature = next((a for a in KNOWN_AGENTS if a.name == agent.name), None)
    if signature is None:
        return roots
    wanted = {_stem(n) for n in signature.process_names}
    try:
        import psutil

        for proc in psutil.process_iter(["pid", "name"]):
            if proc.info.get("name") and _stem(proc.info["name"]) in wanted:
                roots.add(int(proc.info["pid"]))
    except Exception:
        pass
    roots.discard(os.getpid())
    return roots


_MODEL_ENV_VARS = ("ANTHROPIC_MODEL", "CLAUDE_MODEL", "OPENAI_MODEL", "AIDER_MODEL")


def detect_model(roots: set[int] | None = None) -> str | None:
    """Best-effort model name: env vars, else a ``--model`` flag on the agent's command line.

    Never guessed: returns None when neither is present.
    """
    for var in _MODEL_ENV_VARS:
        value = os.environ.get(var)
        if value:
            return value
    if roots:
        try:
            import psutil

            for pid in roots:
                args = psutil.Process(pid).cmdline()
                for i, arg in enumerate(args):
                    if arg == "--model" and i + 1 < len(args):
                        return args[i + 1]
                    if arg.startswith("--model="):
                        return arg.split("=", 1)[1]
        except Exception:
            pass
    return None
