"""Tool-call trace capture for SDK-built and custom agents (capture layer L2).

The filesystem + shell monitors (L1) only see what an agent does to the local
machine. Agents built with the OpenAI Agents SDK, Google ADK, Claude Agent SDK,
LangGraph, or a hand-rolled loop do most of their work as *in-process tool
calls* that never touch disk or spawn a shell — so L1 sees nothing.

:class:`AgentTraceRecorder` records those tool calls into a normal Unworldly
session, reusing the existing risk scoring, SHA-256 hash chain, and seal — so
``unworldly verify``, ``report``, and ``replay`` work on agent decision trails
exactly as they do on file/command events. It is framework-agnostic: wrap your
tool functions with :func:`trace_tool`, or call :meth:`record_tool_call`
directly.

Design note: tool calls are stored as ``COMMAND`` events (executable = tool
name) so the whole pipeline works unchanged. A dedicated ``TOOL`` event type is
tracked as an ADR candidate in ``specs/agent-instrumentation/spec.md``.
"""

from __future__ import annotations

import contextlib
import functools
import json
import os
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

from .session import add_event, create_session, ensure_sessions_dir, save_session
from .types import AgentInfo, CommandInfo, EventType, RiskLevel, Session, WatchEvent

_ARG_PREVIEW_LIMIT = 200

# Substrings that, in a tool name or its serialized arguments, imply intent.
_DANGER_HINTS = (
    "delete", "remove", "rmtree", "drop", "truncate", "destroy", "wipe",
    "exec", "shell", "spawn", "system", "eval", "sudo", "chmod",
    "secret", "credential", "token", "password", "private_key", "apikey", "api_key",
    "transfer", "wire", "payout", "refund",
)
_NETWORK_HINTS = ("http", "https", "fetch", "request", "curl", "webhook", "upload", "post", "send", "email")
_WRITE_HINTS = ("write", "create", "update", "insert", "put", "patch", "install", "deploy", "commit", "modify")
_READ_HINTS = ("read", "get", "list", "search", "query", "fetch_row", "select", "describe", "count")


def assess_tool_risk(tool: str, params: Any = None) -> tuple[RiskLevel, str]:
    """Heuristically score a tool call. Callers can override with an explicit risk.

    Precedence: danger hints → network → write → read → default caution.
    """
    haystack = tool.lower()
    if params is not None:
        try:
            haystack += " " + json.dumps(params, default=str).lower()
        except (TypeError, ValueError):
            haystack += " " + str(params).lower()

    for hint in _DANGER_HINTS:
        if hint in haystack:
            return RiskLevel.DANGER, f"Sensitive tool action: matches '{hint}'"
    for hint in _NETWORK_HINTS:
        if hint in haystack:
            return RiskLevel.DANGER, f"Network/egress tool action: matches '{hint}'"
    for hint in _WRITE_HINTS:
        if hint in haystack:
            return RiskLevel.CAUTION, f"State-changing tool action: matches '{hint}'"
    for hint in _READ_HINTS:
        if hint in haystack:
            return RiskLevel.SAFE, "Read-only tool action"
    return RiskLevel.CAUTION, "Unclassified tool action"


def _preview(params: Any) -> str:
    if params is None:
        return ""
    try:
        text = json.dumps(params, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        text = str(params)
    if len(text) > _ARG_PREVIEW_LIMIT:
        text = text[:_ARG_PREVIEW_LIMIT] + "…"
    return text


class AgentTraceRecorder:
    """Records an agent's tool calls into a sealed Unworldly session.

    Usable as a context manager::

        with AgentTraceRecorder(agent_name="my-agent") as rec:
            rec.record_tool_call("db.read", {"table": "users"})
    """

    def __init__(
        self,
        directory: str = ".",
        agent_name: str | None = None,
        tag: str | None = None,
        capture_source: str = "sdk-trace",
    ) -> None:
        self.abs_dir = os.path.abspath(directory)
        self.session: Session = create_session(self.abs_dir, tag=tag)
        self.session.capture_source = capture_source
        if agent_name:
            self.session.agent = AgentInfo(name=agent_name, detected_via=capture_source)
        ensure_sessions_dir(self.abs_dir)
        self.session_path: str = save_session(self.session, self.abs_dir)

    def record_tool_call(
        self,
        tool: str,
        params: Any = None,
        risk: RiskLevel | None = None,
        reason: str | None = None,
    ) -> WatchEvent:
        """Record a single tool invocation and return the recorded event.

        If ``risk`` is None, a heuristic risk is assigned (see
        :func:`assess_tool_risk`).
        """
        if risk is None:
            risk, heuristic_reason = assess_tool_risk(tool, params)
            reason = reason or heuristic_reason

        preview = _preview(params)
        command_str = f"{tool}({preview})" if preview else f"{tool}()"
        command = CommandInfo(
            executable=tool,
            args=[preview] if preview else [],
            cwd=self.abs_dir,
            pid=os.getpid(),
        )
        event = WatchEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            type=EventType.COMMAND,
            path=command_str,
            risk=risk,
            reason=reason,
            command=command,
        )
        add_event(self.session, event)
        self.session_path = save_session(self.session, self.abs_dir)
        return event

    def close(self) -> str:
        """Finalize and re-seal the session; return its path."""
        self.session_path = save_session(self.session, self.abs_dir)
        return self.session_path

    def __enter__(self) -> AgentTraceRecorder:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


F = TypeVar("F", bound=Callable[..., Any])


def trace_tool(recorder: AgentTraceRecorder, name: str | None = None) -> Callable[[F], F]:
    """Decorator that records each call to a tool function, then runs it.

    The tool's return value is passed through unchanged; a recording failure is
    swallowed so instrumentation never breaks the agent (Zero Interference).
    """

    def decorator(func: F) -> F:
        tool_name: str = name if name is not None else str(getattr(func, "__name__", "tool"))

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                params = kwargs if kwargs else (args[0] if len(args) == 1 else list(args))
                recorder.record_tool_call(tool_name, params)
            except Exception:
                pass  # never break the host agent
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


class MCPCaptureProxy:
    """Records tool calls routed through an MCP session, then forwards them (L3).

    Wraps any object exposing ``async call_tool(name, arguments)`` (e.g. an MCP
    ``ClientSession``). The call is recorded before being delegated; a downstream
    error is recorded too and then re-raised. Import-light: no `mcp` dependency
    here — you pass in your already-constructed session.
    """

    def __init__(self, session: Any, recorder: AgentTraceRecorder) -> None:
        self._session = session
        self._recorder = recorder

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        with contextlib.suppress(Exception):
            self._recorder.record_tool_call(name, arguments)
        return await self._session.call_tool(name, arguments)

    def __getattr__(self, item: str) -> Any:
        # Transparently delegate everything else to the wrapped session.
        return getattr(self._session, item)
