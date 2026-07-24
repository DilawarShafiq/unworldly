"""Standalone MCP capture proxy (capture layer L3, zero agent code changes).

An agent talks to its MCP server over stdio (newline-delimited JSON-RPC 2.0).
Drop Unworldly *between* them:

    unworldly mcp-proxy -- python my_mcp_server.py

Every ``tools/call`` request the agent sends is recorded into a sealed,
hash-chained session (with risk scoring + secret redaction), then forwarded to
the real server unchanged. The agent needs no modification.

The message-inspection core (:class:`MCPProxyInterceptor`, :func:`parse_message`)
is pure and fully tested; the stdio pump is thin plumbing around it.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
from typing import Any

from .agent_trace import AgentTraceRecorder

CAPTURE_SOURCE = "mcp"


def parse_message(line: str) -> dict[str, Any] | None:
    """Parse one line of newline-delimited JSON-RPC into a dict, or None."""
    line = line.strip()
    if not line:
        return None
    try:
        msg = json.loads(line)
    except (TypeError, ValueError):
        return None
    return msg if isinstance(msg, dict) else None


class MCPProxyInterceptor:
    """Records ``tools/call`` requests seen on the client→server stream."""

    def __init__(self, recorder: AgentTraceRecorder) -> None:
        self.recorder = recorder

    def observe(self, message: dict[str, Any]) -> bool:
        """Record the message if it is a tool call. Returns True if recorded.

        Never raises — a recording failure must not break the proxied traffic.
        """
        if message.get("method") != "tools/call":
            return False
        params = message.get("params") or {}
        name = params.get("name")
        if not name:
            return False
        try:
            self.recorder.record_tool_call(str(name), params.get("arguments"))
            return True
        except Exception:
            return False


def run_stdio_proxy(
    target_cmd: list[str],
    directory: str = ".",
    agent_name: str | None = None,
) -> int:
    """Proxy stdio between this process and an MCP server subprocess, recording tool calls.

    Returns the target server's exit code.
    """
    recorder = AgentTraceRecorder(
        directory=directory,
        agent_name=agent_name or "mcp-proxy",
        capture_source=CAPTURE_SOURCE,
    )
    interceptor = MCPProxyInterceptor(recorder)

    proc = subprocess.Popen(  # noqa: S603 — target command is user-supplied by design
        target_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert proc.stdin is not None and proc.stdout is not None

    def pump_server_to_client() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()

    t = threading.Thread(target=pump_server_to_client, daemon=True)
    t.start()

    try:
        for line in sys.stdin:
            msg = parse_message(line)
            if msg is not None:
                interceptor.observe(msg)
            proc.stdin.write(line)
            proc.stdin.flush()
    finally:
        with contextlib.suppress(Exception):
            proc.stdin.close()
        proc.wait()
        recorder.close()
    return proc.returncode
