"""OpenTelemetry GenAI ingestion (capture layer L4).

Maps OpenTelemetry **GenAI** spans (`gen_ai.*`) — tool calls and model calls —
into Unworldly session events, so agents built on stacks that export OTel
(OpenAI Agents SDK, Google ADK, LangGraph) or no-code platforms with OTel export
produce the same sealed, risk-scored, hash-chained audit trail as local agents.

This module is intentionally dependency-light: it works on spans represented as
plain dicts::

    {"name": "execute_tool search", "attributes": {"gen_ai.tool.name": "search",
     "gen_ai.tool.call.arguments": "{\\"q\\": \\"cats\\"}"}, "timestamp": "..."}

so it can map spans decoded from an OTLP payload, a JSON export, or a live
receiver without pulling the OTel SDK into the core package. A live OTLP receiver
is separate, larger work (see ROADMAP / spec).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from .agent_trace import _preview, assess_tool_risk, redact_params
from .session import add_event, create_session, ensure_sessions_dir, save_session
from .types import AgentInfo, CommandInfo, EventType, RiskLevel, Session, WatchEvent

# OTel GenAI semantic-convention attribute keys.
GEN_AI_OP = "gen_ai.operation.name"
GEN_AI_TOOL = "gen_ai.tool.name"
GEN_AI_TOOL_ARGS = "gen_ai.tool.call.arguments"
GEN_AI_MODEL = "gen_ai.request.model"
GEN_AI_SYSTEM = "gen_ai.system"

CAPTURE_SOURCE = "otel"


def _parse_args(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return raw
    return raw


def _extract_tool_name(span: dict[str, Any], attrs: dict[str, Any]) -> str | None:
    tool = attrs.get(GEN_AI_TOOL)
    if tool:
        return str(tool)
    # Convention: span named "execute_tool <name>".
    name = str(span.get("name", ""))
    if name.startswith("execute_tool"):
        parts = name.split(None, 1)
        if len(parts) > 1:
            return parts[1].strip()
    return None


def span_to_event(span: dict[str, Any], redact: bool = True) -> WatchEvent | None:
    """Map one GenAI span to a WatchEvent, or None if it isn't a GenAI span."""
    attrs = span.get("attributes") or {}
    op = str(attrs.get(GEN_AI_OP, ""))
    timestamp = span.get("timestamp") or datetime.now(timezone.utc).isoformat()

    tool = _extract_tool_name(span, attrs)
    if op == "execute_tool" or tool:
        if not tool:
            return None
        params = _parse_args(attrs.get(GEN_AI_TOOL_ARGS))
        # Risk on original args; redact for storage (same contract as L2/L3).
        risk, reason = assess_tool_risk(tool, params)
        stored = redact_params(params) if redact else params
        preview = _preview(stored)
        return WatchEvent(
            timestamp=timestamp,
            type=EventType.COMMAND,
            path=f"{tool}({preview})" if preview else f"{tool}()",
            risk=risk,
            reason=reason,
            command=CommandInfo(executable=tool, args=[preview] if preview else [], cwd=".", pid=-1),
        )

    model = attrs.get(GEN_AI_MODEL)
    if op in ("chat", "text_completion", "generate_content") or model:
        system = str(attrs.get(GEN_AI_SYSTEM, "llm"))
        label = f"llm:{model or system}"
        return WatchEvent(
            timestamp=timestamp,
            type=EventType.COMMAND,
            path=label,
            risk=RiskLevel.SAFE,
            reason=f"LLM model call ({system})",
            command=CommandInfo(executable=label, args=[], cwd=".", pid=-1),
        )

    return None


def spans_to_session(
    spans: list[dict[str, Any]],
    directory: str = ".",
    agent_name: str | None = None,
    redact: bool = True,
    save: bool = True,
) -> Session:
    """Build a sealed Unworldly session from a list of GenAI spans.

    Non-GenAI spans are skipped. Events are hash-chained in the order given.
    """
    abs_dir = os.path.abspath(directory)
    session = create_session(abs_dir)
    session.capture_source = CAPTURE_SOURCE
    if agent_name:
        session.agent = AgentInfo(name=agent_name, detected_via=CAPTURE_SOURCE)

    for span in spans:
        event = span_to_event(span, redact=redact)
        if event is not None:
            add_event(session, event)

    if save:
        ensure_sessions_dir(abs_dir)
        save_session(session, abs_dir)
    return session


def ingest_file(path: str, directory: str = ".", agent_name: str | None = None) -> Session:
    """Load spans from a JSON file (array of spans, or {"spans": [...]}) → session."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    spans = data.get("spans", []) if isinstance(data, dict) else data
    return spans_to_session(spans, directory=directory, agent_name=agent_name)
