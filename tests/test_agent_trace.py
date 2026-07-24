"""Tests for tool-call trace capture (agent decision trail)."""

import asyncio

import pytest

from unworldly.agent_trace import (
    AgentTraceRecorder,
    MCPCaptureProxy,
    assess_tool_risk,
    trace_tool,
)
from unworldly.integrity import verify_session
from unworldly.session import load_session
from unworldly.types import EventType, RiskLevel


class TestAssessToolRisk:
    @pytest.mark.parametrize(
        "tool",
        ["fs.delete", "shell.exec", "db.drop_table", "secrets.get", "payments.transfer"],
    )
    def test_sensitive_tools_are_danger(self, tool):
        level, _ = assess_tool_risk(tool)
        assert level == RiskLevel.DANGER

    def test_network_tool_is_danger(self):
        level, _ = assess_tool_risk("http.post", {"url": "https://x.io"})
        assert level == RiskLevel.DANGER

    def test_write_tool_is_caution(self):
        level, _ = assess_tool_risk("db.update", {"table": "users"})
        assert level == RiskLevel.CAUTION

    def test_read_tool_is_safe(self):
        level, _ = assess_tool_risk("db.read", {"table": "users"})
        assert level == RiskLevel.SAFE

    def test_unknown_tool_defaults_caution(self):
        level, _ = assess_tool_risk("frobnicate")
        assert level == RiskLevel.CAUTION

    def test_danger_hint_in_params_wins(self):
        # tool name looks benign, but arguments reveal a private key
        level, _ = assess_tool_risk("store", {"data": "private_key material"})
        assert level == RiskLevel.DANGER


class TestAgentTraceRecorder:
    def test_records_tool_call_event(self, tmp_path):
        rec = AgentTraceRecorder(directory=str(tmp_path), agent_name="my-agent")
        event = rec.record_tool_call("db.read", {"table": "users"})
        assert event.type == EventType.COMMAND
        assert event.command is not None
        assert event.command.executable == "db.read"
        assert event.risk == RiskLevel.SAFE
        assert "db.read" in event.path

    def test_explicit_risk_overrides_heuristic(self, tmp_path):
        rec = AgentTraceRecorder(directory=str(tmp_path))
        event = rec.record_tool_call("db.read", {"t": 1}, risk=RiskLevel.DANGER, reason="policy")
        assert event.risk == RiskLevel.DANGER
        assert event.reason == "policy"

    def test_session_is_persisted_and_verifiable(self, tmp_path):
        with AgentTraceRecorder(directory=str(tmp_path), agent_name="a") as rec:
            rec.record_tool_call("db.read", {"table": "users"})
            rec.record_tool_call("fs.delete", {"path": "/tmp/x"})
            rec.record_tool_call("http.post", {"url": "https://api.example.com"})
            path = rec.session_path

        loaded = load_session(path)
        assert loaded.summary.total_events == 3
        assert loaded.summary.danger == 2
        assert loaded.capture_source == "sdk-trace"
        # Hash chain + seal must validate — same guarantee as file/command events
        result = verify_session(loaded)
        assert result.valid is True

    def test_agent_identity_recorded(self, tmp_path):
        with AgentTraceRecorder(directory=str(tmp_path), agent_name="ada") as rec:
            rec.record_tool_call("db.read")
            loaded = load_session(rec.session_path)
        assert loaded.agent is not None
        assert loaded.agent.name == "ada"


class TestTraceToolDecorator:
    def test_passthrough_return_value_and_records(self, tmp_path):
        rec = AgentTraceRecorder(directory=str(tmp_path))

        @trace_tool(rec, name="add")
        def add(a, b):
            return a + b

        assert add(2, 3) == 5
        loaded = load_session(rec.close())
        assert loaded.summary.total_events == 1
        assert loaded.events[0].command.executable == "add"

    def test_recording_failure_does_not_break_call(self, tmp_path):
        rec = AgentTraceRecorder(directory=str(tmp_path))

        # Force record to raise; the wrapped function must still run.
        def boom(*a, **k):
            raise RuntimeError("disk full")

        rec.record_tool_call = boom  # type: ignore[method-assign]

        @trace_tool(rec)
        def greet(name):
            return f"hi {name}"

        assert greet("sam") == "hi sam"


class TestMCPCaptureProxy:
    def test_records_and_forwards_call(self, tmp_path):
        calls = []

        class FakeSession:
            async def call_tool(self, name, arguments=None):
                calls.append((name, arguments))
                return {"ok": True}

        rec = AgentTraceRecorder(directory=str(tmp_path))
        proxy = MCPCaptureProxy(FakeSession(), rec)

        result = asyncio.run(proxy.call_tool("search", {"q": "cats"}))
        assert result == {"ok": True}
        assert calls == [("search", {"q": "cats"})]

        loaded = load_session(rec.close())
        assert loaded.summary.total_events == 1
        assert loaded.events[0].command.executable == "search"

    def test_delegates_unknown_attributes(self, tmp_path):
        class FakeSession:
            marker = 42

            async def call_tool(self, name, arguments=None):
                return None

        rec = AgentTraceRecorder(directory=str(tmp_path))
        proxy = MCPCaptureProxy(FakeSession(), rec)
        assert proxy.marker == 42
