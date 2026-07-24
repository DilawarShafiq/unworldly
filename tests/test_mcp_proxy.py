"""Tests for the standalone MCP capture proxy (message-inspection core)."""

from unworldly.agent_trace import AgentTraceRecorder
from unworldly.mcp_proxy import MCPProxyInterceptor, parse_message
from unworldly.session import load_session
from unworldly.types import RiskLevel


class TestParseMessage:
    def test_parses_valid_jsonrpc(self):
        msg = parse_message('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}')
        assert msg is not None
        assert msg["method"] == "tools/call"

    def test_blank_and_malformed_return_none(self):
        assert parse_message("") is None
        assert parse_message("   ") is None
        assert parse_message("not json") is None

    def test_non_object_returns_none(self):
        assert parse_message("[1,2,3]") is None


class TestInterceptor:
    def _recorder(self, tmp_path):
        return AgentTraceRecorder(directory=str(tmp_path), agent_name="mcp", capture_source="mcp")

    def test_records_tools_call(self, tmp_path):
        rec = self._recorder(tmp_path)
        icept = MCPProxyInterceptor(rec)
        recorded = icept.observe(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "fs.delete", "arguments": {"path": "/x"}}}
        )
        assert recorded is True
        loaded = load_session(rec.close())
        assert loaded.summary.total_events == 1
        assert loaded.events[0].command.executable == "fs.delete"
        assert loaded.events[0].risk == RiskLevel.DANGER
        assert loaded.capture_source == "mcp"

    def test_ignores_non_tool_methods(self, tmp_path):
        rec = self._recorder(tmp_path)
        icept = MCPProxyInterceptor(rec)
        assert icept.observe({"method": "tools/list", "id": 2}) is False
        assert icept.observe({"method": "initialize", "id": 0}) is False
        assert load_session(rec.close()).summary.total_events == 0

    def test_tool_call_without_name_is_ignored(self, tmp_path):
        rec = self._recorder(tmp_path)
        assert MCPProxyInterceptor(rec).observe({"method": "tools/call", "params": {}}) is False

    def test_secrets_in_arguments_are_redacted(self, tmp_path):
        rec = self._recorder(tmp_path)
        MCPProxyInterceptor(rec).observe(
            {"method": "tools/call", "params": {"name": "auth", "arguments": {"token": "SUPERSECRET"}}}
        )
        raw = open(rec.close(), encoding="utf-8").read()
        assert "SUPERSECRET" not in raw
