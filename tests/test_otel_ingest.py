"""Tests for OpenTelemetry GenAI ingestion (capture layer L4)."""

import json

from unworldly.integrity import verify_session
from unworldly.otel_ingest import (
    extract_usage,
    ingest_file,
    span_to_event,
    spans_to_session,
)
from unworldly.session import load_session
from unworldly.types import EventType, RiskLevel


class TestSpanToEvent:
    def test_tool_span_by_attribute(self):
        span = {
            "name": "execute_tool",
            "attributes": {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "db.read",
                "gen_ai.tool.call.arguments": '{"table": "users"}',
            },
        }
        ev = span_to_event(span)
        assert ev is not None
        assert ev.type == EventType.COMMAND
        assert ev.command.executable == "db.read"
        assert ev.risk == RiskLevel.SAFE

    def test_tool_name_parsed_from_span_name(self):
        ev = span_to_event({"name": "execute_tool fs.delete", "attributes": {}})
        assert ev is not None
        assert ev.command.executable == "fs.delete"
        assert ev.risk == RiskLevel.DANGER  # delete → danger heuristic

    def test_model_span_is_safe_llm_event(self):
        span = {
            "name": "chat",
            "attributes": {"gen_ai.operation.name": "chat", "gen_ai.request.model": "gpt-x", "gen_ai.system": "openai"},
        }
        ev = span_to_event(span)
        assert ev is not None
        assert ev.path == "llm:gpt-x"
        assert ev.risk == RiskLevel.SAFE

    def test_non_genai_span_is_ignored(self):
        assert span_to_event({"name": "http GET /health", "attributes": {"http.method": "GET"}}) is None

    def test_secrets_in_tool_args_are_redacted(self):
        span = {
            "name": "execute_tool",
            "attributes": {
                "gen_ai.tool.name": "http.post",
                "gen_ai.tool.call.arguments": '{"api_key": "SUPERSECRET"}',
            },
        }
        ev = span_to_event(span)
        assert ev is not None
        assert "SUPERSECRET" not in (ev.path + " ".join(ev.command.args))

    def test_span_timestamp_is_preserved(self):
        ts = "2026-07-24T12:00:00Z"
        ev = span_to_event({"name": "execute_tool x", "attributes": {}, "timestamp": ts})
        assert ev is not None
        assert ev.timestamp == ts


class TestSpansToSession:
    def test_builds_verifiable_session(self, tmp_path):
        spans = [
            {"name": "chat", "attributes": {"gen_ai.operation.name": "chat", "gen_ai.request.model": "m"}},
            {"name": "execute_tool fs.delete", "attributes": {}},
            {"name": "noise", "attributes": {}},  # skipped
        ]
        session = spans_to_session(spans, directory=str(tmp_path), agent_name="otel-agent")
        assert session.summary.total_events == 2  # noise span skipped
        assert session.capture_source == "otel"
        assert session.agent.name == "otel-agent"
        # Verify the sealed session via reload
        loaded = load_session(_path(session, tmp_path))
        assert verify_session(loaded).valid is True
        assert loaded.summary.danger == 1

    def test_ingest_file_roundtrip(self, tmp_path):
        spans_file = tmp_path / "spans.json"
        spans_file.write_text(
            json.dumps([{"name": "execute_tool db.update", "attributes": {"gen_ai.tool.name": "db.update"}}]),
            encoding="utf-8",
        )
        session = ingest_file(str(spans_file), directory=str(tmp_path))
        assert session.summary.total_events == 1
        assert session.summary.caution == 1  # update → caution


class TestUsageTracking:
    def test_extract_usage_reads_tokens(self):
        span = {"attributes": {"gen_ai.usage.input_tokens": 100, "gen_ai.usage.output_tokens": 40}}
        assert extract_usage(span) == (100, 40)

    def test_extract_usage_missing_is_zero(self):
        assert extract_usage({"attributes": {}}) == (0, 0)

    def test_session_aggregates_token_usage(self, tmp_path):
        spans = [
            {"name": "chat", "attributes": {"gen_ai.operation.name": "chat",
             "gen_ai.request.model": "m", "gen_ai.usage.input_tokens": 100, "gen_ai.usage.output_tokens": 40}},
            {"name": "chat", "attributes": {"gen_ai.operation.name": "chat",
             "gen_ai.request.model": "m", "gen_ai.usage.input_tokens": 10, "gen_ai.usage.output_tokens": 5}},
        ]
        session = spans_to_session(spans, directory=str(tmp_path))
        assert session.usage == {"inputTokens": 110, "outputTokens": 45, "totalTokens": 155}

    def test_no_usage_when_no_tokens(self, tmp_path):
        session = spans_to_session([{"name": "execute_tool x", "attributes": {}}], directory=str(tmp_path))
        assert session.usage is None

    def test_usage_survives_reload(self, tmp_path):
        from unworldly.session import load_session

        spans = [{"name": "chat", "attributes": {"gen_ai.request.model": "m", "gen_ai.usage.input_tokens": 7}}]
        session = spans_to_session(spans, directory=str(tmp_path))
        loaded = load_session(_path(session, tmp_path))
        assert loaded.usage is not None
        assert loaded.usage["inputTokens"] == 7


def _path(session, tmp_path):
    return str(tmp_path / ".unworldly" / "sessions" / f"{session.id}.json")
