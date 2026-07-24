"""Tests for capture-coverage provenance surfaced in reports (FR-007)."""

from unworldly.agent_trace import AgentTraceRecorder
from unworldly.report import _generate_markdown, capture_coverage
from unworldly.session import create_session


class TestCaptureCoverage:
    def test_none_is_filesystem_shell(self):
        label, note = capture_coverage(None)
        assert "Filesystem" in label
        assert "does not" in note.lower() or "not include" in note.lower()

    def test_sdk_trace_label(self):
        label, note = capture_coverage("sdk-trace")
        assert "SDK" in label
        assert note

    def test_mcp_label(self):
        label, _ = capture_coverage("mcp")
        assert "MCP" in label

    def test_unknown_source_is_passed_through(self):
        label, note = capture_coverage("custom-thing")
        assert label == "custom-thing"
        assert "custom-thing" in note

    def test_every_coverage_note_states_a_limitation(self):
        # The honesty contract: each note says what it does NOT capture.
        for src in (None, "sdk-trace", "mcp", "otel"):
            _, note = capture_coverage(src)
            assert any(w in note.lower() for w in ("does not", "not include", "depends"))


class TestReportShowsCoverage:
    def test_markdown_watch_session_states_coverage(self):
        session = create_session("/x")  # capture_source is None → watch coverage
        md = _generate_markdown(session)
        assert "## Capture Coverage" in md
        assert "Filesystem + shell" in md

    def test_markdown_trace_session_states_sdk_coverage(self, tmp_path):
        with AgentTraceRecorder(directory=str(tmp_path), agent_name="a") as rec:
            rec.record_tool_call("db.read", {"t": 1})
            session = rec.session
        md = _generate_markdown(session)
        assert "SDK tool-call trace" in md
