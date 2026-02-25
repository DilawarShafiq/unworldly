"""Tests for terminal display formatting."""

from unworldly.display import (
    banner,
    format_event,
    replay_header,
    report_divider,
    session_summary,
    watch_header,
)
from unworldly.types import EventType, RiskLevel, SessionSummary


class TestDisplay:
    class TestBanner:
        def test_contain_unworldly(self):
            output = banner()
            assert "UNWORLDLY" in output

        def test_contain_version(self):
            output = banner()
            assert "v0.3.0" in output

        def test_contain_tagline(self):
            output = banner()
            assert "Flight Recorder" in output

    class TestWatchHeader:
        def test_contain_rec_indicator(self):
            output = watch_header("/test/dir")
            assert "REC" in output

        def test_contain_directory(self):
            output = watch_header("/my/project")
            assert "/my/project" in output

        def test_contain_ctrl_c_hint(self):
            output = watch_header("/test")
            assert "Ctrl+C" in output

    class TestFormatEvent:
        def test_contain_timestamp(self):
            output = format_event("14:23:01", EventType.CREATE, "src/index.ts", RiskLevel.SAFE)
            assert "14:23:01" in output

        def test_contain_file_path(self):
            output = format_event("14:23:01", EventType.MODIFY, "src/utils.ts", RiskLevel.SAFE)
            assert "src/utils.ts" in output

        def test_contain_reason_when_provided(self):
            output = format_event(
                "14:23:01",
                EventType.MODIFY,
                ".env",
                RiskLevel.DANGER,
                "Credential file accessed",
            )
            assert "Credential file accessed" in output

        def test_not_contain_reason_line_when_no_reason(self):
            output = format_event("14:23:01", EventType.CREATE, "file.ts", RiskLevel.SAFE)
            assert "┗━" not in output

        def test_handle_command_event_type(self):
            output = format_event(
                "14:23:01",
                EventType.COMMAND,
                "npm install lodash",
                RiskLevel.CAUTION,
                "Installing package",
            )
            assert "npm install lodash" in output
            assert "Installing package" in output

    class TestSessionSummary:
        def test_contain_event_counts(self):
            summary = SessionSummary(
                total_events=10,
                safe=7,
                caution=2,
                danger=1,
                risk_score=3.5,
            )
            output = session_summary(summary, "/path/to/session.json")
            assert "10" in output
            assert "7" in output
            assert "2" in output
            assert "1" in output

        def test_contain_risk_score(self):
            summary = SessionSummary(
                total_events=5,
                safe=5,
                caution=0,
                danger=0,
                risk_score=0,
            )
            output = session_summary(summary, "/path/to/session.json")
            assert "0/10" in output

        def test_contain_session_path(self):
            summary = SessionSummary(
                total_events=0,
                safe=0,
                caution=0,
                danger=0,
                risk_score=0,
            )
            output = session_summary(summary, "/my/session.json")
            assert "/my/session.json" in output

    class TestReplayHeader:
        def test_contain_replay(self):
            output = replay_header("abc123", "/test", "2026-01-01T00:00:00Z")
            assert "REPLAY" in output

        def test_contain_session_id(self):
            output = replay_header("abc12345", "/test", "2026-01-01T00:00:00Z")
            assert "abc12345" in output

        def test_contain_directory(self):
            output = replay_header("abc", "/my/project", "2026-01-01T00:00:00Z")
            assert "/my/project" in output

    class TestReportDivider:
        def test_return_a_string(self):
            output = report_divider()
            assert isinstance(output, str)
            assert len(output) > 0
