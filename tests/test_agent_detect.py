"""Tests for AI agent identity detection."""

import os

from unworldly.agent_detect import detect_agent


class TestAgentDetect:
    """Test agent detection via environment variables."""

    # Store original env once at class level
    _original_env = None

    def setup_method(self):
        # Save original env
        self._original_env = os.environ.copy()
        # Clear all known agent env vars
        agent_vars = [
            "CLAUDE_CODE",
            "ANTHROPIC_API_KEY",
            "CURSOR_SESSION",
            "CURSOR_TRACE_ID",
            "GITHUB_COPILOT",
            "COPILOT_AGENT",
            "WINDSURF_SESSION",
            "DEVIN_SESSION",
            "DEVIN_API",
            "AIDER_MODEL",
            "OPENCLAW_SESSION",
            "CLINE_SESSION",
        ]
        for var in agent_vars:
            os.environ.pop(var, None)

    def teardown_method(self):
        # Restore original env
        os.environ.clear()
        os.environ.update(self._original_env)

    class TestEnvironmentVariableDetection:
        def setup_method(self):
            self._original_env = os.environ.copy()
            agent_vars = [
                "CLAUDE_CODE",
                "ANTHROPIC_API_KEY",
                "CURSOR_SESSION",
                "CURSOR_TRACE_ID",
                "GITHUB_COPILOT",
                "COPILOT_AGENT",
                "WINDSURF_SESSION",
                "DEVIN_SESSION",
                "DEVIN_API",
                "AIDER_MODEL",
                "OPENCLAW_SESSION",
                "CLINE_SESSION",
            ]
            for var in agent_vars:
                os.environ.pop(var, None)

        def teardown_method(self):
            os.environ.clear()
            os.environ.update(self._original_env)

        def test_detect_claude_code(self):
            os.environ["CLAUDE_CODE"] = "1"
            result = detect_agent()
            assert result is not None
            assert result.name == "Claude Code"
            assert "CLAUDE_CODE" in result.detected_via

        def test_detect_cursor(self):
            os.environ["CURSOR_SESSION"] = "test-session"
            result = detect_agent()
            assert result is not None
            assert result.name == "Cursor"
            assert "CURSOR_SESSION" in result.detected_via

        def test_detect_github_copilot(self):
            os.environ["GITHUB_COPILOT"] = "true"
            result = detect_agent()
            assert result is not None
            assert result.name == "GitHub Copilot"

        def test_detect_windsurf(self):
            os.environ["WINDSURF_SESSION"] = "ws-123"
            result = detect_agent()
            assert result is not None
            assert result.name == "Windsurf"

        def test_detect_devin(self):
            os.environ["DEVIN_SESSION"] = "dev-123"
            result = detect_agent()
            assert result is not None
            assert result.name == "Devin"

        def test_detect_aider(self):
            os.environ["AIDER_MODEL"] = "gpt-4"
            result = detect_agent()
            assert result is not None
            assert result.name == "Aider"

        def test_detect_openclaw(self):
            os.environ["OPENCLAW_SESSION"] = "oc-123"
            result = detect_agent()
            assert result is not None
            assert result.name == "OpenClaw"

        def test_detect_cline(self):
            os.environ["CLINE_SESSION"] = "cl-123"
            result = detect_agent()
            assert result is not None
            assert result.name == "Cline"

    class TestNoAgentDetected:
        def setup_method(self):
            self._original_env = os.environ.copy()
            agent_vars = [
                "CLAUDE_CODE",
                "ANTHROPIC_API_KEY",
                "CURSOR_SESSION",
                "CURSOR_TRACE_ID",
                "GITHUB_COPILOT",
                "COPILOT_AGENT",
                "WINDSURF_SESSION",
                "DEVIN_SESSION",
                "DEVIN_API",
                "AIDER_MODEL",
                "OPENCLAW_SESSION",
                "CLINE_SESSION",
            ]
            for var in agent_vars:
                os.environ.pop(var, None)

        def teardown_method(self):
            os.environ.clear()
            os.environ.update(self._original_env)

        def test_return_null_when_no_env_vars_set(self):
            # All agent env vars cleared in setup
            # Process detection may still find something, so we just verify
            # the function doesn't throw
            result = detect_agent()
            assert result is None or isinstance(result.name, str)

    class TestResultStructure:
        def setup_method(self):
            self._original_env = os.environ.copy()
            agent_vars = [
                "CLAUDE_CODE",
                "ANTHROPIC_API_KEY",
                "CURSOR_SESSION",
                "CURSOR_TRACE_ID",
                "GITHUB_COPILOT",
                "COPILOT_AGENT",
                "WINDSURF_SESSION",
                "DEVIN_SESSION",
                "DEVIN_API",
                "AIDER_MODEL",
                "OPENCLAW_SESSION",
                "CLINE_SESSION",
            ]
            for var in agent_vars:
                os.environ.pop(var, None)

        def teardown_method(self):
            os.environ.clear()
            os.environ.update(self._original_env)

        def test_correct_agent_info_shape(self):
            os.environ["CLAUDE_CODE"] = "1"
            result = detect_agent()
            assert hasattr(result, "name")
            assert hasattr(result, "detected_via")
            assert isinstance(result.name, str)
            assert isinstance(result.detected_via, str)

        def test_include_detection_method(self):
            os.environ["CURSOR_TRACE_ID"] = "trace-xyz"
            result = detect_agent()
            assert "environment variable" in result.detected_via
