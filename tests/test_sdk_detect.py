"""Tests for in-process SDK agent detection."""

import sys
import types

import pytest

from unworldly.agent_detect import detect_sdk_agent
from unworldly.agent_trace import AgentTraceRecorder


@pytest.fixture
def fake_module(monkeypatch):
    """Inject a fake importable module into sys.modules for the duration of a test."""

    def _inject(name: str):
        # Register parent packages too (e.g. google for google.adk).
        parts = name.split(".")
        for i in range(1, len(parts) + 1):
            mod = ".".join(parts[:i])
            if mod not in sys.modules:
                monkeypatch.setitem(sys.modules, mod, types.ModuleType(mod))

    return _inject


class TestDetectSdkAgent:
    def test_none_when_no_sdk_imported(self, monkeypatch):
        # Ensure none of the known SDK modules are present.
        from unworldly.agent_detect import SDK_AGENT_MODULES

        for mod, _ in SDK_AGENT_MODULES:
            monkeypatch.delitem(sys.modules, mod, raising=False)
        assert detect_sdk_agent() is None

    def test_detects_langgraph(self, fake_module):
        fake_module("langgraph")
        info = detect_sdk_agent()
        assert info is not None
        assert info.name == "LangGraph"
        assert "langgraph" in info.detected_via

    def test_detects_openai_agents_sdk(self, fake_module, monkeypatch):
        from unworldly.agent_detect import SDK_AGENT_MODULES

        # Remove higher-priority modules so `agents` is the match.
        for mod, _ in SDK_AGENT_MODULES:
            if mod != "agents":
                monkeypatch.delitem(sys.modules, mod, raising=False)
        fake_module("agents")
        info = detect_sdk_agent()
        assert info is not None
        assert info.name == "OpenAI Agents SDK"

    def test_detects_google_adk_submodule(self, fake_module, monkeypatch):
        from unworldly.agent_detect import SDK_AGENT_MODULES

        for mod, _ in SDK_AGENT_MODULES:
            if mod != "google.adk":
                monkeypatch.delitem(sys.modules, mod, raising=False)
        fake_module("google.adk")
        info = detect_sdk_agent()
        assert info is not None
        assert info.name == "Google ADK"


class TestRecorderAutoLabels:
    def test_recorder_auto_labels_detected_sdk(self, tmp_path, fake_module, monkeypatch):
        from unworldly.agent_detect import SDK_AGENT_MODULES

        for mod, _ in SDK_AGENT_MODULES:
            if mod != "crewai":
                monkeypatch.delitem(sys.modules, mod, raising=False)
        fake_module("crewai")
        rec = AgentTraceRecorder(directory=str(tmp_path))  # no explicit agent_name
        assert rec.session.agent is not None
        assert rec.session.agent.name == "CrewAI"

    def test_explicit_name_wins_over_detection(self, tmp_path, fake_module):
        fake_module("langgraph")
        rec = AgentTraceRecorder(directory=str(tmp_path), agent_name="my-bot")
        assert rec.session.agent is not None
        assert rec.session.agent.name == "my-bot"
