"""Unworldly — The Flight Recorder for AI Agents.

Records everything AI agents do on your system -- file changes AND shell
commands -- replays sessions like a DVR, flags dangerous behavior in
real-time, and produces tamper-proof, ISO 42001-compliant audit trails.
"""

from .agent_detect import detect_agent
from .command_monitor import CommandMonitor, create_command_monitor
from .command_risk import CommandRiskConfig, CommandRiskResult, assess_command_risk
from .config import MonitorConfig, load_config
from .hipaa_risk import assess_hipaa_command_risk, assess_hipaa_file_risk
from .integrity import VerifyResult, compute_session_hash, genesis_hash, hash_event, verify_session
from .diff import diff_command
from .owasp import map_session as owasp_map_session
from .replay import replay
from .report import report
from .sarif import export_sarif
from .snapshot import snapshot_before, snapshot_after
from .agent_trace import (
    AgentTraceRecorder,
    MCPCaptureProxy,
    assess_tool_risk,
    redact_params,
    trace_tool,
)
from .mcp_proxy import MCPProxyInterceptor, parse_message, run_stdio_proxy
from .otel_ingest import ingest_file as otel_ingest_file
from .otel_ingest import extract_usage, span_to_event, spans_to_session
from .shell_hook import (
    ShellHookMonitor,
    create_shell_hook_monitor,
    install_hook,
    parse_hook_line,
    uninstall_hook,
)
from .risk import assess_risk, calculate_risk_score, should_ignore
from .types import (
    AgentInfo,
    CommandInfo,
    EventType,
    RiskLevel,
    Session,
    SessionSummary,
    WatchEvent,
)
from .watcher import watch

from ._version import __version__

__all__ = [
    "__version__",
    # Core functions
    "watch",
    "replay",
    "report",
    # Risk assessment
    "assess_risk",
    "calculate_risk_score",
    "should_ignore",
    "assess_command_risk",
    "assess_hipaa_file_risk",
    "assess_hipaa_command_risk",
    # Monitoring
    "CommandMonitor",
    "create_command_monitor",
    "load_config",
    "detect_agent",
    # Integrity
    "verify_session",
    "hash_event",
    "compute_session_hash",
    "genesis_hash",
    # Types
    "Session",
    "WatchEvent",
    "RiskLevel",
    "EventType",
    "SessionSummary",
    "CommandInfo",
    "AgentInfo",
    "CommandRiskResult",
    "CommandRiskConfig",
    "MonitorConfig",
    "VerifyResult",
    # v0.5.0
    "diff_command",
    "owasp_map_session",
    "export_sarif",
    "snapshot_before",
    "snapshot_after",
    # Shell-hook capture
    "ShellHookMonitor",
    "create_shell_hook_monitor",
    "install_hook",
    "uninstall_hook",
    "parse_hook_line",
    # Agent tool-call trace (L2/L3)
    "AgentTraceRecorder",
    "MCPCaptureProxy",
    "trace_tool",
    "assess_tool_risk",
    "redact_params",
    # OTel GenAI ingestion (L4)
    "span_to_event",
    "spans_to_session",
    "otel_ingest_file",
    "extract_usage",
    # MCP capture proxy (L3)
    "MCPProxyInterceptor",
    "parse_message",
    "run_stdio_proxy",
]
