"""Unworldly — The Flight Recorder for AI Agents.

Records everything AI agents do on your system -- file changes AND shell
commands -- replays sessions like a DVR, flags dangerous behavior in
real-time, and produces tamper-proof, ISO 42001-compliant audit trails.
"""

from .agent_detect import detect_agent
from .command_monitor import CommandMonitor, create_command_monitor
from .command_risk import CommandRiskConfig, CommandRiskResult, assess_command_risk
from .config import MonitorConfig, load_config
from .integrity import VerifyResult, compute_session_hash, genesis_hash, hash_event, verify_session
from .replay import replay
from .report import report
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

__version__ = "0.3.0"

__all__ = [
    # Core functions
    "watch",
    "replay",
    "report",
    # Risk assessment
    "assess_risk",
    "calculate_risk_score",
    "should_ignore",
    "assess_command_risk",
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
]
