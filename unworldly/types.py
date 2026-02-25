"""Core types for Unworldly — The Flight Recorder for AI Agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    """Risk level classification for events."""

    SAFE = "safe"
    CAUTION = "caution"
    DANGER = "danger"


class EventType(str, Enum):
    """Type of recorded event."""

    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    COMMAND = "command"


@dataclass
class CommandInfo:
    """Information about a captured shell command."""

    executable: str
    args: list[str]
    cwd: str
    pid: int
    exit_code: int | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "executable": self.executable,
            "args": self.args,
            "cwd": self.cwd,
            "pid": self.pid,
        }
        if self.exit_code is not None:
            result["exitCode"] = self.exit_code
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommandInfo:
        return cls(
            executable=data["executable"],
            args=data["args"],
            cwd=data["cwd"],
            pid=data["pid"],
            exit_code=data.get("exitCode"),
        )


@dataclass
class WatchEvent:
    """A single recorded event (file change or command execution)."""

    timestamp: str
    type: EventType
    path: str
    risk: RiskLevel
    reason: str | None = None
    command: CommandInfo | None = None
    hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "timestamp": self.timestamp,
            "type": self.type.value,
            "path": self.path,
            "risk": self.risk.value,
        }
        if self.reason is not None:
            result["reason"] = self.reason
        if self.command is not None:
            result["command"] = self.command.to_dict()
        if self.hash is not None:
            result["hash"] = self.hash
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WatchEvent:
        command = None
        if "command" in data and data["command"] is not None:
            command = CommandInfo.from_dict(data["command"])
        return cls(
            timestamp=data["timestamp"],
            type=EventType(data["type"]),
            path=data["path"],
            risk=RiskLevel(data["risk"]),
            reason=data.get("reason"),
            command=command,
            hash=data.get("hash"),
        )


@dataclass
class AgentInfo:
    """Information about a detected AI agent."""

    name: str
    pid: int | None = None
    version: str | None = None
    detected_via: str = ""

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "detectedVia": self.detected_via,
        }
        if self.pid is not None:
            result["pid"] = self.pid
        if self.version is not None:
            result["version"] = self.version
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentInfo:
        return cls(
            name=data["name"],
            pid=data.get("pid"),
            version=data.get("version"),
            detected_via=data.get("detectedVia", ""),
        )


@dataclass
class SessionSummary:
    """Summary statistics for a session."""

    total_events: int = 0
    safe: int = 0
    caution: int = 0
    danger: int = 0
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "totalEvents": self.total_events,
            "safe": self.safe,
            "caution": self.caution,
            "danger": self.danger,
            "riskScore": self.risk_score,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionSummary:
        return cls(
            total_events=data.get("totalEvents", 0),
            safe=data.get("safe", 0),
            caution=data.get("caution", 0),
            danger=data.get("danger", 0),
            risk_score=data.get("riskScore", 0.0),
        )


@dataclass
class Session:
    """A recorded session containing all events."""

    version: str
    id: str
    start_time: str
    end_time: str
    directory: str
    events: list[WatchEvent] = field(default_factory=list)
    summary: SessionSummary = field(default_factory=SessionSummary)
    agent: AgentInfo | None = None
    integrity_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "version": self.version,
            "id": self.id,
            "startTime": self.start_time,
            "endTime": self.end_time,
            "directory": self.directory,
            "events": [e.to_dict() for e in self.events],
            "summary": self.summary.to_dict(),
        }
        if self.agent is not None:
            result["agent"] = self.agent.to_dict()
        if self.integrity_hash is not None:
            result["integrityHash"] = self.integrity_hash
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        agent = None
        if "agent" in data and data["agent"] is not None:
            agent = AgentInfo.from_dict(data["agent"])
        return cls(
            version=data["version"],
            id=data["id"],
            start_time=data.get("startTime", ""),
            end_time=data.get("endTime", ""),
            directory=data["directory"],
            events=[WatchEvent.from_dict(e) for e in data.get("events", [])],
            summary=SessionSummary.from_dict(data.get("summary", {})),
            agent=agent,
            integrity_hash=data.get("integrityHash"),
        )
