"""`unworldly doctor` — honest, per-machine capture diagnostics.

Tells you which capture layers will actually work *on this machine* and, just as
importantly, what they will NOT see — so a sealed audit trail is never mistaken
for a complete one. See the capture-layer model in
``specs/agent-instrumentation/spec.md``.
"""

from __future__ import annotations

import importlib.util
import platform
import shutil
import sys
from dataclasses import dataclass, field

from .shell_hook import LOG_FILENAME, detect_shell, is_installed, rc_path

OK = "ok"
WARN = "warn"
INFO = "info"


@dataclass
class Check:
    """One diagnostic line."""

    name: str
    status: str  # OK | WARN | INFO
    detail: str


@dataclass
class DoctorReport:
    """Result of a doctor run."""

    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str) -> None:
        self.checks.append(Check(name=name, status=status, detail=detail))

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.status == WARN]


def _has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def run_doctor(directory: str = ".") -> DoctorReport:
    """Assess capture capability on this machine. Pure/testable — no printing."""
    report = DoctorReport()

    # Environment
    report.add(
        "Platform",
        INFO,
        f"{platform.system()} {platform.release()} · Python {sys.version.split()[0]}",
    )

    # L1 — filesystem
    if _has_module("watchdog"):
        report.add("L1 file capture", OK, "watchdog present — file changes are captured reliably")
    else:
        report.add("L1 file capture", WARN, "watchdog not importable — file changes will NOT be captured")

    # L1 — command capture (poll mode)
    is_windows = sys.platform == "win32"
    poll_tool = "wmic" if is_windows else "ps"
    if shutil.which(poll_tool):
        report.add(
            "L1 command capture (poll)",
            WARN,
            f"`{poll_tool}` present, but poll mode is best-effort — short-lived commands can be missed. "
            "Use the shell hook for lossless capture.",
        )
    else:
        extra = " (wmic is removed on newer Windows)" if is_windows else ""
        report.add(
            "L1 command capture (poll)",
            WARN,
            f"`{poll_tool}` not found{extra} — poll mode will capture no commands. Install the shell hook.",
        )

    # L1 — command capture (shell hook)
    shell = detect_shell()
    if is_installed(shell):
        report.add(
            "L1 command capture (hook)",
            OK,
            f"{shell} hook installed ({rc_path(shell)}) — lossless. Run `unworldly watch --capture hook`.",
        )
    else:
        report.add(
            "L1 command capture (hook)",
            INFO,
            f"{shell} hook not installed — run `unworldly hook install` for lossless command capture. "
            f"The hook logs to .unworldly/{LOG_FILENAME}.",
        )

    # L2 / L3 — agent decision trail
    report.add(
        "L2/L3 tool-call capture",
        INFO,
        "Available for SDK/custom/MCP agents — wrap tools with AgentTraceRecorder/@trace_tool "
        "or MCPCaptureProxy. Not automatic; the agent code opts in.",
    )

    # L4 — OTel (not yet implemented)
    report.add(
        "L4 OpenTelemetry ingestion",
        INFO,
        "Planned — will capture no-code/cloud agents that export OTel GenAI spans. Not available yet.",
    )

    # HIPAA
    if _has_module("unworldly.hipaa_risk"):
        report.add("HIPAA PHI detection", INFO, "Available — enable with `--hipaa` or config `\"hipaa\": true`.")

    # Honest bottom line
    report.add(
        "What this machine will NOT see",
        INFO,
        "An agent's prompts/reasoning/LLM calls, in-process SDK tool calls without L2/L3 wrapping, "
        "and any cloud/no-code agent that runs off this machine.",
    )

    return report


_ICONS = {OK: ("\033[32m", "✓"), WARN: ("\033[33m", "!"), INFO: ("\033[90m", "·")}


def format_report(report: DoctorReport) -> str:
    """Render a DoctorReport for the terminal."""
    reset = "\033[0m"
    lines = ["", "  \033[1mUnworldly Doctor\033[0m — capture diagnostics", ""]
    for c in report.checks:
        color, icon = _ICONS.get(c.status, ("", "·"))
        lines.append(f"  {color}{icon}{reset} \033[1m{c.name}\033[0m: {c.detail}")
    n_warn = len(report.warnings)
    lines.append("")
    if n_warn:
        lines.append(f"  \033[33m{n_warn} warning(s)\033[0m — see above for how to close capture gaps.")
    else:
        lines.append("  \033[32mAll core capture layers healthy.\033[0m")
    lines.append("")
    return "\n".join(lines)
