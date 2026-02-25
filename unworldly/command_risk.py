"""Command risk assessment for Unworldly.

Classifies shell commands as safe, caution, or danger based on patterns.
Order: custom config > danger patterns > safe patterns > caution patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .types import RiskLevel


@dataclass
class CommandRiskResult:
    """Result of a command risk assessment."""
    level: RiskLevel
    reason: str


@dataclass
class CommandRiskPattern:
    """A pattern for matching commands to risk levels."""
    pattern: re.Pattern[str]
    risk: RiskLevel
    reason: str


@dataclass
class CommandRiskConfig:
    """Custom command risk configuration (allowlist/blocklist)."""
    allowlist: list[dict] = field(default_factory=list)
    blocklist: list[dict] = field(default_factory=list)


# --- DANGER patterns: destructive, privileged, network ---

DANGER_PATTERNS: list[CommandRiskPattern] = [
    CommandRiskPattern(re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--force.*--recursive|--recursive.*--force|-[a-zA-Z]*f[a-zA-Z]*r)\b"), RiskLevel.DANGER, "Destructive recursive deletion"),
    CommandRiskPattern(re.compile(r"\brm\s+-rf\b"), RiskLevel.DANGER, "Destructive recursive deletion"),
    CommandRiskPattern(re.compile(r"\bsudo\b"), RiskLevel.DANGER, "Elevated privilege command"),
    CommandRiskPattern(re.compile(r"\bcurl\b"), RiskLevel.DANGER, "Network request to external URL"),
    CommandRiskPattern(re.compile(r"\bwget\b"), RiskLevel.DANGER, "Network download from external URL"),
    CommandRiskPattern(re.compile(r"\bchmod\s+777\b"), RiskLevel.DANGER, "Setting world-writable permissions"),
    CommandRiskPattern(re.compile(r"\bchmod\s+\+s\b"), RiskLevel.DANGER, "Setting setuid/setgid bit"),
    CommandRiskPattern(re.compile(r"\bdd\s+"), RiskLevel.DANGER, "Low-level disk operation"),
    CommandRiskPattern(re.compile(r"\bmkfs\b"), RiskLevel.DANGER, "Filesystem format operation"),
    CommandRiskPattern(re.compile(r"\bkill\s+-9\b"), RiskLevel.DANGER, "Force-killing process"),
    CommandRiskPattern(re.compile(r"\bkill\s+-SIGKILL\b"), RiskLevel.DANGER, "Force-killing process"),
    CommandRiskPattern(re.compile(r"\bformat\b"), RiskLevel.DANGER, "Disk format operation"),
    CommandRiskPattern(re.compile(r"\bdel\s+/[fF]\s+/[sS]\b"), RiskLevel.DANGER, "Destructive recursive deletion (Windows)"),
    CommandRiskPattern(re.compile(r"\beval\b"), RiskLevel.DANGER, "Dynamic code execution"),
    CommandRiskPattern(re.compile(r"\bnc\s+-l\b"), RiskLevel.DANGER, "Opening network listener"),
    CommandRiskPattern(re.compile(r"\bssh\b.*@"), RiskLevel.DANGER, "Remote SSH connection"),
    CommandRiskPattern(re.compile(r"\bscp\b"), RiskLevel.DANGER, "Remote file copy"),
    CommandRiskPattern(re.compile(r"\bgit\s+push\s+--force\b"), RiskLevel.DANGER, "Force-pushing to remote repository"),
    CommandRiskPattern(re.compile(r"\bgit\s+reset\s+--hard\b"), RiskLevel.DANGER, "Hard reset discards changes"),
]

# --- CAUTION patterns: package installs, docker, permission changes ---

CAUTION_PATTERNS: list[CommandRiskPattern] = [
    CommandRiskPattern(re.compile(r"\bnpm\s+install\b"), RiskLevel.CAUTION, "Installing npm package"),
    CommandRiskPattern(re.compile(r"\bnpm\s+i\b"), RiskLevel.CAUTION, "Installing npm package"),
    CommandRiskPattern(re.compile(r"\bpip\s+install\b"), RiskLevel.CAUTION, "Installing Python package"),
    CommandRiskPattern(re.compile(r"\bbrew\s+install\b"), RiskLevel.CAUTION, "Installing Homebrew package"),
    CommandRiskPattern(re.compile(r"\bapt\s+install\b"), RiskLevel.CAUTION, "Installing system package"),
    CommandRiskPattern(re.compile(r"\bapt-get\s+install\b"), RiskLevel.CAUTION, "Installing system package"),
    CommandRiskPattern(re.compile(r"\byarn\s+add\b"), RiskLevel.CAUTION, "Installing yarn package"),
    CommandRiskPattern(re.compile(r"\bpnpm\s+add\b"), RiskLevel.CAUTION, "Installing pnpm package"),
    CommandRiskPattern(re.compile(r"\bgit\s+push\b"), RiskLevel.CAUTION, "Pushing to remote repository"),
    CommandRiskPattern(re.compile(r"\bdocker\s+run\b"), RiskLevel.CAUTION, "Running Docker container"),
    CommandRiskPattern(re.compile(r"\bdocker\s+exec\b"), RiskLevel.CAUTION, "Executing in Docker container"),
    CommandRiskPattern(re.compile(r"\bchmod\b"), RiskLevel.CAUTION, "Changing file permissions"),
    CommandRiskPattern(re.compile(r"\bchown\b"), RiskLevel.CAUTION, "Changing file ownership"),
    CommandRiskPattern(re.compile(r"\brm\b"), RiskLevel.CAUTION, "Deleting files"),
    CommandRiskPattern(re.compile(r"\bgit\s+checkout\s+--\b"), RiskLevel.CAUTION, "Discarding file changes"),
    CommandRiskPattern(re.compile(r"\bnpx\b"), RiskLevel.CAUTION, "Executing remote npm package"),
]

# --- SAFE patterns: read-only commands, standard dev tools ---

SAFE_PATTERNS: list[CommandRiskPattern] = [
    CommandRiskPattern(re.compile(r"\bgit\s+add\b"), RiskLevel.SAFE, "Staging files"),
    CommandRiskPattern(re.compile(r"\bgit\s+status\b"), RiskLevel.SAFE, "Checking git status"),
    CommandRiskPattern(re.compile(r"\bgit\s+diff\b"), RiskLevel.SAFE, "Viewing git diff"),
    CommandRiskPattern(re.compile(r"\bgit\s+log\b"), RiskLevel.SAFE, "Viewing git log"),
    CommandRiskPattern(re.compile(r"\bgit\s+branch\b"), RiskLevel.SAFE, "Managing branches"),
    CommandRiskPattern(re.compile(r"\bgit\s+stash\b"), RiskLevel.SAFE, "Stashing changes"),
    CommandRiskPattern(re.compile(r"\bls\b"), RiskLevel.SAFE, "Listing directory"),
    CommandRiskPattern(re.compile(r"\bcat\b"), RiskLevel.SAFE, "Reading file"),
    CommandRiskPattern(re.compile(r"\becho\b"), RiskLevel.SAFE, "Echoing output"),
    CommandRiskPattern(re.compile(r"\bpwd\b"), RiskLevel.SAFE, "Printing working directory"),
    CommandRiskPattern(re.compile(r"\bnode\b"), RiskLevel.SAFE, "Running Node.js"),
    CommandRiskPattern(re.compile(r"\bnpm\s+test\b"), RiskLevel.SAFE, "Running tests"),
    CommandRiskPattern(re.compile(r"\bnpm\s+run\s+build\b"), RiskLevel.SAFE, "Building project"),
    CommandRiskPattern(re.compile(r"\bnpm\s+run\s+dev\b"), RiskLevel.SAFE, "Running dev server"),
    CommandRiskPattern(re.compile(r"\bnpm\s+run\s+lint\b"), RiskLevel.SAFE, "Running linter"),
    CommandRiskPattern(re.compile(r"\btsc\b"), RiskLevel.SAFE, "Running TypeScript compiler"),
    CommandRiskPattern(re.compile(r"\bvitest\b"), RiskLevel.SAFE, "Running tests"),
    CommandRiskPattern(re.compile(r"\bmkdir\b"), RiskLevel.SAFE, "Creating directory"),
    CommandRiskPattern(re.compile(r"\bcp\b"), RiskLevel.SAFE, "Copying files"),
    CommandRiskPattern(re.compile(r"\bmv\b"), RiskLevel.SAFE, "Moving files"),
    CommandRiskPattern(re.compile(r"\bhead\b"), RiskLevel.SAFE, "Reading file head"),
    CommandRiskPattern(re.compile(r"\btail\b"), RiskLevel.SAFE, "Reading file tail"),
    CommandRiskPattern(re.compile(r"\bgrep\b"), RiskLevel.SAFE, "Searching content"),
    CommandRiskPattern(re.compile(r"\bfind\b"), RiskLevel.SAFE, "Finding files"),
]


def assess_command_risk(
    executable: str,
    args: list[str],
    config: Optional[CommandRiskConfig] = None,
) -> CommandRiskResult:
    """Assess the risk level of a shell command.

    Check order: custom config (allowlist then blocklist) > danger > safe > caution.
    Unknown commands default to safe.
    """
    full_command = " ".join([executable] + args)

    # Check custom config patterns first (allowlist then blocklist)
    if config is not None:
        for entry in config.allowlist:
            if re.search(entry["pattern"], full_command):
                return CommandRiskResult(
                    level=RiskLevel(entry["risk"]),
                    reason=entry["reason"],
                )
        for entry in config.blocklist:
            if re.search(entry["pattern"], full_command):
                return CommandRiskResult(
                    level=RiskLevel(entry["risk"]),
                    reason=entry["reason"],
                )

    # Check danger patterns first (highest priority)
    for crp in DANGER_PATTERNS:
        if crp.pattern.search(full_command):
            return CommandRiskResult(level=RiskLevel.DANGER, reason=crp.reason)

    # Then safe patterns (before caution, to allow specific safe overrides)
    for crp in SAFE_PATTERNS:
        if crp.pattern.search(full_command):
            return CommandRiskResult(level=RiskLevel.SAFE, reason=crp.reason)

    # Then caution patterns
    for crp in CAUTION_PATTERNS:
        if crp.pattern.search(full_command):
            return CommandRiskResult(level=RiskLevel.CAUTION, reason=crp.reason)

    # Unknown commands default to safe
    return CommandRiskResult(level=RiskLevel.SAFE, reason="Standard command")
