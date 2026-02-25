"""Configuration loader for Unworldly.

Loads custom command risk patterns from .unworldly/config.json.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field

from .command_risk import CommandRiskConfig


@dataclass
class MonitorConfig:
    """Top-level monitoring configuration."""
    commands: CommandRiskConfig = field(default_factory=CommandRiskConfig)


def _default_config() -> MonitorConfig:
    return MonitorConfig(commands=CommandRiskConfig(allowlist=[], blocklist=[]))


def load_config(base_dir: str) -> MonitorConfig:
    """Load configuration from .unworldly/config.json.

    Returns defaults if the file doesn't exist or is malformed.
    """
    config_path = os.path.join(base_dir, ".unworldly", "config.json")

    if not os.path.exists(config_path):
        return _default_config()

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            parsed = json.load(f)

        commands_data = parsed.get("commands", {})
        return MonitorConfig(
            commands=CommandRiskConfig(
                allowlist=commands_data.get("allowlist", []),
                blocklist=commands_data.get("blocklist", []),
            ),
        )
    except Exception:
        print(
            "Warning: Failed to parse .unworldly/config.json -- using defaults",
            file=sys.stderr,
        )
        return _default_config()
