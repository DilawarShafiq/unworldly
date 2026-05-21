"""SARIF 2.1.0 export for Unworldly.

Generates GitHub Code Scanning compatible SARIF so Unworldly findings
appear natively in the GitHub Security tab alongside CodeQL results.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from .session import load_session
from .types import RiskLevel, Session

# SARIF severity mapping
_LEVEL = {
    RiskLevel.DANGER: "error",
    RiskLevel.CAUTION: "warning",
    RiskLevel.SAFE: "note",
}

# Rule definitions (one per risk reason category)
_RULES = [
    {
        "id": "UW001",
        "name": "CredentialFileModified",
        "shortDescription": {"text": "Credential or secret file modified"},
        "fullDescription": {"text": "An AI agent modified a file containing credentials, private keys, or secrets."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://github.com/DilawarShafiq/unworldly#risk-levels",
    },
    {
        "id": "UW002",
        "name": "DangerousCommandExecuted",
        "shortDescription": {"text": "Dangerous shell command executed"},
        "fullDescription": {"text": "An AI agent ran a shell command classified as dangerous (e.g. rm -rf, sudo, curl)."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://github.com/DilawarShafiq/unworldly#risk-levels",
    },
    {
        "id": "UW003",
        "name": "SensitiveFileModified",
        "shortDescription": {"text": "Sensitive configuration file modified"},
        "fullDescription": {"text": "An AI agent modified a sensitive config file (e.g. package.json, Dockerfile, CI/CD config)."},
        "defaultConfiguration": {"level": "warning"},
        "helpUri": "https://github.com/DilawarShafiq/unworldly#risk-levels",
    },
    {
        "id": "UW004",
        "name": "CautionCommandExecuted",
        "shortDescription": {"text": "Caution-level command executed"},
        "fullDescription": {"text": "An AI agent ran a command that warrants review (e.g. npm install, git push, docker run)."},
        "defaultConfiguration": {"level": "warning"},
        "helpUri": "https://github.com/DilawarShafiq/unworldly#risk-levels",
    },
    {
        "id": "UW005",
        "name": "FileDeleted",
        "shortDescription": {"text": "File deleted by agent"},
        "fullDescription": {"text": "An AI agent deleted a file during its session."},
        "defaultConfiguration": {"level": "note"},
        "helpUri": "https://github.com/DilawarShafiq/unworldly#risk-levels",
    },
]


def _pick_rule(event_type: str, risk: RiskLevel, reason: str | None) -> str:
    """Select the best matching rule ID for an event."""
    reason_lower = (reason or "").lower()
    if event_type == "command":
        return "UW002" if risk == RiskLevel.DANGER else "UW004"
    if risk == RiskLevel.DANGER:
        return "UW001"
    if risk == RiskLevel.CAUTION:
        return "UW003"
    if event_type == "delete":
        return "UW005"
    return "UW003"


def _to_sarif(session: Session) -> dict:  # type: ignore[type-arg]
    """Convert a session to SARIF 2.1.0 structure."""
    results = []
    for i, event in enumerate(session.events):
        if event.risk == RiskLevel.SAFE:
            continue  # omit safe events — keep SARIF signal-to-noise high

        rule_id = _pick_rule(event.type.value, event.risk, event.reason)
        level = _LEVEL[event.risk]

        # Build location — file events have a real path, commands get a virtual URI
        if event.type.value == "command":
            uri = "agent://command"
        else:
            # Make path relative and use forward slashes for SARIF
            uri = event.path.replace("\\", "/")

        message_text = event.reason or f"{event.type.value.upper()} — {event.path}"

        result: dict = {  # type: ignore[type-arg]
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "unworldly/sessionId": session.id,
                "unworldly/eventIndex": i,
                "unworldly/timestamp": event.timestamp,
                "unworldly/riskScore": session.summary.risk_score,
            },
        }

        if session.agent:
            result["properties"]["unworldly/agent"] = session.agent.name

        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Unworldly",
                        "version": "0.5.0",
                        "informationUri": "https://github.com/DilawarShafiq/unworldly",
                        "rules": _RULES,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": session.start_time,
                        "endTimeUtc": session.end_time or session.start_time,
                        "properties": {
                            "unworldly/sessionId": session.id,
                            "unworldly/directory": session.directory,
                            "unworldly/riskScore": session.summary.risk_score,
                            "unworldly/agent": session.agent.name if session.agent else "unknown",
                        },
                    }
                ],
            }
        ],
    }


def export_sarif(session_path: str, output: str | None = None) -> None:
    """Export a session as a SARIF 2.1.0 file."""
    session = load_session(session_path)
    sarif = _to_sarif(session)

    out_path = output or f"unworldly-{session.id}.sarif"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    green = "\033[32m"
    gray = "\033[90m"
    white_bold = "\033[1;37m"
    reset = "\033[0m"

    findings = len(sarif["runs"][0]["results"])
    print(f"\n  {green}✓ SARIF exported:{reset} {out_path}")
    print(f"  {white_bold}{findings}{reset} findings ({session.summary.danger} error, {session.summary.caution} warning)")
    print(f"  {gray}Upload to GitHub: gh code-scanning upload-results --sarif {out_path}{reset}\n")
