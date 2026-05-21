"""OWASP Agentic AI Top 10 (2026) mapping for Unworldly.

Maps session events to the OWASP Top 10 for Agentic Applications 2026
based on risk reasons and event types.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .types import Session, WatchEvent

# ── OWASP rule definitions ────────────────────────────────────────────────────

@dataclass
class OWASPRule:
    id: str          # e.g. "AA01"
    name: str
    description: str
    triggers: list[str]   # substrings matched against event.reason (case-insensitive)
    severity: str    # "critical" | "high" | "medium"


OWASP_RULES: list[OWASPRule] = [
    OWASPRule(
        id="AA01",
        name="Goal Hijacking",
        description="Agent redirected to unintended objectives via malicious inputs.",
        triggers=["eval", "injection", "shell=true", "exec(", "subprocess"],
        severity="critical",
    ),
    OWASPRule(
        id="AA02",
        name="Identity Confusion",
        description="Agent assumes incorrect identity or acts outside its authorization scope.",
        triggers=["impersonat", "identity", "as root", "become"],
        severity="high",
    ),
    OWASPRule(
        id="AA03",
        name="Tool Misuse",
        description="Agent uses legitimate tools destructively or outside intended scope.",
        triggers=["rm -rf", "dangerous: rm", "force delete", "mkfs", "dd if=", "shred", "wipe"],
        severity="critical",
    ),
    OWASPRule(
        id="AA04",
        name="Privilege Escalation",
        description="Agent gains elevated access beyond its defined permissions.",
        triggers=["sudo", "chmod 777", "dangerous: chmod", "su -", "doas", "runas", "privilege"],
        severity="critical",
    ),
    OWASPRule(
        id="AA05",
        name="Data Exfiltration",
        description="Agent unauthorizedly extracts or exposes sensitive data.",
        triggers=[
            "credential", "private key", ".env", ".pem", ".key", "secret", "token",
            "curl", "wget", "scp", "rsync", "outbound", "upload", "aws credentials",
            "azure credentials", "gcp credentials", "ssh key",
        ],
        severity="critical",
    ),
    OWASPRule(
        id="AA06",
        name="Resource Abuse",
        description="Agent consumes excessive system resources or kills critical processes.",
        triggers=["kill -9", "kill all", "pkill", "taskkill", "fork bomb", "resource"],
        severity="high",
    ),
    OWASPRule(
        id="AA07",
        name="Cascading Failures",
        description="Agent actions trigger a chain of unintended failures across systems.",
        triggers=["database", "drop table", "truncate", "delete from", "cascade"],
        severity="high",
    ),
    OWASPRule(
        id="AA08",
        name="Memory Poisoning",
        description="Agent's persistent memory or context is corrupted by malicious input.",
        triggers=["memory", "context", "cache poison", "inject"],
        severity="medium",
    ),
    OWASPRule(
        id="AA09",
        name="Rogue Behavior",
        description="Agent acts autonomously outside its defined goals or boundaries.",
        triggers=["git push --force", "force push", "git reset --hard", "deploy", "publish"],
        severity="high",
    ),
    OWASPRule(
        id="AA10",
        name="Supply Chain Compromise",
        description="Agent installs or uses compromised third-party packages or tools.",
        triggers=[
            "npm install", "pip install", "cargo install", "apt install",
            "brew install", "yarn add", "gem install", "dependency", "package install",
        ],
        severity="medium",
    ),
]


# ── Mapping logic ─────────────────────────────────────────────────────────────

@dataclass
class OWASPFinding:
    rule: OWASPRule
    events: list[WatchEvent] = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return len(self.events) > 0


def map_session(session: Session) -> list[OWASPFinding]:
    """Map a session's events to OWASP Agentic AI Top 10 findings."""
    findings = {rule.id: OWASPFinding(rule=rule) for rule in OWASP_RULES}

    for event in session.events:
        reason = (event.reason or "").lower()
        path = event.path.lower()
        combined = f"{reason} {path}"

        for rule in OWASP_RULES:
            if any(t in combined for t in rule.triggers):
                findings[rule.id].events.append(event)

    return list(findings.values())


def owasp_terminal_report(findings: list[OWASPFinding]) -> str:
    """Render OWASP findings as a terminal string."""
    red_bold = "\033[1;31m"
    yellow = "\033[33m"
    green_bold = "\033[1;32m"
    gray = "\033[90m"
    white_bold = "\033[1;37m"
    cyan = "\033[36m"
    reset = "\033[0m"

    lines = [
        "",
        f"{white_bold}  OWASP Agentic AI Top 10 — 2026{reset}",
        f"{gray}  {'─' * 56}{reset}",
        "",
    ]

    triggered = [f for f in findings if f.triggered]
    clean = [f for f in findings if not f.triggered]

    if triggered:
        lines.append(f"{red_bold}  Risks Detected:{reset}")
        for f in triggered:
            sev_color = red_bold if f.rule.severity == "critical" else yellow
            lines.append(
                f"  {sev_color}[{f.rule.id}]{reset} {white_bold}{f.rule.name}{reset}"
                f"  {gray}({f.rule.severity}){reset}  {cyan}{len(f.events)} event(s){reset}"
            )
            lines.append(f"       {gray}{f.rule.description}{reset}")
        lines.append("")

    if clean:
        lines.append(f"{green_bold}  Not Triggered:{reset}")
        for f in clean:
            lines.append(f"  {green_bold}✓{reset} {gray}[{f.rule.id}] {f.rule.name}{reset}")
        lines.append("")

    coverage = len(triggered)
    lines.append(
        f"  {white_bold}Coverage:{reset} {coverage}/10 risks detected"
        f"  {gray}(lower is better){reset}\n"
    )
    return "\n".join(lines)


def owasp_markdown_section(findings: list[OWASPFinding]) -> str:
    """Render OWASP findings as a markdown section."""
    lines = [
        "## OWASP Agentic AI Top 10 — 2026\n",
        "| ID | Risk | Severity | Events | Status |",
        "|----|------|----------|--------|--------|",
    ]
    for f in findings:
        status = f"🚨 **{len(f.events)} triggered**" if f.triggered else "✅ Clean"
        lines.append(f"| {f.rule.id} | {f.rule.name} | {f.rule.severity} | {len(f.events)} | {status} |")

    triggered = [f for f in findings if f.triggered]
    if triggered:
        lines.append("\n### Triggered Risk Details\n")
        for f in triggered:
            lines.append(f"**[{f.rule.id}] {f.rule.name}** ({f.rule.severity})")
            lines.append(f"> {f.rule.description}\n")
            lines.append("| Time | Event | Path |")
            lines.append("|------|-------|------|")
            for e in f.events[:10]:
                from datetime import datetime
                t = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")).strftime("%H:%M:%S")
                lines.append(f"| {t} | {e.type.value.upper()} | `{e.path}` |")
            if len(f.events) > 10:
                lines.append(f"| … | … | *{len(f.events) - 10} more* |")
            lines.append("")

    return "\n".join(lines)
