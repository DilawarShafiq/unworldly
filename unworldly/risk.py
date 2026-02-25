"""File risk assessment for Unworldly.

Classifies file changes as safe, caution, or danger based on path patterns.
Danger patterns are checked first, then caution, then safe.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .types import EventType, RiskLevel


@dataclass
class RiskResult:
    """Result of a risk assessment."""

    level: RiskLevel
    reason: str | None = None


# --- DANGER patterns: credential files, keys, secrets ---

DANGER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\.env$"), "Credential file accessed"),
    (re.compile(r"\.env\.[a-z]+$", re.IGNORECASE), "Environment config accessed"),
    (re.compile(r"\.pem$"), "Certificate/key file accessed"),
    (re.compile(r"\.key$"), "Private key file accessed"),
    (re.compile(r"\.p12$"), "Certificate file accessed"),
    (re.compile(r"\.pfx$"), "Certificate file accessed"),
    (re.compile(r"id_rsa"), "SSH private key accessed"),
    (re.compile(r"id_ed25519"), "SSH private key accessed"),
    (re.compile(r"id_ecdsa"), "SSH private key accessed"),
    (re.compile(r"\.keystore$"), "Keystore accessed"),
    (re.compile(r"\.jks$"), "Java keystore accessed"),
    (re.compile(r"credentials", re.IGNORECASE), "Credentials file accessed"),
    (re.compile(r"secret", re.IGNORECASE), "Secrets file accessed"),
    (re.compile(r"\.aws/"), "AWS credentials accessed"),
    (re.compile(r"\.azure/"), "Azure config accessed"),
    (re.compile(r"\.gcloud/"), "Google Cloud config accessed"),
    (re.compile(r"kubeconfig", re.IGNORECASE), "Kubernetes config accessed"),
    (re.compile(r"\.kube/"), "Kubernetes config accessed"),
    (re.compile(r"shadow$"), "System password file accessed"),
    (re.compile(r"passwd$"), "System user file accessed"),
]

# --- CAUTION patterns: dependency files, CI/CD, configs ---

CAUTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"package\.json$"), "Dependency manifest modified"),
    (re.compile(r"package-lock\.json$"), "Lock file modified"),
    (re.compile(r"yarn\.lock$"), "Lock file modified"),
    (re.compile(r"pnpm-lock\.yaml$"), "Lock file modified"),
    (re.compile(r"Gemfile\.lock$"), "Lock file modified"),
    (re.compile(r"requirements\.txt$"), "Python dependencies modified"),
    (re.compile(r"Pipfile\.lock$"), "Lock file modified"),
    (re.compile(r"go\.sum$"), "Go checksum modified"),
    (re.compile(r"Cargo\.lock$"), "Rust lock file modified"),
    (re.compile(r"Dockerfile", re.IGNORECASE), "Container config modified"),
    (re.compile(r"docker-compose", re.IGNORECASE), "Container orchestration modified"),
    (re.compile(r"\.github/workflows/"), "CI/CD pipeline modified"),
    (re.compile(r"\.gitlab-ci", re.IGNORECASE), "CI/CD pipeline modified"),
    (re.compile(r"Jenkinsfile", re.IGNORECASE), "CI/CD pipeline modified"),
    (re.compile(r"\.gitignore$"), "Git ignore rules modified"),
    (re.compile(r"\.gitattributes$"), "Git attributes modified"),
    (re.compile(r"nginx", re.IGNORECASE), "Server config modified"),
    (re.compile(r"\.htaccess$", re.IGNORECASE), "Server config modified"),
    (re.compile(r"webpack\.config", re.IGNORECASE), "Build config modified"),
    (re.compile(r"vite\.config", re.IGNORECASE), "Build config modified"),
    (re.compile(r"rollup\.config", re.IGNORECASE), "Build config modified"),
    (re.compile(r"tsconfig", re.IGNORECASE), "TypeScript config modified"),
    (re.compile(r"eslint", re.IGNORECASE), "Linter config modified"),
    (re.compile(r"prettier", re.IGNORECASE), "Formatter config modified"),
]

# --- IGNORE patterns: build artifacts, caches, etc. ---

IGNORE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"node_modules"),
    re.compile(r"\.git/"),
    re.compile(r"\.git$"),
    re.compile(r"dist/"),
    re.compile(r"build/"),
    re.compile(r"\.unworldly/"),
    re.compile(r"\.DS_Store"),
    re.compile(r"\.swp$"),
    re.compile(r"~$"),
    re.compile(r"\.tmp$"),
    re.compile(r"\.temp$"),
    re.compile(r"\.cache"),
    re.compile(r"__pycache__"),
    re.compile(r"\.pyc$"),
    re.compile(r"\.class$"),
    re.compile(r"\.o$"),
    re.compile(r"\.obj$"),
]


def should_ignore(file_path: str) -> bool:
    """Check if a file path should be ignored (build artifacts, caches, etc.)."""
    normalized = file_path.replace("\\", "/")
    return any(p.search(normalized) for p in IGNORE_PATTERNS)


def assess_risk(file_path: str, event_type: EventType) -> RiskResult:
    """Assess the risk level of a file change event.

    Checks danger patterns first, then caution, then defaults to safe.
    File deletions that don't match other patterns are flagged as caution.
    """
    normalized = file_path.replace("\\", "/")
    basename = os.path.basename(normalized)

    # Check danger patterns first (highest priority)
    for pattern, reason in DANGER_PATTERNS:
        if pattern.search(normalized) or pattern.search(basename):
            return RiskResult(level=RiskLevel.DANGER, reason=reason)

    # Then caution patterns
    for pattern, reason in CAUTION_PATTERNS:
        if pattern.search(normalized) or pattern.search(basename):
            return RiskResult(level=RiskLevel.CAUTION, reason=reason)

    # File deletions are caution by default
    if event_type == EventType.DELETE:
        return RiskResult(level=RiskLevel.CAUTION, reason="File deleted")

    return RiskResult(level=RiskLevel.SAFE)


def calculate_risk_score(safe: int, caution: int, danger: int) -> float:
    """Calculate a risk score from 0-10 based on event counts.

    Danger events are weighted much higher (10) than caution (3).
    """
    total = safe + caution + danger
    if total == 0:
        return 0.0
    score = ((caution * 3) + (danger * 10)) / total
    return min(10.0, round(score * 10) / 10)
