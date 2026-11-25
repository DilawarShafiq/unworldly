"""Behaviour flags computed from the signed record (spec: specs/flag-0.9/spec.md).

Findings are a pure, deterministic function of a session's events: they are never
stored, so rules can improve and be re-run on old sessions while the evidence stays
raw facts. The same ``FlagEngine`` runs live in ``watch`` (one event at a time) and
over a saved session (``find_flags``).
"""

from __future__ import annotations

import re
import shlex
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

from .packages import check_install
from .types import EventType, RiskLevel, Session, WatchEvent

WINDOW_SECONDS = 600.0  # sequence rules look back 10 minutes
MASS_DELETE_COUNT = 20
MASS_DELETE_SECONDS = 60.0
FLAIL_COUNT = 5
REWRITE_COUNT = 10
REWRITE_SECONDS = 300.0


@dataclass
class Finding:
    kind: str  # exfiltration | download-run | persistence | mass-delete | push-after-credentials |
    #            supply-chain | git | flailing | rewrites
    level: RiskLevel
    message: str
    events: list[int] = field(default_factory=list)  # 1-based event numbers involved

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "level": self.level.value, "message": self.message, "events": self.events}


_NETWORK = re.compile(
    r"\b(curl|wget|scp|sftp|ftp|nc|ncat|socat|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b|\bssh\b.*@|\brsync\b.*\S+:",
    re.IGNORECASE,
)
_DOWNLOAD = re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr)\b", re.IGNORECASE)
_PIPE_TO_SHELL = re.compile(
    r"\b(curl|wget|iwr|Invoke-WebRequest)\b.*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\biex\b.*\b(iwr|irm)\b", re.I
)
_RUN = re.compile(r"^(chmod\s+\+x|bash|sh|zsh|python3?|node|pwsh|powershell)\b|^\./", re.IGNORECASE)
_SECRET_PATH = re.compile(
    r"(\.env\b|id_rsa|id_ed25519|id_ecdsa|\.pem\b|\.key\b|credentials|\.aws[/\\]|\.ssh[/\\]|secret)", re.IGNORECASE
)
_READ_CMD = re.compile(r"^(cat|type|less|more|head|tail|Get-Content|gc|cp|copy|base64|xxd)\b", re.IGNORECASE)
_GIT_PUSH = re.compile(r"\bgit\s+push\b")

# Dangerous git operations (F3): (pattern, level, message)
_GIT_RULES: list[tuple[re.Pattern[str], RiskLevel, str]] = [
    (
        re.compile(r"\bgit\s+push\b.*(\s--force(-with-lease)?\b|\s-f\b)"),
        RiskLevel.DANGER,
        "Force-push rewrites remote history",
    ),
    (re.compile(r"\bgit\s+push\b.*(\s--delete\b|\s:\S+)"), RiskLevel.DANGER, "Deleting a remote branch"),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), RiskLevel.DANGER, "Hard reset discards uncommitted work"),
    (re.compile(r"\bgit\s+clean\s+-\w*f"), RiskLevel.DANGER, "git clean deletes untracked files"),
    (re.compile(r"\bgit\s+branch\s+(-D|--delete\s+--force)\b"), RiskLevel.DANGER, "Force-deleting a branch"),
    (re.compile(r"\bgit\s+(filter-branch|filter-repo)\b"), RiskLevel.DANGER, "Rewriting repository history"),
    (re.compile(r"\bgit\s+(checkout\s+--\s+\.|restore\s+\.)"), RiskLevel.CAUTION, "Discarding all local changes"),
    (re.compile(r"\bgit\s+rebase\b"), RiskLevel.CAUTION, "Rebase rewrites commits"),
    (re.compile(r"\bgit\s+commit\b.*(\s--no-verify\b|\s-n\b)"), RiskLevel.CAUTION, "Commit skipping git hooks"),
    (re.compile(r"\bgit\s+config\s+--global\b"), RiskLevel.CAUTION, "Changing global git config"),
]
_GIT_ADD = re.compile(r"\bgit\s+add\b(.*)")

# Production-destructive actions (blast radius), in command lines or tool-call arguments.
_BLAST_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bterraform\s+(destroy\b|apply\b.*\s-destroy\b)"), "Terraform destroy"),
    (re.compile(r"\b(pulumi|cdk)\s+destroy\b"), "Infrastructure stack destroy"),
    (
        re.compile(
            r"\bkubectl\s+delete\s+(ns|namespaces?|deploy(ment)?s?|statefulsets?|sts|pvc|pv|persistentvolume\w*)\b|\bkubectl\s+delete\b.*\s--all\b"
        ),
        "Kubernetes resources deleted",
    ),
    (re.compile(r"\bhelm\s+(uninstall|delete)\b"), "Helm release removed"),
    (re.compile(r"\baws\s+rds\s+delete-db-(instance|cluster)\b"), "AWS database deleted"),
    (re.compile(r"\baws\s+s3\s+rb\b|\baws\s+s3\s+rm\b.*--recursive"), "AWS S3 data deleted"),
    (re.compile(r"\baws\s+dynamodb\s+delete-table\b"), "AWS DynamoDB table deleted"),
    (re.compile(r"\baws\s+ec2\s+terminate-instances\b"), "AWS instances terminated"),
    (
        re.compile(r"\baws\s+(cloudformation\s+delete-stack|eks\s+delete-cluster|lambda\s+delete-function)\b"),
        "AWS resource deleted",
    ),
    (re.compile(r"\baws\s+iam\s+delete-"), "AWS IAM identity deleted"),
    (
        re.compile(
            r"\bgcloud\b.*\b(sql\s+instances|projects|container\s+clusters|compute\s+instances|storage\s+buckets)\s+delete\b|\bgsutil\s+(rm\s+-r|rb)\b"
        ),
        "Google Cloud resource deleted",
    ),
    (
        re.compile(r"\baz\s+group\s+delete\b|\baz\s+(sql|aks|storage|cosmosdb|postgres|mysql)\b.*\bdelete\b"),
        "Azure resource deleted",
    ),
    (
        re.compile(r"\brailway\s+(volume\s+delete|down|environment\s+delete|service\s+delete)\b"),
        "Railway resource deleted",
    ),
    (re.compile(r"\b(fly|flyctl)\s+(apps\s+destroy|volumes?\s+destroy|destroy)\b"), "Fly.io resource destroyed"),
    (re.compile(r"\bheroku\s+(apps:destroy|pg:reset)\b"), "Heroku app or database destroyed"),
    (re.compile(r"\bvercel\s+(remove|rm)\b"), "Vercel deployment removed"),
    (re.compile(r"\bsupabase\s+db\s+reset\b"), "Supabase database reset"),
    (re.compile(r"(?i)\bdrop\s+(table|database|schema)\b"), "SQL DROP"),
    (re.compile(r"(?i)\btruncate\s+(table\s+)?\w+"), "SQL TRUNCATE"),
    (re.compile(r"(?i)\bdelete\s+from\s+[\w.\"`]+\s*(;|$|\"|')"), "SQL DELETE without WHERE"),
    (re.compile(r"\bdropdb\b|\bredis-cli\b.*\bflush(all|db)\b|\bdropDatabase\s*\("), "Database wiped"),
    (
        re.compile(r"\bprisma\s+(migrate\s+reset|db\s+push\b.*--(force-reset|accept-data-loss))"),
        "Prisma reset (data loss)",
    ),
    (
        re.compile(r"\brails\s+db:(drop|reset)\b|\bmanage\.py\s+flush\b|\balembic\s+downgrade\s+base\b"),
        "Database reset by migration tool",
    ),
    (
        re.compile(r"\bdocker\s+system\s+prune\b.*(-a|--all).*--volumes|\bdocker\s+volume\s+(rm|prune)\b"),
        "Docker volumes deleted",
    ),
]
_PRODUCTION = re.compile(r"(?i)\bprod(uction)?\b")


def _ts(event: WatchEvent) -> float:
    try:
        return datetime.fromisoformat(event.timestamp.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _is_secret_file_event(event: WatchEvent) -> bool:
    return event.type != EventType.COMMAND and event.risk == RiskLevel.DANGER


def _reads_secret(cmd: str) -> bool:
    return bool(_READ_CMD.search(cmd) and _SECRET_PATH.search(cmd))


def _short(cmd: str, limit: int = 80) -> str:
    return cmd if len(cmd) <= limit else cmd[: limit - 1] + "…"


def _tokens(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


class FlagEngine:
    """Feed events in order; get the findings each one triggers (each fires once)."""

    def __init__(self) -> None:
        self._recent: deque[tuple[int, float, WatchEvent]] = deque()  # within WINDOW_SECONDS
        self._fired: set[tuple[object, ...]] = set()

    def _once(self, key: tuple[object, ...], finding: Finding, out: list[Finding]) -> None:
        if key not in self._fired:
            self._fired.add(key)
            out.append(finding)

    def process(self, number: int, event: WatchEvent) -> list[Finding]:
        """``number`` is the 1-based event number."""
        now = _ts(event)
        while self._recent and now - self._recent[0][1] > WINDOW_SECONDS:
            self._recent.popleft()
        out: list[Finding] = []
        if event.type == EventType.COMMAND:
            self._command_rules(number, now, event, out)
        else:
            self._file_rules(number, now, event, out)
        self._recent.append((number, now, event))
        return out

    # -- commands ---------------------------------------------------------------

    def _command_rules(self, number: int, now: float, event: WatchEvent, out: list[Finding]) -> None:
        cmd = event.path
        network = bool(_NETWORK.search(cmd))

        # F1: exfiltration — secret touched or read, then a network command
        if network:
            for n, _t, prior in self._recent:
                touched = _is_secret_file_event(prior) or (
                    prior.type == EventType.COMMAND and _reads_secret(prior.path)
                )
                if touched:
                    self._once(
                        ("exfiltration", n, number),
                        Finding(
                            "exfiltration",
                            RiskLevel.DANGER,
                            f"Possible exfiltration: `{_short(prior.path, 50)}` then network command `{_short(cmd)}`",
                            [n, number],
                        ),
                        out,
                    )
                    break

        # F1: download piped straight into a shell
        if _PIPE_TO_SHELL.search(cmd):
            self._once(
                ("download-run", number),
                Finding("download-run", RiskLevel.DANGER, f"Download piped into a shell: `{_short(cmd)}`", [number]),
                out,
            )
        # F1: download, then running a file created after it
        elif _RUN.search(cmd):
            targets = {t.replace("\\", "/").rsplit("/", 1)[-1] for t in _tokens(cmd)[1:] if not t.startswith("-")}
            for n, t_dl, prior in self._recent:
                if prior.type != EventType.COMMAND or not _DOWNLOAD.search(prior.path):
                    continue
                for m, t_file, created in self._recent:
                    if (
                        created.type == EventType.CREATE
                        and t_file >= t_dl
                        and created.path.replace("\\", "/").rsplit("/", 1)[-1] in targets
                    ):
                        self._once(
                            ("download-run", n, number),
                            Finding(
                                "download-run",
                                RiskLevel.DANGER,
                                f"Downloaded then ran `{created.path}` "
                                f"(`{_short(prior.path, 50)}` → `{_short(cmd, 50)}`)",
                                [n, m, number],
                            ),
                            out,
                        )

        # F1: persistence — startup file changed, then network (either order)
        if network:
            for n, _t, prior in self._recent:
                if "persistence" in (prior.reason or ""):
                    self._once(
                        ("persistence", n, number),
                        Finding(
                            "persistence",
                            RiskLevel.DANGER,
                            f"Startup file `{prior.path}` changed and network command `{_short(cmd)}` run",
                            [n, number],
                        ),
                        out,
                    )

        # F1: credentials outside the project changed, then git push
        if _GIT_PUSH.search(cmd):
            for n, _t, prior in self._recent:
                if prior.path.startswith("~/") and prior.risk == RiskLevel.DANGER:
                    self._once(
                        ("push-after-credentials", n, number),
                        Finding(
                            "push-after-credentials",
                            RiskLevel.DANGER,
                            f"`{prior.path}` changed, then `{_short(cmd)}`",
                            [n, number],
                        ),
                        out,
                    )
                    break

        # F2: supply chain
        for level, message in check_install(cmd):
            self._once(("supply-chain", number, message), Finding("supply-chain", level, message, [number]), out)

        # F3: dangerous git operations
        for pattern, level, message in _GIT_RULES:
            if pattern.search(cmd):
                self._once(
                    ("git", number, message), Finding("git", level, f"{message}: `{_short(cmd)}`", [number]), out
                )
                break
        added = _GIT_ADD.search(cmd)
        if added and _SECRET_PATH.search(added.group(1)):
            self._once(
                ("git", number, "add-secret"),
                Finding("git", RiskLevel.DANGER, f"Staging a secret file for commit: `{_short(cmd)}`", [number]),
                out,
            )

        # Blast radius: production-destructive infrastructure / data actions
        for pattern, label in _BLAST_RULES:
            if pattern.search(cmd):
                where = " on PRODUCTION" if _PRODUCTION.search(cmd) else ""
                self._once(
                    ("blast-radius", number),
                    Finding("blast-radius", RiskLevel.DANGER, f"{label}{where}: `{_short(cmd)}`", [number]),
                    out,
                )
                break

        # Credential lineage: first use of each credential
        for ref in event.credentials or []:
            source, _, name = ref.rpartition("#")
            self._once(
                ("credential-use", ref),
                Finding(
                    "credential-use",
                    event.risk if event.risk != RiskLevel.SAFE else RiskLevel.CAUTION,
                    f"Credential `{name}` from `{source}` used: `{_short(cmd)}`",
                    [number],
                ),
                out,
            )

        # F6: flailing — the same command repeated
        normalised = " ".join(cmd.split())
        same = [
            n
            for n, _t, prior in self._recent
            if prior.type == EventType.COMMAND and " ".join(prior.path.split()) == normalised
        ]
        if len(same) + 1 == FLAIL_COUNT:
            self._once(
                ("flailing", normalised, same[0]),
                Finding(
                    "flailing",
                    RiskLevel.CAUTION,
                    f"Agent may be stuck: `{_short(cmd)}` run {FLAIL_COUNT} times "
                    f"in {int(WINDOW_SECONDS // 60)} minutes",
                    [*same, number],
                ),
                out,
            )

    # -- files ------------------------------------------------------------------

    def _file_rules(self, number: int, now: float, event: WatchEvent, out: list[Finding]) -> None:
        for ref in event.credentials or []:
            source, _, name = ref.rpartition("#")
            self._once(
                ("credential-use", ref),
                Finding(
                    "credential-use",
                    RiskLevel.DANGER,
                    f"Credential `{name}` from `{source}` written into `{event.path}`",
                    [number],
                ),
                out,
            )

        # F1: persistence — a network command came first
        if "persistence" in (event.reason or ""):
            for n, _t, prior in self._recent:
                if prior.type == EventType.COMMAND and _NETWORK.search(prior.path):
                    self._once(
                        ("persistence", number, n),
                        Finding(
                            "persistence",
                            RiskLevel.DANGER,
                            f"Network command `{_short(prior.path)}` run and startup file `{event.path}` changed",
                            [n, number],
                        ),
                        out,
                    )
                    break

        # F1: mass deletion
        if event.type == EventType.DELETE:
            burst = [
                n for n, t, prior in self._recent if prior.type == EventType.DELETE and now - t <= MASS_DELETE_SECONDS
            ]
            if len(burst) + 1 == MASS_DELETE_COUNT:
                self._once(
                    ("mass-delete", burst[0]),
                    Finding(
                        "mass-delete",
                        RiskLevel.DANGER,
                        f"Mass deletion: {MASS_DELETE_COUNT} files deleted within {int(MASS_DELETE_SECONDS)} seconds",
                        [*burst, number],
                    ),
                    out,
                )

        # F6: repeated rewrites of one file
        if event.type == EventType.MODIFY:
            same = [
                n
                for n, t, prior in self._recent
                if prior.type == EventType.MODIFY and prior.path == event.path and now - t <= REWRITE_SECONDS
            ]
            if len(same) + 1 == REWRITE_COUNT:
                self._once(
                    ("rewrites", event.path, same[0]),
                    Finding(
                        "rewrites",
                        RiskLevel.CAUTION,
                        f"`{event.path}` rewritten {REWRITE_COUNT} times in {int(REWRITE_SECONDS // 60)} minutes",
                        [*same, number],
                    ),
                    out,
                )


def find_flags(session: Session) -> list[Finding]:
    """All findings for a saved session (deterministic: same session, same findings)."""
    engine = FlagEngine()
    findings: list[Finding] = []
    for number, event in enumerate(session.events, start=1):
        findings.extend(engine.process(number, event))
    return findings
