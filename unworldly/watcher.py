"""File and command watcher for Unworldly.

Uses watchdog for filesystem monitoring and CommandMonitor for
process detection. Combines both into a unified event timeline.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from .agent_detect import detect_agent, detect_model, find_agent_roots
from .command_monitor import create_command_monitor
from .command_risk import assess_command_risk
from .config import load_config
from .content import ContentTracker
from .display import agent_badge, banner, format_event, session_summary, watch_header
from .hipaa_risk import assess_hipaa_command_risk, assess_hipaa_file_risk
from .risk import assess_risk, should_ignore
from .session import add_checkpoint, add_event, close_session, create_session, ensure_sessions_dir, save_session
from .signing import DEFAULT_HEARTBEAT_SECONDS
from .types import AgentInfo, CommandInfo, EventType, RiskLevel, Session, WatchEvent


def _format_time(dt: datetime) -> str:
    """Format a datetime as HH:MM:SS."""
    return dt.strftime("%H:%M:%S")


def _map_watchdog_event(event: FileSystemEvent) -> EventType | None:
    """Map a watchdog event to our EventType."""
    if isinstance(event, FileCreatedEvent):
        return EventType.CREATE
    elif isinstance(event, FileModifiedEvent):
        return EventType.MODIFY
    elif isinstance(event, FileDeletedEvent):
        return EventType.DELETE
    return None


class _UnworldlyHandler(FileSystemEventHandler):
    """Watchdog event handler that records file changes."""

    def __init__(self, abs_dir: str, session: Session, hipaa: bool = False, on_danger: str | None = None) -> None:
        super().__init__()
        self.abs_dir = abs_dir
        self.session = session
        self.hipaa = hipaa
        self.on_danger = on_danger
        self.content = ContentTracker(abs_dir)

    def _handle(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        event_type = _map_watchdog_event(event)
        if event_type is None:
            return

        relative_path = os.path.relpath(os.path.realpath(str(event.src_path)), self.abs_dir)
        if should_ignore(relative_path):
            return

        # HIPAA patterns checked first when enabled
        risk_result = None
        if self.hipaa:
            risk_result = assess_hipaa_file_risk(relative_path, event_type)
        if risk_result is None:
            risk_result = assess_risk(relative_path, event_type)
        now = datetime.now(timezone.utc)

        change = self.content.describe(relative_path, event_type, risk_result.level)
        watch_event = WatchEvent(
            timestamp=now.isoformat(),
            type=event_type,
            path=relative_path,
            risk=risk_result.level,
            reason=risk_result.reason,
            before_hash=change.before_hash,
            after_hash=change.after_hash,
            diff=change.diff,
        )

        add_event(self.session, watch_event)
        print(
            format_event(
                _format_time(now),
                event_type,
                relative_path,
                risk_result.level,
                risk_result.reason,
            )
        )

        if self.on_danger and risk_result.level.value == "danger":
            from .alerts import fire_alert

            fire_alert(self.on_danger, watch_event, self.session)

        # Save incrementally so no data is lost on abrupt exit
        save_session(self.session, self.abs_dir)

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._handle(event)


# -- Sensitive locations outside the project (R2) ---------------------------------

# (path under home, recursive directory?, risk, reason)
_OUTSIDE_TARGETS: list[tuple[str, bool, RiskLevel, str]] = [
    (".ssh", True, RiskLevel.DANGER, "Outside project: SSH keys or config changed"),
    (".aws", True, RiskLevel.DANGER, "Outside project: AWS credentials or config changed"),
    (".azure", True, RiskLevel.DANGER, "Outside project: Azure credentials changed"),
    (".config/gcloud", True, RiskLevel.DANGER, "Outside project: Google Cloud credentials changed"),
    (".kube", True, RiskLevel.DANGER, "Outside project: Kubernetes config changed"),
    (".gnupg", True, RiskLevel.DANGER, "Outside project: GPG keys changed"),
    (".docker", True, RiskLevel.DANGER, "Outside project: Docker credentials changed"),
    (".bashrc", False, RiskLevel.DANGER, "Outside project: shell startup file changed (persistence risk)"),
    (".bash_profile", False, RiskLevel.DANGER, "Outside project: shell startup file changed (persistence risk)"),
    (".zshrc", False, RiskLevel.DANGER, "Outside project: shell startup file changed (persistence risk)"),
    (".profile", False, RiskLevel.DANGER, "Outside project: shell startup file changed (persistence risk)"),
    (
        "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
        False,
        RiskLevel.DANGER,
        "Outside project: PowerShell profile changed (persistence risk)",
    ),
    (
        "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
        False,
        RiskLevel.DANGER,
        "Outside project: PowerShell profile changed (persistence risk)",
    ),
    (".gitconfig", False, RiskLevel.DANGER, "Outside project: global git config changed"),
    (".npmrc", False, RiskLevel.DANGER, "Outside project: npm credentials/config changed"),
    (".pypirc", False, RiskLevel.DANGER, "Outside project: PyPI credentials changed"),
    (".netrc", False, RiskLevel.DANGER, "Outside project: network credentials changed"),
]


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(root)]) == os.path.realpath(root)
    except ValueError:  # different drives on Windows
        return False


class _OutsideHandler(FileSystemEventHandler):
    """Records writes to sensitive files outside the project. Paths only, never content."""

    def __init__(
        self,
        home: str,
        session: Session,
        abs_dir: str,
        risk: RiskLevel,
        reason: str,
        only_file: str | None,
        on_danger: str | None,
    ) -> None:
        super().__init__()
        self.home = home
        self.session = session
        self.abs_dir = abs_dir
        self.risk = risk
        self.reason = reason
        self.only_file = os.path.normcase(os.path.realpath(only_file)) if only_file else None
        self.on_danger = on_danger

    def _handle(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        event_type = _map_watchdog_event(event)
        if event_type is None:
            return
        src = os.path.realpath(str(event.src_path))
        if self.only_file is not None and os.path.normcase(src) != self.only_file:
            return
        risk, reason = self.risk, self.reason
        if os.path.basename(src) == "known_hosts":
            risk, reason = RiskLevel.CAUTION, "Outside project: SSH known hosts updated (new host contacted)"
        display_path = "~/" + os.path.relpath(src, self.home).replace(os.sep, "/")
        now = datetime.now(timezone.utc)
        watch_event = WatchEvent(
            timestamp=now.isoformat(), type=event_type, path=display_path, risk=risk, reason=reason
        )
        add_event(self.session, watch_event)
        print(format_event(_format_time(now), event_type, display_path, risk, reason))
        if self.on_danger and risk == RiskLevel.DANGER:
            from .alerts import fire_alert

            fire_alert(self.on_danger, watch_event, self.session)
        save_session(self.session, self.abs_dir)

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._handle(event)


def schedule_outside_watches(
    observer: Any, session: Session, abs_dir: str, on_danger: str | None, home: str | None = None
) -> list[str]:
    """Watch the sensitive locations that exist on this machine; returns what is watched."""
    home = os.path.realpath(home or os.path.expanduser("~"))
    watched: list[str] = []
    for rel, recursive, risk, reason in _OUTSIDE_TARGETS:
        target = os.path.join(home, *rel.split("/"))
        if not os.path.exists(target) or _inside(target, abs_dir):
            continue
        if recursive and os.path.isdir(target):
            handler = _OutsideHandler(home, session, abs_dir, risk, reason, None, on_danger)
            observer.schedule(handler, target, recursive=True)
        elif not recursive and os.path.isfile(target):
            handler = _OutsideHandler(home, session, abs_dir, risk, reason, target, on_danger)
            observer.schedule(handler, os.path.dirname(target), recursive=False)
        else:
            continue
        watched.append("~/" + rel)
    return watched


def watch(
    directory: str,
    hipaa: bool = False,
    tag: str | None = None,
    on_danger: str | None = None,
    capture: str = "poll",
    outside: bool = True,
    model: str | None = None,
    agent_version: str | None = None,
) -> None:
    """Start recording AI agent activity in the given directory.

    Monitors file changes (create/modify/delete) and shell commands,
    detects the running AI agent, and saves a tamper-evident session.

    Args:
        directory: Directory to watch.
        hipaa:     Enable HIPAA PHI detection patterns.
        tag:       Optional label for the session (e.g. "pr-456").
        on_danger: Fire an alert on every danger event — a webhook URL or "desktop".
        capture:   Command-capture mode. "poll" (default) samples the process
                   list and can miss short-lived commands; "hook" is lossless
                   and reads the shell hook log (run `unworldly hook install`
                   first); "both" runs the two together.
        outside:   Also watch sensitive locations outside the project
                   (~/.ssh, ~/.aws, shell startup files, ...). Paths only.
        model:     Model name to record (overrides detection).
        agent_version: Agent version to record.
    """
    abs_dir = os.path.realpath(directory)
    session = create_session(abs_dir, tag=tag, heartbeat_seconds=DEFAULT_HEARTBEAT_SECONDS)

    # ISO 42001 A.3.2: Detect which AI agent is running
    agent = detect_agent()
    agent_roots = find_agent_roots(agent)
    if agent is None and (model or agent_version):
        agent = AgentInfo(name="Unknown agent", detected_via="set on the command line")
    if agent is not None:
        agent.model = model or detect_model(agent_roots)
        if agent_version:
            agent.version = agent_version
        session.agent = agent

    print(banner())
    print(watch_header(abs_dir))
    if agent:
        print(agent_badge(agent))

    # Load user config for command risk overrides
    config = load_config(abs_dir)
    # CLI --hipaa flag OR config file "hipaa": true
    hipaa_enabled = hipaa or config.hipaa

    if hipaa_enabled:
        yellow = "\033[33m"
        reset = "\033[0m"
        print(f"  {yellow}⚕ HIPAA mode enabled — PHI detection patterns active{reset}")
        print()

    # Set up watchdog observer
    handler = _UnworldlyHandler(abs_dir, session, hipaa=hipaa_enabled, on_danger=on_danger)
    observer = Observer()
    observer.schedule(handler, abs_dir, recursive=True)
    outside_watched = schedule_outside_watches(observer, session, abs_dir, on_danger) if outside else []
    observer.start()
    if outside_watched:
        print(f"  \033[90mAlso watching outside the project: {', '.join(outside_watched)}\033[0m")

    # Start command monitor(s) according to capture mode
    def _on_command(cmd: CommandInfo) -> None:
        risk_result = None
        if hipaa_enabled:
            risk_result = assess_hipaa_command_risk(cmd.executable, cmd.args)
        if risk_result is None:
            risk_result = assess_command_risk(cmd.executable, cmd.args, config.commands)
        now = datetime.now(timezone.utc)
        command_str = " ".join([cmd.executable] + cmd.args)

        watch_event = WatchEvent(
            timestamp=now.isoformat(),
            type=EventType.COMMAND,
            path=command_str,
            risk=risk_result.level,
            reason=risk_result.reason,
            command=cmd,
        )

        add_event(session, watch_event)
        print(
            format_event(
                _format_time(now),
                EventType.COMMAND,
                command_str,
                risk_result.level,
                risk_result.reason,
            )
        )
        if on_danger and risk_result.level.value == "danger":
            from .alerts import fire_alert

            fire_alert(on_danger, watch_event, session)
        save_session(session, abs_dir)

    yellow = "\033[33m"
    reset = "\033[0m"
    monitors: list[object] = []

    if capture in ("poll", "both"):
        cmd_monitor = create_command_monitor()
        if cmd_monitor is not None:
            cmd_monitor.set_agent_roots(agent_roots)
            cmd_monitor.start(abs_dir, _on_command)
            monitors.append(cmd_monitor)
        else:
            print(f"  {yellow}⚠ Process monitoring unavailable — tracking file changes only{reset}")

    if capture in ("hook", "both"):
        from .shell_hook import create_shell_hook_monitor, is_installed

        hook_monitor = create_shell_hook_monitor()
        if hook_monitor is not None:
            hook_monitor.start(abs_dir, _on_command)
            monitors.append(hook_monitor)
            if not is_installed():
                print(
                    f"  {yellow}⚠ Shell hook not detected — run `unworldly hook install` "
                    f"and restart your shell for lossless command capture{reset}"
                )

    if session.signer is None:
        print(f"  {yellow}⚠ Session signing unavailable — this session will be tamper-evident only{reset}")

    # Pre-create session dir and save initial empty session
    ensure_sessions_dir(abs_dir)
    save_session(session, abs_dir)

    # Signed heartbeats prove the recorder was alive; `verify` reports any gaps.
    heartbeat_stop = threading.Event()

    def _heartbeat() -> None:
        while not heartbeat_stop.wait(DEFAULT_HEARTBEAT_SECONDS):
            if add_checkpoint(session, "heartbeat") is not None:
                save_session(session, abs_dir)

    if session.signer is not None:
        threading.Thread(target=_heartbeat, daemon=True).start()

    # Graceful shutdown
    def _shutdown(signum: int | None = None, frame: object = None) -> None:
        heartbeat_stop.set()
        for mon in monitors:
            mon.stop()  # type: ignore[attr-defined]
        observer.stop()
        observer.join()
        session_path = close_session(session, abs_dir)
        print(session_summary(session.summary, session_path))
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Keep alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _shutdown()
