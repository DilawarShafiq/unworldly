"""File and command watcher for Unworldly.

Uses watchdog for filesystem monitoring and CommandMonitor for
process detection. Combines both into a unified event timeline.
"""

from __future__ import annotations

import os
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Optional

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileSystemEvent,
)

from .types import EventType, Session, WatchEvent
from .risk import assess_risk, should_ignore
from .command_risk import assess_command_risk
from .command_monitor import create_command_monitor
from .config import load_config
from .session import add_event, create_session, save_session, ensure_sessions_dir
from .display import banner, format_event, session_summary, watch_header, agent_badge
from .agent_detect import detect_agent


def _format_time(dt: datetime) -> str:
    """Format a datetime as HH:MM:SS."""
    return dt.strftime("%H:%M:%S")


def _map_watchdog_event(event: FileSystemEvent) -> Optional[EventType]:
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

    def __init__(self, abs_dir: str, session: Session) -> None:
        super().__init__()
        self.abs_dir = abs_dir
        self.session = session

    def _handle(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        event_type = _map_watchdog_event(event)
        if event_type is None:
            return

        relative_path = os.path.relpath(event.src_path, self.abs_dir)
        if should_ignore(relative_path):
            return

        risk_result = assess_risk(relative_path, event_type)
        now = datetime.now(timezone.utc)

        watch_event = WatchEvent(
            timestamp=now.isoformat(),
            type=event_type,
            path=relative_path,
            risk=risk_result.level,
            reason=risk_result.reason,
        )

        add_event(self.session, watch_event)
        print(format_event(
            _format_time(now), event_type, relative_path,
            risk_result.level, risk_result.reason,
        ))

        # Save incrementally so no data is lost on abrupt exit
        save_session(self.session, self.abs_dir)

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._handle(event)


def watch(directory: str) -> None:
    """Start recording AI agent activity in the given directory.

    Monitors file changes (create/modify/delete) and shell commands,
    detects the running AI agent, and saves a tamper-proof session.
    """
    abs_dir = os.path.abspath(directory)
    session = create_session(abs_dir)

    # ISO 42001 A.3.2: Detect which AI agent is running
    agent = detect_agent()
    if agent:
        session.agent = agent

    print(banner())
    print(watch_header(abs_dir))
    if agent:
        print(agent_badge(agent))

    # Set up watchdog observer
    handler = _UnworldlyHandler(abs_dir, session)
    observer = Observer()
    observer.schedule(handler, abs_dir, recursive=True)
    observer.start()

    # Load user config for command risk overrides
    config = load_config(abs_dir)

    # Start command monitor
    cmd_monitor = create_command_monitor()
    if cmd_monitor is not None:
        def _on_command(cmd):
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
            print(format_event(
                _format_time(now), EventType.COMMAND, command_str,
                risk_result.level, risk_result.reason,
            ))
            save_session(session, abs_dir)

        cmd_monitor.start(abs_dir, _on_command)
    else:
        yellow = "\033[33m"
        reset = "\033[0m"
        print(f"  {yellow}⚠ Process monitoring unavailable — tracking file changes only{reset}")

    # Pre-create session dir and save initial empty session
    ensure_sessions_dir(abs_dir)
    save_session(session, abs_dir)

    # Graceful shutdown
    def _shutdown(signum=None, frame=None):
        if cmd_monitor is not None:
            cmd_monitor.stop()
        observer.stop()
        observer.join()
        session_path = save_session(session, abs_dir)
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
