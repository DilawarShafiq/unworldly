"""Cross-platform process monitor for Unworldly.

Polls the system process list at regular intervals to detect new commands.
Uses `ps` on Unix and `wmic` on Windows.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .types import CommandInfo


@dataclass
class ProcessEntry:
    """A single process from the system process list."""
    pid: int
    command: str
    args: str


class CommandMonitor:
    """Monitors running processes for new commands.

    Polls the system process list every 500ms and reports new processes
    via the provided callback. Already-seen PIDs are tracked to avoid
    duplicate reporting.
    """

    def __init__(self) -> None:
        self._timer: Optional[threading.Event] = None
        self._thread: Optional[threading.Thread] = None
        self._seen_pids: set[int] = set()
        self._watch_dir: str = ""
        self._self_pid: int = os.getpid()
        self._running: bool = False

    def start(self, cwd: str, callback: Callable[[CommandInfo], None]) -> None:
        """Start monitoring processes in the given directory."""
        self._watch_dir = os.path.abspath(cwd)
        self._seen_pids.clear()

        # Snapshot current processes to avoid reporting pre-existing ones
        try:
            initial = self._list_processes()
            for proc in initial:
                self._seen_pids.add(proc.pid)
        except Exception:
            pass  # If initial snapshot fails, start clean

        self._running = True
        self._timer = threading.Event()
        self._thread = threading.Thread(
            target=self._poll_loop,
            args=(callback,),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop monitoring processes."""
        self._running = False
        if self._timer is not None:
            self._timer.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._timer = None
        self._seen_pids.clear()

    def _poll_loop(self, callback: Callable[[CommandInfo], None]) -> None:
        """Internal polling loop that runs on a background thread."""
        while self._running:
            try:
                processes = self._list_processes()
                for proc in processes:
                    if proc.pid in self._seen_pids:
                        continue
                    if proc.pid == self._self_pid:
                        continue

                    self._seen_pids.add(proc.pid)

                    # Parse command and args
                    parts = proc.args.strip().split()
                    executable = parts[0] if parts else proc.command
                    args = parts[1:] if parts else []

                    # Skip system/internal processes
                    if self._should_skip(executable):
                        continue

                    info = CommandInfo(
                        executable=os.path.basename(executable),
                        args=args,
                        cwd=self._watch_dir,
                        pid=proc.pid,
                    )

                    callback(info)
            except Exception:
                # Silently skip poll failures -- Zero Interference
                pass

            # Wait 500ms or until stop() is called
            if self._timer is not None:
                self._timer.wait(timeout=0.5)

    def _should_skip(self, executable: str) -> bool:
        """Check if a process should be skipped (system/internal processes)."""
        skip = [
            "ps", "wmic", "powershell", "cmd.exe", "conhost",
            "unworldly", "node_modules/.bin",
            "Get-Process", "WMIC.exe",
        ]
        base = os.path.basename(executable).lower()
        return any(s.lower() in base for s in skip)

    def _list_processes(self) -> list[ProcessEntry]:
        """List running processes using platform-appropriate method."""
        if sys.platform == "win32":
            return self._list_processes_windows()
        return self._list_processes_unix()

    def _list_processes_unix(self) -> list[ProcessEntry]:
        """List processes on Unix using `ps`."""
        output = subprocess.check_output(
            ["ps", "-eo", "pid,comm,args", "--no-headers"],
            encoding="utf-8",
            timeout=2,
            stderr=subprocess.DEVNULL,
        )

        entries: list[ProcessEntry] = []
        for line in output.strip().split("\n"):
            trimmed = line.strip()
            if not trimmed:
                continue

            import re
            match = re.match(r"^(\d+)\s+(\S+)\s+(.*)$", trimmed)
            if not match:
                continue

            entries.append(ProcessEntry(
                pid=int(match.group(1)),
                command=match.group(2),
                args=match.group(3),
            ))

        return entries

    def _list_processes_windows(self) -> list[ProcessEntry]:
        """List processes on Windows using `wmic`."""
        output = subprocess.check_output(
            ["wmic", "process", "get", "ProcessId,Name,CommandLine", "/format:csv"],
            encoding="utf-8",
            timeout=3,
            stderr=subprocess.DEVNULL,
        )

        entries: list[ProcessEntry] = []
        lines = output.strip().split("\n")

        # Skip header line (first non-empty line after filtering)
        for line in lines[1:]:
            trimmed = line.strip()
            if not trimmed:
                continue

            # CSV format: Node,CommandLine,Name,ProcessId
            parts = trimmed.split(",")
            if len(parts) < 4:
                continue

            command_line = ",".join(parts[1:-2])  # CommandLine may contain commas
            name = parts[-2]
            try:
                pid = int(parts[-1])
            except ValueError:
                continue

            entries.append(ProcessEntry(
                pid=pid,
                command=name,
                args=command_line or name,
            ))

        return entries


def create_command_monitor() -> Optional[CommandMonitor]:
    """Create a CommandMonitor instance, or None if unavailable."""
    try:
        monitor = CommandMonitor()
        return monitor
    except Exception:
        return None
