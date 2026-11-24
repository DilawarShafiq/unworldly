"""Cross-platform process monitor for Unworldly.

Polls the system process list at regular intervals to detect new commands.
Uses `psutil` on every platform (no helper processes spawned); falls back to
`ps` / `wmic` only if psutil is unavailable.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass

from .types import CommandInfo

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a declared dependency
    psutil = None  # type: ignore[assignment]

# Helper/internal processes, matched on the exact executable name (without .exe).
_SKIP_NAMES = frozenset({"ps", "wmic", "conhost", "unworldly"})
# Shells skipped only when started bare (an interactive prompt, not a command).
_BARE_SHELLS = frozenset({"powershell", "pwsh", "cmd"})


@dataclass
class ProcessEntry:
    """A single process from the system process list."""

    pid: int
    command: str
    args: str
    actor: str | None = None
    parents: list[str] | None = None
    own_child: bool = False  # spawned by Unworldly itself (e.g. its own `git` calls)
    argv: list[str] | None = None  # original argument list, when the platform gives one


class CommandMonitor:
    """Monitors running processes for new commands.

    Polls the system process list every 500ms and reports new processes
    via the provided callback. Already-seen PIDs are tracked to avoid
    duplicate reporting.
    """

    def __init__(self) -> None:
        self._timer: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._seen_pids: set[int] = set()
        self._watch_dir: str = ""
        self._self_pid: int = os.getpid()
        self._running: bool = False
        self._agent_roots: set[int] = set()
        self._names: dict[int, str] = {}  # pid -> process name cache

    def set_agent_roots(self, roots: set[int]) -> None:
        """PIDs of the agent's own processes; commands under them are ``actor="agent"``."""
        self._agent_roots = set(roots)

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
                    if proc.own_child:
                        continue

                    # Parse command and args
                    # Keep the real argument list when we have it: re-splitting a joined
                    # string breaks paths with spaces (C:\Program Files\...).
                    parts = proc.argv if proc.argv else proc.args.strip().split()
                    executable = parts[0] if parts else proc.command
                    args = parts[1:] if parts else []

                    # Skip system/internal processes
                    if self._should_skip(executable, args):
                        continue

                    info = CommandInfo(
                        executable=os.path.basename(executable),
                        args=args,
                        cwd=self._watch_dir,
                        pid=proc.pid,
                        actor=proc.actor,
                        parents=proc.parents,
                    )

                    callback(info)
            except Exception:
                # Silently skip poll failures -- Zero Interference
                pass

            # Wait 500ms or until stop() is called
            if self._timer is not None:
                self._timer.wait(timeout=0.5)

    def _should_skip(self, executable: str, args: list[str] | None = None) -> bool:
        """Check if a process should be skipped (Unworldly's own helpers, bare shells).

        Matches whole executable names only, so real commands that merely contain
        a skipped name (e.g. ``psql`` contains ``ps``) are still recorded.
        """
        norm = executable.replace("\\", "/").lower()
        if "node_modules/.bin" in norm:
            return True
        base = os.path.basename(norm)
        stem = base[:-4] if base.endswith(".exe") else base
        if stem in _SKIP_NAMES or stem.startswith("unworldly"):
            return True
        return stem in _BARE_SHELLS and not args

    def _list_processes(self) -> list[ProcessEntry]:
        """List running processes using platform-appropriate method."""
        if psutil is not None:
            return self._list_processes_psutil()
        if sys.platform == "win32":
            return self._list_processes_windows()
        return self._list_processes_unix()

    def _list_processes_psutil(self) -> list[ProcessEntry]:
        """List processes via psutil.

        Cheap by design: ``psutil.pids()`` every poll; command lines, names and the
        parent-ID table are fetched only when unseen PIDs appear, and only while
        recording (not for the start-up snapshot).
        """
        entries: list[ProcessEntry] = []
        ppid_of: Callable[[int], int | None] | None = None
        for pid in psutil.pids():
            if pid in self._seen_pids or not self._running:
                entries.append(ProcessEntry(pid=pid, command="", args=""))
                continue
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmdline = []
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            self._names[pid] = name
            entry = ProcessEntry(pid=pid, command=name, args=" ".join(cmdline) or name, argv=cmdline or None)
            if ppid_of is None:
                ppid_of = _ppid_lookup()
            self._attribute(pid, entry, ppid_of)
            entries.append(entry)
        return entries

    def _name(self, pid: int) -> str | None:
        if pid not in self._names:
            try:
                self._names[pid] = psutil.Process(pid).name()
            except Exception:
                return None
        return self._names[pid]

    def _attribute(self, pid: int, entry: ProcessEntry, ppid_of: Callable[[int], int | None]) -> None:
        """Walk the parent chain: mark Unworldly's own children and agent-owned commands."""
        ancestors: list[int] = []
        current = pid
        for _ in range(12):
            parent = ppid_of(current)
            if not parent or parent == current or parent in ancestors:
                break
            ancestors.append(parent)
            current = parent
        if self._self_pid in ancestors:
            entry.own_child = True
            return
        names: list[str] = []
        for parent_pid in ancestors[:6]:
            name = self._name(parent_pid)
            if name is None:
                break
            names.append(name)
        entry.parents = names
        if self._agent_roots:
            entry.actor = "agent" if ({pid, *ancestors} & self._agent_roots) else "other"

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

            entries.append(
                ProcessEntry(
                    pid=int(match.group(1)),
                    command=match.group(2),
                    args=match.group(3),
                )
            )

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

            entries.append(
                ProcessEntry(
                    pid=pid,
                    command=name,
                    args=command_line or name,
                )
            )

        return entries


def _ppid_lookup() -> Callable[[int], int | None]:
    """Parent-PID lookup for one poll.

    Uses psutil's whole-system parent table when the platform has one (one cheap
    snapshot on Windows/Linux); otherwise asks each process for its parent.
    """
    try:
        platform_impl = getattr(psutil, "_psplatform")  # noqa: B009 - private, guarded by the except below
        table: dict[int, int] = dict(platform_impl.ppid_map())
        return table.get
    except Exception:

        def ask(pid: int) -> int | None:
            try:
                return int(psutil.Process(pid).ppid())
            except Exception:
                return None

        return ask


def create_command_monitor() -> CommandMonitor | None:
    """Create a CommandMonitor instance, or None if process listing doesn't work here.

    Probes one listing so an unusable backend (e.g. ``wmic`` removed from newer
    Windows) is reported up front instead of silently recording no commands.
    """
    try:
        monitor = CommandMonitor()
        monitor._list_processes()
        return monitor
    except Exception:
        return None
