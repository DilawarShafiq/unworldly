"""Lossless shell-command capture for Unworldly.

The default :mod:`command_monitor` polls the OS process list every 500 ms, so
any command that starts and finishes between polls is never recorded. That is
fine for a rough picture but unacceptable for an audit trail — most commands
live for tens of milliseconds.

This module closes that gap. A tiny ``preexec`` hook installed in the user's
shell rc appends every command *before it runs* to ``.unworldly/commands.log``
inside the watched project. :class:`ShellHookMonitor` tails that file and feeds
each command into the same risk/hash-chain pipeline the poller uses — so
capture is lossless for any shell-driven coding agent.

Line format (tab-separated, command last so it may contain spaces)::

    2026-07-24T12:00:00Z<TAB>/path/to/cwd<TAB>12345<TAB>git commit -m "wip"
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from pathlib import Path

from .types import CommandInfo

LOG_FILENAME = "commands.log"
MARKER_START = "# >>> unworldly hook >>>"
MARKER_END = "# <<< unworldly hook <<<"

SUPPORTED_SHELLS = ("bash", "zsh", "pwsh")


# ── hook snippets ───────────────────────────────────────────────────────────

_BASH_SNIPPET = r"""
__unworldly_log() {
  local d="$PWD/.unworldly"
  [ -d "$d" ] || return
  local cmd="$1"
  case "$cmd" in
    __unworldly_log*) return ;;
  esac
  printf '%s\t%s\t%s\t%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PWD" "$$" "$cmd" >> "$d/commands.log" 2>/dev/null
}
trap '__unworldly_log "$BASH_COMMAND"' DEBUG
"""

_ZSH_SNIPPET = r"""
__unworldly_preexec() {
  local d="$PWD/.unworldly"
  [ -d "$d" ] || return
  printf '%s\t%s\t%s\t%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PWD" "$$" "$1" >> "$d/commands.log" 2>/dev/null
}
autoload -Uz add-zsh-hook 2>/dev/null
add-zsh-hook preexec __unworldly_preexec 2>/dev/null || preexec_functions+=(__unworldly_preexec)
"""

# PowerShell has no preexec; log the previous command each time a prompt is
# drawn. This wraps (does not clobber) any existing prompt function.
_PWSH_SNIPPET = r"""
if (-not (Test-Path variable:global:__unworldly_inner_prompt)) {
  $global:__unworldly_inner_prompt = $function:prompt
}
function global:prompt {
  $d = Join-Path $PWD '.unworldly'
  if (Test-Path $d) {
    $h = Get-History -Count 1 -ErrorAction SilentlyContinue
    if ($h -and $h.Id -ne $global:__unworldly_last) {
      $global:__unworldly_last = $h.Id
      $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
      $line = "$ts`t$PWD`t$PID`t$($h.CommandLine)"
      Add-Content -Path (Join-Path $d 'commands.log') -Value $line -ErrorAction SilentlyContinue
    }
  }
  & $global:__unworldly_inner_prompt
}
"""

_SNIPPETS = {"bash": _BASH_SNIPPET, "zsh": _ZSH_SNIPPET, "pwsh": _PWSH_SNIPPET}


def detect_shell() -> str:
    """Best-effort detection of the user's interactive shell.

    Returns one of :data:`SUPPORTED_SHELLS`. Defaults to ``bash`` on POSIX and
    ``pwsh`` on Windows when detection is inconclusive.
    """
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return "zsh"
    if "bash" in shell:
        return "bash"
    has_pwsh = any(key.upper() == "PSMODULEPATH" for key in os.environ)
    if os.name == "nt" or has_pwsh:
        return "pwsh"
    return "bash"


def hook_snippet(shell: str) -> str:
    """Return the rc snippet (wrapped in markers) for ``shell``."""
    if shell not in _SNIPPETS:
        raise ValueError(f"Unsupported shell: {shell!r}. Choose from {SUPPORTED_SHELLS}.")
    return f"{MARKER_START}\n{_SNIPPETS[shell].strip()}\n{MARKER_END}\n"


def rc_path(shell: str) -> Path:
    """Return the rc file path where the hook for ``shell`` is installed."""
    home = Path.home()
    if shell == "zsh":
        return home / ".zshrc"
    if shell == "bash":
        return home / ".bashrc"
    if shell == "pwsh":
        # $PROFILE.CurrentUserAllHosts — location differs per OS.
        if os.name == "nt":
            return home / "Documents" / "PowerShell" / "profile.ps1"
        return home / ".config" / "powershell" / "profile.ps1"
    raise ValueError(f"Unsupported shell: {shell!r}")


def _strip_block(text: str) -> str:
    """Remove any existing unworldly hook block from rc file text."""
    start = text.find(MARKER_START)
    if start == -1:
        return text
    end = text.find(MARKER_END, start)
    if end == -1:
        return text[:start].rstrip() + "\n"
    end += len(MARKER_END)
    return (text[:start].rstrip() + "\n" + text[end:].lstrip("\n")).rstrip() + "\n"


def is_installed(shell: str | None = None) -> bool:
    """Return True if the hook block is present in ``shell``'s rc file."""
    shell = shell or detect_shell()
    path = rc_path(shell)
    if not path.exists():
        return False
    return MARKER_START in path.read_text(encoding="utf-8", errors="replace")


def install_hook(shell: str | None = None) -> tuple[str, Path]:
    """Install (or refresh) the hook block in ``shell``'s rc file.

    Idempotent: an existing unworldly block is replaced, never duplicated.
    Returns the resolved shell and the rc path written.
    """
    shell = shell or detect_shell()
    path = rc_path(shell)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    cleaned = _strip_block(existing).rstrip()
    body = (cleaned + "\n\n" if cleaned else "") + hook_snippet(shell)
    path.write_text(body, encoding="utf-8")
    return shell, path


def uninstall_hook(shell: str | None = None) -> tuple[bool, Path]:
    """Remove the hook block from ``shell``'s rc file.

    Returns (removed, rc_path). ``removed`` is False if nothing was present.
    """
    shell = shell or detect_shell()
    path = rc_path(shell)
    if not path.exists():
        return False, path
    existing = path.read_text(encoding="utf-8", errors="replace")
    if MARKER_START not in existing:
        return False, path
    path.write_text(_strip_block(existing), encoding="utf-8")
    return True, path


def parse_hook_line(line: str) -> CommandInfo | None:
    """Parse one tab-separated hook log line into a :class:`CommandInfo`.

    Returns None for malformed or empty lines. The command string is tokenised
    the same way the poll-based monitor tokenises process args, so both capture
    paths feed the risk engine identically.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None
    parts = line.split("\t", 3)
    if len(parts) < 4:
        return None
    _ts, cwd, pid_str, command = parts
    tokens = command.strip().split()
    if not tokens:
        return None
    try:
        pid = int(pid_str)
    except ValueError:
        pid = -1
    return CommandInfo(
        executable=os.path.basename(tokens[0]),
        args=tokens[1:],
        cwd=cwd,
        pid=pid,
    )


class ShellHookMonitor:
    """Tails ``.unworldly/commands.log`` and reports each appended command.

    Only lines appended *after* :meth:`start` are reported, so restarting a
    watch session does not replay old commands. Runs on a daemon thread and
    fails silent to honour the Zero-Interference principle.
    """

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._running = False

    def log_path(self, cwd: str) -> Path:
        return Path(cwd) / ".unworldly" / LOG_FILENAME

    def start(self, cwd: str, callback: Callable[[CommandInfo], None]) -> None:
        """Begin tailing the hook log for ``cwd``."""
        self._stop.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._tail_loop,
            args=(str(self.log_path(cwd)), callback),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _tail_loop(self, path: str, callback: Callable[[CommandInfo], None]) -> None:
        fh = None
        pos = 0
        try:
            while self._running:
                if fh is None:
                    if os.path.exists(path):
                        # Long-lived handle tailed across loop iterations; a
                        # context manager would close it every pass.
                        fh = open(path, encoding="utf-8", errors="replace")  # noqa: SIM115
                        fh.seek(0, os.SEEK_END)  # only report new lines
                        pos = fh.tell()
                    else:
                        self._stop.wait(0.2)
                        continue

                line = fh.readline()
                if line and line.endswith("\n"):
                    pos = fh.tell()
                    try:
                        info = parse_hook_line(line)
                        if info is not None:
                            callback(info)
                    except Exception:
                        pass  # Zero Interference — never crash the watcher
                else:
                    # No complete line yet — rewind over any partial read and wait.
                    if line:
                        fh.seek(pos)
                    self._stop.wait(0.15)
        finally:
            if fh is not None:
                fh.close()


def create_shell_hook_monitor() -> ShellHookMonitor | None:
    """Create a :class:`ShellHookMonitor`, or None if unavailable."""
    try:
        return ShellHookMonitor()
    except Exception:
        return None
