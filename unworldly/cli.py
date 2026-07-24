"""CLI entry point for Unworldly — The Flight Recorder for AI Agents."""

from __future__ import annotations

import os
import sys

import click

from ._version import __version__
from .display import banner, verify_display
from .integrity import verify_session
from .replay import list_command, replay, touched_command
from .report import report
from .session import get_latest_session, load_session
from .watcher import watch


@click.group()
@click.version_option(version=__version__, prog_name="unworldly")
def cli() -> None:
    """The flight recorder for AI agents.

    Record, replay, and audit everything AI agents do on your system.
    """
    pass


# ── watch ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("directory", default=".")
@click.option("--hipaa", is_flag=True, default=False, help="Enable HIPAA PHI detection patterns.")
@click.option("--tag", default=None, help="Label this session (e.g. pr-456, sprint-3).")
@click.option("--on-danger", "on_danger", default=None, help="Alert on danger events: a webhook URL or 'desktop'.")
@click.option(
    "--capture",
    type=click.Choice(["poll", "hook", "both"]),
    default="poll",
    help="Command capture: poll (default, best-effort), hook (lossless, needs `hook install`), both.",
)
def watch_cmd(directory: str, hipaa: bool, tag: str | None, on_danger: str | None, capture: str) -> None:
    """Start recording AI agent activity in the current directory."""
    watch(directory, hipaa=hipaa, tag=tag, on_danger=on_danger, capture=capture)


watch_cmd.name = "watch"


# ── hook ──────────────────────────────────────────────────────────────────────

@cli.group()
def hook() -> None:
    """Manage the shell hook for lossless command capture.

    The default `watch` poll mode samples the process list and can miss
    short-lived commands. Installing the shell hook records every command
    before it runs, giving a complete audit trail.
    """
    pass


@hook.command(name="install")
@click.option("--shell", type=click.Choice(["bash", "zsh", "pwsh"]), default=None, help="Target shell (auto-detected).")
def hook_install(shell: str | None) -> None:
    """Install the shell hook into your shell rc file."""
    from .shell_hook import install_hook

    resolved, path = install_hook(shell)
    click.echo(f"✓ Installed unworldly {resolved} hook → {path}")
    click.echo("  Restart your shell (or `source` the rc file), then run:")
    click.echo("    unworldly watch --capture hook")


@hook.command(name="uninstall")
@click.option("--shell", type=click.Choice(["bash", "zsh", "pwsh"]), default=None, help="Target shell (auto-detected).")
def hook_uninstall(shell: str | None) -> None:
    """Remove the shell hook from your shell rc file."""
    from .shell_hook import uninstall_hook

    removed, path = uninstall_hook(shell)
    if removed:
        click.echo(f"✓ Removed unworldly hook from {path}")
    else:
        click.echo(f"No unworldly hook found in {path}")


@hook.command(name="status")
@click.option("--shell", type=click.Choice(["bash", "zsh", "pwsh"]), default=None)
def hook_status(shell: str | None) -> None:
    """Show whether the shell hook is installed."""
    from .shell_hook import detect_shell, is_installed, rc_path

    resolved = shell or detect_shell()
    state = "installed" if is_installed(resolved) else "not installed"
    click.echo(f"{resolved}: hook {state} ({rc_path(resolved)})")


@hook.command(name="print")
@click.option("--shell", type=click.Choice(["bash", "zsh", "pwsh"]), default=None)
def hook_print(shell: str | None) -> None:
    """Print the hook snippet so you can add it to your rc file manually."""
    from .shell_hook import detect_shell, hook_snippet

    click.echo(hook_snippet(shell or detect_shell()))


# ── replay ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("session", required=False)
@click.option("-s", "--speed", default=1.0, type=float, help="Playback speed multiplier.")
def replay_cmd(session: str | None, speed: float) -> None:
    """Replay a recorded session in the terminal."""
    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    replay(session_path, speed=speed)


replay_cmd.name = "replay"


# ── report ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("session", required=False)
@click.option("-f", "--format", "fmt", default="terminal", help="Output format: terminal, md.")
@click.option("-o", "--output", default=None, help="Output file path (for md format).")
@click.option("--owasp", is_flag=True, default=False, help="Include OWASP Agentic AI Top 10 mapping.")
def report_cmd(session: str | None, fmt: str, output: str | None, owasp: bool) -> None:
    """Generate a security report from a recorded session."""
    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    report(session_path, output=output, format=fmt, include_owasp=owasp)


report_cmd.name = "report"


# ── verify ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("session", required=False)
def verify(session: str | None) -> None:
    """Verify integrity of a recorded session (tamper detection)."""
    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    data = load_session(session_path)
    print(banner())
    result = verify_session(data)
    print(verify_display(result))
    sys.exit(0 if result.valid else 1)


# ── list / ls ─────────────────────────────────────────────────────────────────

@cli.command(name="list")
@click.option("--risk", type=click.Choice(["safe", "caution", "danger"]), default=None, help="Filter by max risk level.")
@click.option("--agent", default=None, help="Filter by agent name (partial match).")
@click.option("--since", default=None, help="Filter by recency: 30m, 2h, 7d.")
@click.option("--tag", default=None, help="Filter by session tag.")
def list_cmd(risk: str | None, agent: str | None, since: str | None, tag: str | None) -> None:
    """List all recorded sessions."""
    list_command(os.getcwd(), risk=risk, agent=agent, since=since, tag=tag)


@cli.command(name="ls", hidden=True)
@click.option("--risk", type=click.Choice(["safe", "caution", "danger"]), default=None)
@click.option("--agent", default=None)
@click.option("--since", default=None)
@click.option("--tag", default=None)
def ls_cmd(risk: str | None, agent: str | None, since: str | None, tag: str | None) -> None:
    """List all recorded sessions (alias for list)."""
    list_command(os.getcwd(), risk=risk, agent=agent, since=since, tag=tag)


# ── touched ───────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("session", required=False)
def touched(session: str | None) -> None:
    """Show a per-file summary of what the agent touched in a session."""
    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    touched_command(session_path)


# ── diff ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("session_a")
@click.argument("session_b")
def diff(session_a: str, session_b: str) -> None:
    """Compare two recorded sessions side by side."""
    from .diff import diff_command
    diff_command(session_a, session_b)


# ── export ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("session", required=False)
@click.option("--sarif", "fmt", flag_value="sarif", default=True, help="Export as SARIF 2.1.0 (GitHub Code Scanning).")
@click.option("-o", "--output", default=None, help="Output file path.")
def export(session: str | None, fmt: str, output: str | None) -> None:
    """Export a session to SARIF format for GitHub Code Scanning."""
    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    from .sarif import export_sarif
    export_sarif(session_path, output=output)


# ── snapshot ──────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("mode", type=click.Choice(["before", "after"]))
@click.argument("directory", default=".")
def snapshot(mode: str, directory: str) -> None:
    """Record git state before/after an agent run for change diffing.

    Run `unworldly snapshot before` before starting your agent,
    then `unworldly snapshot after` when it finishes.
    """
    from .snapshot import snapshot_before, snapshot_after
    if mode == "before":
        snapshot_before(directory)
    else:
        snapshot_after(directory)


# ── review ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("session", required=False)
@click.option("-o", "--output", default=None, help="Save review decisions to this JSON file.")
@click.option("--all", "show_all", is_flag=True, default=False, help="Review safe events too (default: danger+caution only).")
def review(session: str | None, output: str | None, show_all: bool) -> None:
    """Interactively review session events — approve, flag, or skip each one."""
    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    from .review import review_command
    review_command(session_path, output=output, show_all=show_all)


# ── doctor ────────────────────────────────────────────────────────────────────

@cli.command()
def doctor() -> None:
    """Diagnose which capture layers work on this machine — and what they can't see."""
    from .doctor import format_report, run_doctor

    click.echo(format_report(run_doctor(os.getcwd())))


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
