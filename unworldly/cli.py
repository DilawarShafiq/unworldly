"""CLI entry point for Unworldly — The Flight Recorder for AI Agents.

Uses click for command-line argument parsing (similar to commander.js).
"""

from __future__ import annotations

import os
import sys

import click

from .watcher import watch
from .replay import replay, list_command
from .report import report
from .session import get_latest_session, load_session
from .integrity import verify_session
from .display import banner, verify_display


@click.group()
@click.version_option(version="0.3.0", prog_name="unworldly")
def cli() -> None:
    """The flight recorder for AI agents.

    Record, replay, and audit everything AI agents do on your system.
    """
    pass


@cli.command()
@click.argument("directory", default=".")
def watch_cmd(directory: str) -> None:
    """Start recording AI agent activity in the current directory."""
    watch(directory)


# Register with the name "watch" instead of "watch_cmd"
watch_cmd.name = "watch"


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


@cli.command()
@click.argument("session", required=False)
@click.option("-f", "--format", "fmt", default="terminal", help="Output format: terminal, md.")
@click.option("-o", "--output", default=None, help="Output file path (for md format).")
def report_cmd(session: str | None, fmt: str, output: str | None) -> None:
    """Generate a security report from a recorded session."""
    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    report(session_path, output=output, format=fmt)


report_cmd.name = "report"


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


@cli.command(name="list")
def list_cmd() -> None:
    """List all recorded sessions."""
    list_command(os.getcwd())


# Also register an alias "ls"
@cli.command(name="ls", hidden=True)
def ls_cmd() -> None:
    """List all recorded sessions (alias for list)."""
    list_command(os.getcwd())


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
