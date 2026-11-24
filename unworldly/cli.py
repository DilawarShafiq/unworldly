"""CLI entry point for Unworldly — The Flight Recorder for AI Agents."""

from __future__ import annotations

import os
import sys

import click

from ._version import __version__
from .display import banner, verify_display
from .integrity import verify_session
from .replay import list_command, replay, show_event, touched_command
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
@click.option(
    "--outside/--no-outside",
    default=True,
    help="Also watch sensitive places outside the project: ~/.ssh, ~/.aws, shell startup files (default: on).",
)
@click.option("--model", default=None, help="Model name to record for this session (overrides detection).")
@click.option("--agent-version", "agent_version", default=None, help="Agent version to record for this session.")
def watch_cmd(
    directory: str,
    hipaa: bool,
    tag: str | None,
    on_danger: str | None,
    capture: str,
    outside: bool,
    model: str | None,
    agent_version: str | None,
) -> None:
    """Start recording AI agent activity in the current directory."""
    watch(
        directory,
        hipaa=hipaa,
        tag=tag,
        on_danger=on_danger,
        capture=capture,
        outside=outside,
        model=model,
        agent_version=agent_version,
    )


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
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Also fail on recording gaps / abnormal end (exit 2) and unsigned legacy sessions (exit 3).",
)
def verify(session: str | None, strict: bool) -> None:
    """Verify integrity of a recorded session (tamper detection).

    Exit codes: 0 verified, 1 tampered; with --strict also 2 for gaps or an
    abnormal end and 3 for an unsigned legacy session.
    """
    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    data = load_session(session_path)
    print(banner())
    result = verify_session(data)
    print(verify_display(result))
    if not result.valid:
        sys.exit(1)
    if strict and result.status == "VERIFIED_WITH_GAPS":
        sys.exit(2)
    if strict and result.status == "LEGACY":
        sys.exit(3)
    sys.exit(0)


# ── list / ls ─────────────────────────────────────────────────────────────────


@cli.command(name="list")
@click.option(
    "--risk", type=click.Choice(["safe", "caution", "danger"]), default=None, help="Filter by max risk level."
)
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


# ── show ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("number", type=int)
@click.argument("session", required=False)
def show(number: int, session: str | None) -> None:
    """Show one event in full: who ran it, file hashes and the (redacted) diff.

    NUMBER is the event number shown in reports (1 = first event).
    """
    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    if not show_event(session_path, number):
        click.echo(f"No event #{number} in this session.", err=True)
        sys.exit(1)


# ── flags ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("session", required=False)
@click.option("--json", "as_json", is_flag=True, default=False, help="Print findings as JSON.")
def flags(session: str | None, as_json: bool) -> None:
    """List behaviour flags: risky sequences, supply-chain, git, loops.

    Flags are computed from the signed record, so they can be re-run on any
    session. Exit code 1 if any danger flag is found (for CI).
    """
    import json as _json

    from .display import format_finding
    from .flags import find_flags
    from .types import RiskLevel

    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    findings = find_flags(load_session(session_path))
    if as_json:
        click.echo(_json.dumps([f.to_dict() for f in findings], indent=2))
    elif not findings:
        click.echo("\n  \033[32m✓ No behaviour flags in this session\033[0m\n")
    else:
        click.echo("")
        for finding in findings:
            click.echo(format_finding(finding))
        click.echo("")
    sys.exit(1 if any(f.level == RiskLevel.DANGER for f in findings) else 0)


# ── canary ────────────────────────────────────────────────────────────────────


@cli.group()
def canary() -> None:
    """Plant decoy credentials and get flagged if anything uses them.

    Opt-in. Reading the decoy can't be seen; using its values can.
    """


@canary.command(name="plant")
@click.argument("directory", default=".")
@click.option("--name", default=".env.canary", help="Decoy file name (default: .env.canary).")
def canary_plant(directory: str, name: str) -> None:
    """Write a decoy credentials file into the project."""
    from .canary import plant

    try:
        record = plant(os.path.abspath(directory), name)
    except FileExistsError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)
    click.echo(f"  Planted decoy credentials in {record['file']}")
    click.echo("  Any use of them during `unworldly watch` is flagged as danger.")
    click.echo("  The decoy is added to .gitignore when one exists. Remove with `unworldly canary remove`.")


@canary.command(name="list")
@click.argument("directory", default=".")
def canary_list(directory: str) -> None:
    """Show planted decoys (not their values)."""
    from .canary import load

    planted = load(os.path.abspath(directory))
    if not planted:
        click.echo("  No canaries planted. Run `unworldly canary plant`.")
        return
    for c in planted:
        click.echo(f"  {c.get('file')}  (planted {c.get('created', '?')[:19]})")


@canary.command(name="remove")
@click.argument("directory", default=".")
def canary_remove(directory: str) -> None:
    """Delete all planted decoys."""
    from .canary import remove

    removed = remove(os.path.abspath(directory))
    click.echo(f"  Removed {len(removed)} decoy file(s)." if removed else "  No canaries to remove.")


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
    from .snapshot import snapshot_after, snapshot_before

    if mode == "before":
        snapshot_before(directory)
    else:
        snapshot_after(directory)


# ── review ────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("session", required=False)
@click.option("-o", "--output", default=None, help="Save review decisions to this JSON file.")
@click.option(
    "--all", "show_all", is_flag=True, default=False, help="Review safe events too (default: danger+caution only)."
)
def review(session: str | None, output: str | None, show_all: bool) -> None:
    """Interactively review session events — approve, flag, or skip each one."""
    session_path = session or get_latest_session(os.getcwd())
    if not session_path:
        click.echo("No sessions found. Run `unworldly watch` first.", err=True)
        sys.exit(1)
    from .review import review_command

    review_command(session_path, output=output, show_all=show_all)


# ── collect (OTel GenAI ingestion) ──────────────────────────────────────────────


@cli.command()
@click.argument("spans_file")
@click.option("--agent", "agent_name", default=None, help="Label the session with this agent name.")
def collect(spans_file: str, agent_name: str | None) -> None:
    """Ingest OpenTelemetry GenAI spans from a JSON file into a sealed session.

    Maps gen_ai.* tool/model spans (OpenAI Agents SDK, Google ADK, LangGraph,
    or any OTel-exporting agent) into an Unworldly audit trail.
    """
    from .otel_ingest import ingest_file

    session = ingest_file(spans_file, directory=os.getcwd(), agent_name=agent_name)
    click.echo(f"✓ Ingested {session.summary.total_events} event(s) from {spans_file}")
    click.echo(f"  Session {session.id} — risk score {session.summary.risk_score}/10")
    click.echo("  Review: unworldly report | verify | replay")


# ── mcp-proxy ───────────────────────────────────────────────────────────────────


@cli.command(name="mcp-proxy", context_settings={"ignore_unknown_options": True})
@click.option("--agent", "agent_name", default=None, help="Label the session with this agent name.")
@click.argument("target", nargs=-1, required=True)
def mcp_proxy(agent_name: str | None, target: tuple[str, ...]) -> None:
    """Proxy an MCP server, recording every tool call. No agent code changes.

    Example: unworldly mcp-proxy -- python my_mcp_server.py
    """
    from .mcp_proxy import run_stdio_proxy

    code = run_stdio_proxy(list(target), directory=os.getcwd(), agent_name=agent_name)
    sys.exit(code)


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
