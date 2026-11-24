"""End-to-end test: run the real `unworldly watch` CLI, act like an agent, then use every
read-side command on the session it produced.

Unit tests check pieces in isolation; this test catches whole-product breakage such as
command capture silently recording nothing on a platform.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

# Run the code under test, not whatever copy of unworldly is installed in site-packages.
_REPO = str(Path(__file__).resolve().parents[1])
ENV = {
    **os.environ,
    "PYTHONIOENCODING": "utf-8",
    "NO_COLOR": "1",
    "PYTHONPATH": os.pathsep.join(filter(None, [_REPO, os.environ.get("PYTHONPATH")])),
    # Never touch the developer's real OS keychain from tests.
    "UNWORLDLY_KEY_STORE": "file",
    "UNWORLDLY_HOME": tempfile.mkdtemp(prefix="unworldly-e2e-home-"),
}


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "unworldly.cli", *args],
        cwd=cwd,
        env=ENV,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )


def _wait_for(predicate, timeout: float = 20.0) -> bool:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return False


def _session_file(project: Path) -> Path | None:
    files = sorted((project / ".unworldly" / "sessions").glob("*.json"))
    return files[-1] if files else None


def _events(project: Path) -> list[dict]:  # type: ignore[type-arg]
    path = _session_file(project)
    if path is None:
        return []
    try:
        return list(json.loads(path.read_text(encoding="utf-8")).get("events", []))
    except (json.JSONDecodeError, OSError):
        return []  # file mid-write


@pytest.fixture(scope="module")
def recorded(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Record one real session: a risky file, a normal file, and a shell command."""
    project = tmp_path_factory.mktemp("project")
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    watcher = subprocess.Popen(
        [sys.executable, "-m", "unworldly.cli", "watch", str(project)],
        cwd=project,
        env=ENV,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    try:
        assert _wait_for(lambda: _session_file(project) is not None), "watch never created a session"
        time.sleep(1.5)  # let the file observer and process poller settle

        (project / ".env").write_text("API_KEY=x\n", encoding="utf-8")
        (project / "app.py").write_text("print('hi')\n", encoding="utf-8")
        subprocess.run(
            [sys.executable, "-c", "import time; time.sleep(2)  # unworldly-e2e-marker"],
            cwd=project,
            check=True,
        )

        def captured() -> bool:
            paths = [e.get("path", "") for e in _events(project)]
            return any(p.endswith(".env") for p in paths) and any("unworldly-e2e-marker" in p for p in paths)

        assert _wait_for(captured), f"events not captured: {[e.get('path') for e in _events(project)]}"
    finally:
        if sys.platform == "win32":
            watcher.terminate()  # session is saved after every event, so a hard stop loses nothing
        else:
            watcher.send_signal(signal.SIGINT)
        watcher.wait(timeout=15)
    return project


def test_watch_records_risky_file_as_danger(recorded: Path) -> None:
    env_events = [e for e in _events(recorded) if e["path"].endswith(".env")]
    assert env_events and env_events[0]["risk"] == "danger"


def test_watch_records_shell_command(recorded: Path) -> None:
    cmds = [e for e in _events(recorded) if e["type"] == "command"]
    assert any("unworldly-e2e-marker" in e["path"] for e in cmds)


def test_verify_passes_on_untouched_session(recorded: Path) -> None:
    result = _cli("verify", cwd=recorded)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SESSION VERIFIED" in result.stdout and "Signed by identity" in result.stdout


def test_session_is_signed_with_heartbeat_declared(recorded: Path) -> None:
    path = _session_file(recorded)
    assert path is not None
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["signing"]["scheme"] == "ed25519-fs-v1"
    assert data["signing"]["heartbeatSeconds"] == 30.0
    assert all("signature" in e for e in data["events"])


@pytest.mark.parametrize(
    "args",
    [
        ("list",),
        ("replay", "--speed", "1000"),
        ("report",),
        ("report", "--owasp"),
        ("touched",),
    ],
)
def test_read_commands_succeed(recorded: Path, args: tuple[str, ...]) -> None:
    result = _cli(*args, cwd=recorded)
    assert result.returncode == 0, result.stdout + result.stderr


def test_markdown_report_mentions_risky_file(recorded: Path) -> None:
    out = recorded / "report.md"
    result = _cli("report", "-f", "md", "-o", str(out), cwd=recorded)
    assert result.returncode == 0, result.stdout + result.stderr
    assert ".env" in out.read_text(encoding="utf-8")


def test_sarif_export_is_valid_json(recorded: Path) -> None:
    out = recorded / "session.sarif"
    result = _cli("export", "--sarif", "-o", str(out), cwd=recorded)
    assert result.returncode == 0, result.stdout + result.stderr
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]


def test_verify_detects_tampering(recorded: Path, tmp_path: Path) -> None:
    session_path = _session_file(recorded)
    assert session_path is not None
    data = json.loads(session_path.read_text(encoding="utf-8"))
    data["events"][0]["path"] = "innocent.txt"
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(data), encoding="utf-8")
    result = _cli("verify", str(tampered), cwd=recorded)
    assert result.returncode != 0
