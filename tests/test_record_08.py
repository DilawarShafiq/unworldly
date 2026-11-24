"""0.8 Record: file content changes (R3), outside-project watching (R2), agent model (R4)."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from unworldly.agent_detect import detect_agent, detect_model
from unworldly.agent_trace import REDACTED, redact_text
from unworldly.content import MAX_DIFF_LINES, TOO_LARGE, ContentTracker
from unworldly.integrity import TAMPERED, VERIFIED, verify_session
from unworldly.session import add_event, close_session, create_session
from unworldly.types import EventType, RiskLevel, WatchEvent


class TestContentTracker:
    def test_second_modify_chains_hashes_and_diffs(self, tmp_path: Path) -> None:
        tracker = ContentTracker(str(tmp_path))
        f = tmp_path / "app.py"
        f.write_text("a = 1\n", encoding="utf-8")
        first = tracker.describe("app.py", EventType.CREATE, RiskLevel.SAFE)
        f.write_text("a = 2\n", encoding="utf-8")
        second = tracker.describe("app.py", EventType.MODIFY, RiskLevel.SAFE)
        assert second.before_hash == first.after_hash != second.after_hash
        assert second.diff is not None and "-a = 1" in second.diff and "+a = 2" in second.diff

    def test_create_diffs_against_nothing(self, tmp_path: Path) -> None:
        (tmp_path / "new.py").write_text("print('hi')\n", encoding="utf-8")
        change = ContentTracker(str(tmp_path)).describe("new.py", EventType.CREATE, RiskLevel.SAFE)
        assert change.before_hash is None and change.diff is not None and "+print('hi')" in change.diff

    def test_secrets_in_diff_are_redacted(self, tmp_path: Path) -> None:
        tracker = ContentTracker(str(tmp_path))
        f = tmp_path / "settings.py"
        f.write_text("DEBUG = True\n", encoding="utf-8")
        tracker.describe("settings.py", EventType.CREATE, RiskLevel.SAFE)
        f.write_text('DEBUG = True\nAPI_KEY = "sk-live-abc123"\npassword: hunter2\n', encoding="utf-8")
        change = tracker.describe("settings.py", EventType.MODIFY, RiskLevel.SAFE)
        assert change.diff is not None
        assert "sk-live-abc123" not in change.diff and "hunter2" not in change.diff
        assert REDACTED in change.diff

    def test_danger_files_get_hashes_but_no_diff(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("SECRET=x\n", encoding="utf-8")
        change = ContentTracker(str(tmp_path)).describe(".env", EventType.CREATE, RiskLevel.DANGER)
        assert change.after_hash and change.diff is None

    def test_binary_gets_no_diff(self, tmp_path: Path) -> None:
        (tmp_path / "img.bin").write_bytes(b"\x89PNG\x00\x01\x02")
        change = ContentTracker(str(tmp_path)).describe("img.bin", EventType.CREATE, RiskLevel.SAFE)
        assert change.after_hash and change.diff is None

    def test_large_diff_is_truncated(self, tmp_path: Path) -> None:
        tracker = ContentTracker(str(tmp_path))
        f = tmp_path / "big.txt"
        f.write_text("", encoding="utf-8")
        tracker.describe("big.txt", EventType.CREATE, RiskLevel.SAFE)
        f.write_text("".join(f"line {i}\n" for i in range(1000)), encoding="utf-8")
        change = tracker.describe("big.txt", EventType.MODIFY, RiskLevel.SAFE)
        assert change.diff is not None and "diff truncated" in change.diff
        assert change.diff.count("\n") <= MAX_DIFF_LINES + 1

    def test_too_large_is_hash_only_marker(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from unworldly import content

        monkeypatch.setattr(content, "MAX_HASH_BYTES", 10)
        (tmp_path / "huge.txt").write_text("x" * 100, encoding="utf-8")
        change = ContentTracker(str(tmp_path)).describe("huge.txt", EventType.CREATE, RiskLevel.SAFE)
        assert change.after_hash == TOO_LARGE and change.diff is None

    def test_delete_keeps_before_hash(self, tmp_path: Path) -> None:
        tracker = ContentTracker(str(tmp_path))
        f = tmp_path / "gone.py"
        f.write_text("x\n", encoding="utf-8")
        created = tracker.describe("gone.py", EventType.CREATE, RiskLevel.SAFE)
        f.unlink()
        deleted = tracker.describe("gone.py", EventType.DELETE, RiskLevel.CAUTION)
        assert deleted.before_hash == created.after_hash and deleted.after_hash is None


def test_redact_text_handles_common_forms() -> None:
    text = "token=abc123\nAuthorization: Bearer xyz.abc\nemail me@example.com\nsafe = 1\n"
    out = redact_text(text)
    assert "abc123" not in out and "xyz.abc" not in out and "me@example.com" not in out
    assert "safe = 1" in out


class TestContentIsSigned:
    def _session(self, tmp_path: Path):  # type: ignore[no-untyped-def]
        session = create_session(str(tmp_path))
        add_event(
            session,
            WatchEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                type=EventType.MODIFY,
                path="app.py",
                risk=RiskLevel.SAFE,
                before_hash="a" * 64,
                after_hash="b" * 64,
                diff="-x\n+y\n",
            ),
        )
        close_session(session, str(tmp_path))
        return session

    def test_verified(self, tmp_path: Path) -> None:
        assert verify_session(self._session(tmp_path)).status == VERIFIED

    def test_editing_diff_is_tampering(self, tmp_path: Path) -> None:
        session = self._session(tmp_path)
        session.events[0].diff = "-x\n+innocent\n"
        assert verify_session(session).status == TAMPERED

    def test_editing_actor_is_tampering(self, tmp_path: Path) -> None:
        from unworldly.types import CommandInfo

        session = create_session(str(tmp_path))
        add_event(
            session,
            WatchEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                type=EventType.COMMAND,
                path="rm -rf build",
                risk=RiskLevel.CAUTION,
                command=CommandInfo(executable="rm", args=["-rf", "build"], cwd=".", pid=1, actor="agent"),
            ),
        )
        close_session(session, str(tmp_path))
        assert session.events[0].command is not None
        session.events[0].command.actor = "other"
        assert verify_session(session).status == TAMPERED


class TestOutsideProject:
    def test_ssh_write_is_recorded_as_danger(self, tmp_path: Path) -> None:
        from watchdog.observers import Observer

        from unworldly.watcher import schedule_outside_watches

        home = tmp_path / "home"
        (home / ".ssh").mkdir(parents=True)
        project = tmp_path / "project"
        project.mkdir()
        session = create_session(str(project), sign=False)
        observer = Observer()
        watched = schedule_outside_watches(observer, session, str(project), None, home=str(home))
        observer.start()
        try:
            assert "~/.ssh" in watched
            time.sleep(0.5)
            (home / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAA attacker\n", encoding="utf-8")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not session.events:
                time.sleep(0.1)
        finally:
            observer.stop()
            observer.join()
        assert session.events, "write to ~/.ssh was not recorded"
        event = session.events[0]
        assert event.path == "~/.ssh/authorized_keys" and event.risk == RiskLevel.DANGER
        assert event.diff is None  # never content outside the project

    def test_only_existing_locations_are_watched(self, tmp_path: Path) -> None:
        from unworldly.watcher import schedule_outside_watches

        class FakeObserver:
            def __init__(self) -> None:
                self.paths: list[str] = []

            def schedule(self, handler: object, path: str, recursive: bool) -> None:
                self.paths.append(path)

        home = tmp_path / "home"
        home.mkdir()
        (home / ".zshrc").write_text("", encoding="utf-8")
        observer = FakeObserver()
        watched = schedule_outside_watches(
            observer, create_session(str(tmp_path), sign=False), str(tmp_path / "p"), None, home=str(home)
        )
        assert watched == ["~/.zshrc"]
        assert not (home / ".ssh").exists()  # nothing created

    def test_locations_inside_the_project_are_skipped(self, tmp_path: Path) -> None:
        from unworldly.watcher import schedule_outside_watches

        class FakeObserver:
            def schedule(self, handler: object, path: str, recursive: bool) -> None:
                raise AssertionError("should not schedule")

        (tmp_path / ".ssh").mkdir()
        assert (
            schedule_outside_watches(
                FakeObserver(), create_session(str(tmp_path), sign=False), str(tmp_path), None, home=str(tmp_path)
            )
            == []
        )


class TestAgentModel:
    def test_model_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-5-5")
        assert detect_model() == "claude-opus-5-5"

    def test_model_from_agent_command_line(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess
        import sys

        for var in ("ANTHROPIC_MODEL", "CLAUDE_MODEL", "OPENAI_MODEL", "AIDER_MODEL"):
            monkeypatch.delenv(var, raising=False)
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3)", "--model", "gpt-test"])
        try:
            time.sleep(0.3)
            assert detect_model({proc.pid}) == "gpt-test"
        finally:
            proc.kill()

    def test_no_model_is_never_guessed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in ("ANTHROPIC_MODEL", "CLAUDE_MODEL", "OPENAI_MODEL", "AIDER_MODEL"):
            monkeypatch.delenv(var, raising=False)
        assert detect_model(set()) is None

    def test_api_key_alone_is_not_claude_code(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in list(os.environ):
            if var.startswith(
                ("CLAUDE", "CURSOR", "COPILOT", "GITHUB_COPILOT", "WINDSURF", "DEVIN", "AIDER", "OPENCLAW", "CLINE")
            ):
                monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        agent = detect_agent()
        assert agent is None or "environment variable" not in agent.detected_via

    def test_claude_code_pid_comes_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CLAUDECODE", "1")
        monkeypatch.setenv("CLAUDE_PID", "4242")
        agent = detect_agent()
        assert agent is not None and agent.name == "Claude Code" and agent.pid == 4242
