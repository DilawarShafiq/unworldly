"""Tests for lossless shell-hook command capture."""

import os
import time

import pytest

from unworldly.shell_hook import (
    MARKER_END,
    MARKER_START,
    SUPPORTED_SHELLS,
    ShellHookMonitor,
    create_shell_hook_monitor,
    detect_shell,
    hook_snippet,
    install_hook,
    is_installed,
    parse_hook_line,
    rc_path,
    uninstall_hook,
)
from unworldly.types import CommandInfo


class TestParseHookLine:
    def test_parses_well_formed_line(self):
        line = "2026-07-24T12:00:00Z\t/home/dev/proj\t4242\tgit commit -m wip"
        info = parse_hook_line(line)
        assert isinstance(info, CommandInfo)
        assert info.executable == "git"
        assert info.args == ["commit", "-m", "wip"]
        assert info.cwd == "/home/dev/proj"
        assert info.pid == 4242

    def test_basenames_the_executable(self):
        info = parse_hook_line("t\t/c\t1\t/usr/bin/curl https://x.io")
        assert info is not None
        assert info.executable == "curl"
        assert info.args == ["https://x.io"]

    def test_trailing_newline_is_stripped(self):
        info = parse_hook_line("t\t/c\t1\tls -la\n")
        assert info is not None
        assert info.executable == "ls"
        assert info.args == ["-la"]

    @pytest.mark.parametrize("bad", ["", "   ", "only\ttwo", "a\tb\tc"])
    def test_malformed_lines_return_none(self, bad):
        assert parse_hook_line(bad) is None

    def test_empty_command_returns_none(self):
        assert parse_hook_line("t\t/c\t1\t   ") is None

    def test_non_numeric_pid_falls_back(self):
        info = parse_hook_line("t\t/c\tnotapid\tls")
        assert info is not None
        assert info.pid == -1


class TestSnippets:
    @pytest.mark.parametrize("shell", SUPPORTED_SHELLS)
    def test_snippet_is_wrapped_in_markers(self, shell):
        snip = hook_snippet(shell)
        assert snip.startswith(MARKER_START)
        assert MARKER_END in snip

    @pytest.mark.parametrize("shell", SUPPORTED_SHELLS)
    def test_snippet_writes_to_commands_log(self, shell):
        assert "commands.log" in hook_snippet(shell)

    def test_unsupported_shell_raises(self):
        with pytest.raises(ValueError):
            hook_snippet("fish")

    def test_detect_shell_returns_supported(self):
        assert detect_shell() in SUPPORTED_SHELLS


class TestInstallUninstall:
    def test_install_then_uninstall_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        assert not is_installed("bash")

        resolved, path = install_hook("bash")
        assert resolved == "bash"
        assert is_installed("bash")
        assert MARKER_START in path.read_text(encoding="utf-8")

        removed, _ = uninstall_hook("bash")
        assert removed is True
        assert not is_installed("bash")

    def test_install_is_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        install_hook("bash")
        install_hook("bash")
        text = rc_path("bash").read_text(encoding="utf-8")
        assert text.count(MARKER_START) == 1

    def test_install_preserves_existing_content(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        rc = rc_path("bash")
        rc.write_text("export FOO=bar\n", encoding="utf-8")
        install_hook("bash")
        text = rc.read_text(encoding="utf-8")
        assert "export FOO=bar" in text
        assert MARKER_START in text

    def test_uninstall_when_absent_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        removed, _ = uninstall_hook("bash")
        assert removed is False


class TestShellHookMonitor:
    def test_create_monitor_instance(self):
        assert isinstance(create_shell_hook_monitor(), ShellHookMonitor)

    def test_stop_cleanly_without_starting(self):
        ShellHookMonitor().stop()  # should not raise

    def test_captures_appended_commands(self, tmp_path):
        (tmp_path / ".unworldly").mkdir()
        log = tmp_path / ".unworldly" / "commands.log"
        log.write_text("", encoding="utf-8")

        captured: list[CommandInfo] = []
        monitor = ShellHookMonitor()
        monitor.start(str(tmp_path), captured.append)
        try:
            # Give the tail thread a moment to open at EOF, then append.
            time.sleep(0.3)
            with open(log, "a", encoding="utf-8") as fh:
                fh.write("2026-07-24T12:00:00Z\t/x\t1\tnpm install left-pad\n")
                fh.flush()
            deadline = time.time() + 3.0
            while not captured and time.time() < deadline:
                time.sleep(0.1)
        finally:
            monitor.stop()

        assert len(captured) == 1
        assert captured[0].executable == "npm"
        assert captured[0].args == ["install", "left-pad"]

    def test_does_not_replay_preexisting_lines(self, tmp_path):
        (tmp_path / ".unworldly").mkdir()
        log = tmp_path / ".unworldly" / "commands.log"
        log.write_text("2026-07-24T12:00:00Z\t/x\t1\tls\n", encoding="utf-8")

        captured: list[CommandInfo] = []
        monitor = ShellHookMonitor()
        monitor.start(str(tmp_path), captured.append)
        try:
            time.sleep(0.5)
        finally:
            monitor.stop()

        assert captured == []

    def test_log_path_points_into_unworldly(self, tmp_path):
        p = ShellHookMonitor().log_path(str(tmp_path))
        assert p.name == "commands.log"
        assert os.path.basename(os.path.dirname(p)) == ".unworldly"
