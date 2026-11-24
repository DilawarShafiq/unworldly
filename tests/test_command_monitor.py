"""Tests for cross-platform command monitor."""

import time

from unworldly.command_monitor import CommandMonitor, create_command_monitor


class TestCommandMonitor:
    def test_create_monitor_instance(self):
        monitor = create_command_monitor()
        assert isinstance(monitor, CommandMonitor)

    def test_stop_cleanly_after_start(self):
        monitor = CommandMonitor()
        events = []
        monitor.start(".", lambda cmd: events.append(cmd))
        # Let it run briefly then stop
        monitor.stop()
        # Should not throw
        assert True

    def test_stop_cleanly_without_starting(self):
        monitor = CommandMonitor()
        # Should not throw
        monitor.stop()
        assert True

    def test_not_report_same_pid_twice(self):
        monitor = CommandMonitor()
        events = []
        monitor.start(".", lambda cmd: events.append(cmd))

        # Several poll cycles; new system processes may appear, but no PID may repeat.
        time.sleep(1.8)
        monitor.stop()

        pids = [cmd.pid for cmd in events]
        assert len(pids) == len(set(pids))


class TestSkipFilter:
    """The skip filter must match whole names, never fragments (regression: psql was dropped)."""

    def setup_method(self) -> None:
        from unworldly.command_monitor import CommandMonitor

        self.m = CommandMonitor()

    def test_real_commands_containing_skipped_fragments_are_kept(self) -> None:
        for exe in ["psql", "/usr/bin/psql", "gpsd", "apsw", r"C:\Tools\psql.exe"]:
            assert not self.m._should_skip(exe, ["-c", "select 1"]), exe

    def test_unworldly_helpers_are_skipped(self) -> None:
        for exe in ["ps", "wmic", r"C:\Windows\System32\wbem\WMIC.exe", "conhost.exe", "unworldly"]:
            assert self.m._should_skip(exe, []), exe

    def test_shell_running_a_command_is_kept_but_bare_shell_skipped(self) -> None:
        assert not self.m._should_skip("powershell.exe", ["-Command", "Remove-Item x"])
        assert not self.m._should_skip("cmd.exe", ["/c", "del x"])
        assert self.m._should_skip("powershell.exe", [])
        assert self.m._should_skip("pwsh", None)

    def test_node_modules_bin_is_skipped(self) -> None:
        assert self.m._should_skip("node_modules/.bin/tsc", [])


def test_create_command_monitor_returns_none_when_listing_fails(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from unworldly import command_monitor

    def boom(self):  # type: ignore[no-untyped-def]
        raise FileNotFoundError("wmic")

    monkeypatch.setattr(command_monitor.CommandMonitor, "_list_processes", boom)
    assert command_monitor.create_command_monitor() is None


def test_process_listing_works_on_this_platform() -> None:
    from unworldly.command_monitor import create_command_monitor

    monitor = create_command_monitor()
    assert monitor is not None
    assert len(monitor._list_processes()) > 0
