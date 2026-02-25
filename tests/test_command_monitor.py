"""Tests for cross-platform command monitor."""

import time
import pytest
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

        # Wait for two poll cycles
        time.sleep(1.2)
        count = len(events)

        # Wait another cycle -- should not get duplicates of existing processes
        time.sleep(0.6)

        monitor.stop()
        # The count should not have significantly increased from duplicate reporting
        # (new system processes may appear, but existing ones should not repeat)
        assert len(events) <= count + 5
