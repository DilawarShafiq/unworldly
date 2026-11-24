"""Regression (0.8.3): odd file events must never stop the watcher from recording."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from watchdog.events import FileCreatedEvent

from unworldly import watcher
from unworldly.session import create_session
from unworldly.watcher import _real, _UnworldlyHandler

EXTENDED = "\\\\?\\"  # Windows extended-length prefix: \\?\


def test_real_strips_windows_extended_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os.path, "realpath", lambda p: EXTENDED + "C:\\proj\\x.tmp")
    assert _real("ignored") == "C:\\proj\\x.tmp"
    unc = EXTENDED + "UNC\\server\\share\\x"
    monkeypatch.setattr(os.path, "realpath", lambda p: unc)
    assert _real("ignored") == unc  # the UNC form is left alone


def test_vanished_temp_file_then_real_change_is_recorded(tmp_path: Path) -> None:
    session = create_session(str(tmp_path), sign=False)
    handler = _UnworldlyHandler(_real(str(tmp_path)), session)
    handler.on_created(FileCreatedEvent(str(tmp_path / "gone.tmp")))  # never existed / already renamed
    real = tmp_path / "app.py"
    real.write_text("x = 1\n", encoding="utf-8")
    handler.on_created(FileCreatedEvent(str(real)))
    assert any(e.path == "app.py" for e in session.events)


def test_an_exception_in_one_event_does_not_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = create_session(str(tmp_path), sign=False)
    handler = _UnworldlyHandler(str(tmp_path), session)

    def boom(*_a: object, **_k: object) -> None:
        raise ValueError("path is on mount " + EXTENDED + "C:, start on mount C:")

    monkeypatch.setattr(watcher, "assess_risk", boom)
    handler.on_created(FileCreatedEvent(str(tmp_path / "a.py")))  # must not raise
