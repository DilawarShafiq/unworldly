"""Shared test setup: never touch the developer's real OS keychain or home directory."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_identity_key(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from unworldly.signing import reset_identity_cache

    home: Path = tmp_path_factory.getbasetemp() / "unworldly-home"
    monkeypatch.setenv("UNWORLDLY_KEY_STORE", "file")
    monkeypatch.setenv("UNWORLDLY_HOME", str(home))
    reset_identity_cache()
    yield
    reset_identity_cache()
