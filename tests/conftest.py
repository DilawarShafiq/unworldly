"""Shared test setup: never touch the developer's real OS keychain, home folder or credentials."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_identity_key(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from unworldly.signing import reset_identity_cache

    base: Path = tmp_path_factory.getbasetemp()
    monkeypatch.setenv("UNWORLDLY_KEY_STORE", "file")
    monkeypatch.setenv("UNWORLDLY_HOME", str(base / "unworldly-home"))
    # Credential lineage indexes ~/.aws/credentials etc.; point "home" at an empty folder.
    fake_home = base / "user-home"
    fake_home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    reset_identity_cache()
    yield
    reset_identity_cache()
