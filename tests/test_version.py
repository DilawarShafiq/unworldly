"""Guards that the version has a single source of truth and never drifts.

`unworldly/_version.py` is the one place the version is defined. pyproject reads
it dynamically; cli/session/display/sarif/alerts import it. These tests fail
loudly if anyone reintroduces a hardcoded version string.
"""

from __future__ import annotations

import re
from pathlib import Path

from unworldly import __version__ as pkg_version
from unworldly._version import __version__

ROOT = Path(__file__).resolve().parent.parent


def test_version_is_valid_semver():
    assert re.match(r"^\d+\.\d+\.\d+([.-].+)?$", __version__), __version__


def test_package_reexports_same_version():
    assert pkg_version == __version__


def test_cli_reports_single_source_version():
    from click.testing import CliRunner

    from unworldly.cli import cli

    result = CliRunner().invoke(cli, ["--version"])
    assert __version__ in result.output


def test_create_session_uses_single_source_version():
    from unworldly.session import create_session

    assert create_session("/tmp/x").version == __version__


def test_no_hardcoded_version_literals_in_package():
    """No source file should contain a bare x.y.z version literal except _version.py."""
    # Only a *quoted* semver literal looks like a hardcoded version; bare
    # dotted numbers (e.g. the ISO control "A.6.2.8") are not versions.
    literal = re.compile(r"""['"]\d+\.\d+\.\d+['"]""")
    offenders = []
    for path in (ROOT / "unworldly").glob("*.py"):
        if path.name == "_version.py":
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            # Ignore the SARIF schema version and comments referencing releases.
            if "2.1.0" in line or line.lstrip().startswith("#"):
                continue
            if literal.search(line) and "__version__" not in line:
                offenders.append(f"{path.name}:{i}: {line.strip()}")
    assert not offenders, "Hardcoded version literals found:\n" + "\n".join(offenders)
