"""0.10.1 signed incident packets (specs/forensics-0.10/spec.md, L3)."""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from click.testing import CliRunner

from unworldly.cli import cli
from unworldly.incident import create_packet, verify_packet
from unworldly.session import add_event, close_session, create_session
from unworldly.types import EventType, RiskLevel, WatchEvent


def _recorded(tmp_path: Path) -> str:
    session = create_session(str(tmp_path))
    for i, (cmd, risk) in enumerate(
        [("npm test", RiskLevel.SAFE), ("terraform destroy -auto-approve", RiskLevel.DANGER)]
    ):
        add_event(session, WatchEvent(datetime.now(timezone.utc).isoformat(), EventType.COMMAND, cmd, risk, f"r{i}"))
    return close_session(session, str(tmp_path))


def _rewrite(packet: Path, out: Path, change: dict[str, bytes | None]) -> None:
    """Copy a packet, replacing (bytes) or dropping (None) entries, or adding new ones."""
    with zipfile.ZipFile(packet) as src, zipfile.ZipFile(out, "w") as dst:
        for name in src.namelist():
            if name in change:
                if change[name] is not None:
                    dst.writestr(name, change[name])  # type: ignore[arg-type]
            else:
                dst.writestr(name, src.read(name))
        for name, data in change.items():
            if name not in src.namelist() and data is not None:
                dst.writestr(name, data)


def test_round_trip_verifies(tmp_path: Path) -> None:
    packet = Path(create_packet(_recorded(tmp_path), str(tmp_path / "p.zip")))
    names = set(zipfile.ZipFile(packet).namelist())
    assert {
        "session.json",
        "report.md",
        "flags.json",
        "verify.json",
        "credentials.json",
        "README.txt",
        "manifest.json",
    } <= names
    check = verify_packet(str(packet))
    assert check.ok and check.session_status == "VERIFIED" and check.packager_fingerprint


def test_flags_and_report_are_inside(tmp_path: Path) -> None:
    packet = create_packet(_recorded(tmp_path), str(tmp_path / "p.zip"))
    with zipfile.ZipFile(packet) as zf:
        flags = json.loads(zf.read("flags.json"))
        assert any(f["kind"] == "blast-radius" for f in flags)
        assert "Unworldly Security Report" in zf.read("report.md").decode("utf-8")


def test_modified_file_fails(tmp_path: Path) -> None:
    packet = Path(create_packet(_recorded(tmp_path), str(tmp_path / "p.zip")))
    bad = tmp_path / "bad.zip"
    _rewrite(packet, bad, {"report.md": b"# nothing happened here"})
    check = verify_packet(str(bad))
    assert not check.ok and any("report.md was modified" in p for p in check.problems)


def test_added_and_removed_files_fail(tmp_path: Path) -> None:
    packet = Path(create_packet(_recorded(tmp_path), str(tmp_path / "p.zip")))
    added, removed = tmp_path / "added.zip", tmp_path / "removed.zip"
    _rewrite(packet, added, {"extra.txt": b"hi"})
    _rewrite(packet, removed, {"flags.json": None})
    assert not verify_packet(str(added)).ok and not verify_packet(str(removed)).ok


def test_rehashed_manifest_without_the_key_fails(tmp_path: Path) -> None:
    """Changing a file and updating its hash in the manifest still fails: the signature breaks."""
    import hashlib

    packet = Path(create_packet(_recorded(tmp_path), str(tmp_path / "p.zip")))
    with zipfile.ZipFile(packet) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    forged = b"# nothing happened here"
    manifest["files"]["report.md"] = hashlib.sha256(forged).hexdigest()
    bad = tmp_path / "bad.zip"
    _rewrite(packet, bad, {"report.md": forged, "manifest.json": json.dumps(manifest).encode()})
    check = verify_packet(str(bad))
    assert not check.ok and any("signature invalid" in p for p in check.problems)


def test_tampered_session_inside_a_resigned_packet_still_fails(tmp_path: Path) -> None:
    """Even a packet re-signed by someone else can't hide an edited session: its own signatures break."""
    session_path = Path(_recorded(tmp_path))
    data = json.loads(session_path.read_text(encoding="utf-8"))
    data["events"][1]["path"] = "npm run lint"  # hide the terraform destroy
    session_path.write_text(json.dumps(data), encoding="utf-8")
    packet = create_packet(str(session_path), str(tmp_path / "p.zip"))
    check = verify_packet(packet)
    assert not check.ok and check.session_status == "TAMPERED"


def test_not_a_zip(tmp_path: Path) -> None:
    junk = tmp_path / "junk.zip"
    junk.write_text("not a zip", encoding="utf-8")
    assert not verify_packet(str(junk)).ok


def test_cli_create_and_verify(tmp_path: Path) -> None:
    runner = CliRunner()
    session = _recorded(tmp_path)
    out = tmp_path / "pkt.zip"
    assert runner.invoke(cli, ["incident", session, "-o", str(out)]).exit_code == 0
    result = runner.invoke(cli, ["incident", "--verify", str(out)])
    assert result.exit_code == 0 and "PACKET VERIFIED" in result.output
    bad = tmp_path / "bad.zip"
    _rewrite(out, bad, {"report.md": b"x"})
    assert runner.invoke(cli, ["incident", "--verify", str(bad)]).exit_code == 1
