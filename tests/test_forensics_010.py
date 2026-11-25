"""0.10 forensic readiness: credential lineage, custody, blast radius (specs/forensics-0.10/spec.md)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from unworldly.agent_trace import AgentTraceRecorder
from unworldly.cli import cli
from unworldly.content import ContentTracker
from unworldly.credentials import CredentialIndex, extract
from unworldly.custody import collect_custody, describe_custody
from unworldly.flags import find_flags
from unworldly.integrity import TAMPERED, VERIFIED, verify_session
from unworldly.session import (
    add_event,
    close_session,
    create_session,
    load_session,
    record_credential_index,
    record_custody,
)
from unworldly.types import EventType, RiskLevel, WatchEvent

TOKEN = "rw_live_9f8e7d6c5b4a3210"  # a fake Railway-style token, 24 chars


def _project(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / ".env").write_text(
        f"RAILWAY_TOKEN={TOKEN}\nDEBUG=true\nSHORT=abc\nAPI_KEY=your-api-key-here\n", encoding="utf-8"
    )
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / ".env").write_text("NPM_SECRET=should_not_be_indexed_123\n", encoding="utf-8")
    return tmp_path


class TestIndex:
    def test_extract_skips_short_values_and_placeholders(self) -> None:
        names = {
            c.name for c in extract(f"RAILWAY_TOKEN={TOKEN}\nSHORT_TOKEN=abc\nAPI_KEY=your-api-key-here\n", ".env")
        }
        assert names == {"RAILWAY_TOKEN"}

    def test_extract_known_formats_without_a_sensitive_name(self) -> None:
        creds = extract("x = AKIAIOSFODNN7EXAMPLA\n", "conf.py")
        assert creds and creds[0].name == "AWS access key"

    def test_build_indexes_project_and_home_but_not_ignored_dirs(self, tmp_path: Path) -> None:
        project = _project(tmp_path / "p")
        home = tmp_path / "home"
        (home / ".aws").mkdir(parents=True)
        (home / ".aws" / "credentials").write_text(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzq81x\n", encoding="utf-8"
        )
        index = CredentialIndex(str(project), home=str(home)).build()
        refs = {c["source"] + "#" + c["name"] for c in index.summary()["credentials"]}
        assert ".env#RAILWAY_TOKEN" in refs and "~/.aws/credentials#aws_secret_access_key" in refs
        assert not any("node_modules" in r for r in refs)

    def test_summary_never_contains_values(self, tmp_path: Path) -> None:
        index = CredentialIndex(str(_project(tmp_path)), home=str(tmp_path / "nohome")).build()
        assert TOKEN not in str(index.summary())
        assert len(index.summary()["credentials"][0]["fingerprint"]) == 16

    def test_fingerprint_is_stable_for_a_salt(self, tmp_path: Path) -> None:
        a = CredentialIndex(str(tmp_path), salt="00" * 16)
        b = CredentialIndex(str(tmp_path), salt="00" * 16)
        c = CredentialIndex(str(tmp_path), salt="11" * 16)
        assert a.fingerprint(TOKEN) == b.fingerprint(TOKEN) != c.fingerprint(TOKEN)

    def test_use_reference_and_redaction(self, tmp_path: Path) -> None:
        index = CredentialIndex(str(_project(tmp_path)), home=str(tmp_path / "nohome")).build()
        assert [c.name for c in index.used_values(f"curl -H 'Authorization: {TOKEN}' api")] == ["RAILWAY_TOKEN"]
        assert [c.name for c in index.referenced_names("railway up --token $RAILWAY_TOKEN")] == ["RAILWAY_TOKEN"]
        assert [c.name for c in index.referenced_names("echo %RAILWAY_TOKEN% ${RAILWAY_TOKEN}")] == ["RAILWAY_TOKEN"]
        assert index.redact(f"x {TOKEN} y") == "x ***RAILWAY_TOKEN*** y"

    def test_credential_written_into_a_file_is_traced_and_redacted(self, tmp_path: Path) -> None:
        project = _project(tmp_path)
        index = CredentialIndex(str(project), home=str(tmp_path / "nohome")).build()
        tracker = ContentTracker(str(project), credentials=index)
        (project / "deploy.py").write_text(f"TOKEN = '{TOKEN}'\n", encoding="utf-8")
        change = tracker.describe("deploy.py", EventType.CREATE, RiskLevel.SAFE)
        assert change.credentials == [".env#RAILWAY_TOKEN"]
        assert change.diff is not None and TOKEN not in change.diff


class TestToolCalls:
    def test_tool_call_using_a_credential(self, tmp_path: Path) -> None:
        project = _project(tmp_path)
        with AgentTraceRecorder(directory=str(project)) as rec:
            event = rec.record_tool_call("railway.volume_delete", {"volume": "prod-db", "auth": f"Bearer {TOKEN}"})
            path = rec.session_path
        assert event.risk == RiskLevel.DANGER and event.credentials == [".env#RAILWAY_TOKEN"]
        assert TOKEN not in Path(path).read_text(encoding="utf-8")
        assert verify_session(load_session(path)).status == VERIFIED


class TestCustodyAndSigning:
    def _session(self, tmp_path: Path):  # type: ignore[no-untyped-def]
        session = create_session(str(tmp_path))
        record_custody(session, collect_custody(str(tmp_path), None, "poll"))
        record_credential_index(session, CredentialIndex(str(_project(tmp_path))).build().summary())
        add_event(
            session,
            WatchEvent(
                datetime.now(timezone.utc).isoformat(),
                EventType.COMMAND,
                "railway volume delete",
                RiskLevel.DANGER,
                "x",
                credentials=[".env#RAILWAY_TOKEN"],
            ),
        )
        close_session(session, str(tmp_path))
        return session

    def test_custody_contents(self, tmp_path: Path) -> None:
        custody = collect_custody(str(tmp_path), None, "hook")
        assert custody["osUser"] and custody["host"] and custody["capture"] == "hook"
        assert custody["recorder"]["pid"] > 0
        assert describe_custody(custody)[0][0] == "Run by"

    def test_ci_provenance_recorded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_ACTOR", "octocat")
        custody = collect_custody(str(tmp_path), None)
        assert custody["ci"]["GITHUB_ACTOR"] == "octocat"
        assert any(label == "CI run" for label, _ in describe_custody(custody))

    def test_signed_session_verifies(self, tmp_path: Path) -> None:
        assert verify_session(self._session(tmp_path)).status == VERIFIED

    def test_editing_custody_is_tampering(self, tmp_path: Path) -> None:
        session = self._session(tmp_path)
        assert session.custody is not None
        session.custody["osUser"] = "someone-else"
        assert verify_session(session).status == TAMPERED

    def test_editing_the_credential_index_is_tampering(self, tmp_path: Path) -> None:
        session = self._session(tmp_path)
        assert session.credential_index is not None
        session.credential_index["credentials"] = []
        assert verify_session(session).status == TAMPERED

    def test_editing_event_credentials_is_tampering(self, tmp_path: Path) -> None:
        session = self._session(tmp_path)
        session.events[0].credentials = []
        assert verify_session(session).status == TAMPERED

    def test_credentials_command_shows_names_not_values(self, tmp_path: Path) -> None:
        self._session(tmp_path)
        path = next((tmp_path / ".unworldly" / "sessions").glob("*.json"))
        out = CliRunner().invoke(cli, ["credentials", str(path)]).output
        assert "RAILWAY_TOKEN" in out and "USED" in out and TOKEN not in out


def _flags(cmd: str) -> list[str]:
    session = create_session(".", sign=False)
    add_event(session, WatchEvent(datetime.now(timezone.utc).isoformat(), EventType.COMMAND, cmd, RiskLevel.SAFE))
    return [f.kind for f in find_flags(session)]


@pytest.mark.parametrize(
    "cmd",
    [
        "terraform destroy -auto-approve",
        "terraform apply -destroy",
        "pulumi destroy --yes",
        "kubectl delete namespace prod",
        "kubectl delete pvc data-0",
        "kubectl delete pods --all",
        "helm uninstall api",
        "aws rds delete-db-instance --db-instance-identifier prod-db",
        "aws s3 rb s3://backups --force",
        "aws s3 rm s3://data --recursive",
        "aws dynamodb delete-table --table-name users",
        "aws ec2 terminate-instances --instance-ids i-1",
        "gcloud sql instances delete prod",
        "az group delete -n prod-rg",
        "railway volume delete",
        "railway down",
        "fly apps destroy api",
        "heroku pg:reset DATABASE_URL",
        "supabase db reset",
        'psql -c "DROP TABLE users"',
        'psql -c "DELETE FROM users;"',
        "mysql -e 'TRUNCATE TABLE orders'",
        "redis-cli FLUSHALL",
        "npx prisma migrate reset --force",
        "npx prisma db push --accept-data-loss",
        "rails db:drop",
        "python manage.py flush",
        "docker volume prune -f",
    ],
)
def test_blast_radius_flagged(cmd: str) -> None:
    assert "blast-radius" in _flags(cmd.replace("FLUSHALL", "flushall"))


@pytest.mark.parametrize(
    "cmd",
    [
        "kubectl get pods",
        "terraform plan",
        "aws s3 ls",
        'psql -c "DELETE FROM users WHERE id = 1"',
        "helm list",
        "railway up",
        "docker ps",
        "aws rds describe-db-instances",
    ],
)
def test_harmless_lookalikes_not_flagged(cmd: str) -> None:
    assert "blast-radius" not in _flags(cmd)


def test_production_is_called_out() -> None:
    session = create_session(".", sign=False)
    add_event(
        session,
        WatchEvent(
            datetime.now(timezone.utc).isoformat(),
            EventType.COMMAND,
            "kubectl delete namespace production",
            RiskLevel.SAFE,
        ),
    )
    assert "PRODUCTION" in find_flags(session)[0].message
