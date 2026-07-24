"""Tests for sensitive-argument redaction in the trace recorder (privacy NFR)."""

from unworldly.agent_trace import REDACTED, AgentTraceRecorder, redact_params
from unworldly.session import load_session
from unworldly.types import RiskLevel


class TestRedactParams:
    def test_sensitive_keys_are_redacted_wholesale(self):
        out = redact_params({"password": "hunter2", "api_key": "abc", "user": "ada"})
        assert out["password"] == REDACTED
        assert out["api_key"] == REDACTED
        assert out["user"] == "ada"  # non-sensitive key preserved

    def test_email_in_value_is_redacted(self):
        out = redact_params({"note": "contact me at jane.doe@example.com please"})
        assert "jane.doe@example.com" not in out["note"]
        assert REDACTED in out["note"]

    def test_bearer_token_is_redacted(self):
        out = redact_params({"headers": "Authorization: Bearer abc.def.ghi"})
        assert "abc.def.ghi" not in out["headers"]

    def test_long_blob_is_redacted(self):
        secret = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7"  # >32 chars
        out = redact_params({"data": secret})
        assert secret not in out["data"]
        assert REDACTED in out["data"]

    def test_nested_structures(self):
        out = redact_params({"outer": {"token": "xyz"}, "list": [{"secret": "s"}]})
        assert out["outer"]["token"] == REDACTED
        assert out["list"][0]["secret"] == REDACTED

    def test_short_benign_values_preserved(self):
        out = redact_params({"table": "users", "limit": 10})
        assert out == {"table": "users", "limit": 10}


class TestRecorderRedaction:
    def test_secret_never_written_to_disk(self, tmp_path):
        with AgentTraceRecorder(directory=str(tmp_path), agent_name="a") as rec:
            rec.record_tool_call("http.post", {"url": "https://x.io", "api_key": "SUPERSECRET"})
            path = rec.session_path
        raw = (open(path, encoding="utf-8").read())
        assert "SUPERSECRET" not in raw
        assert REDACTED in raw

    def test_risk_assessed_on_original_not_redacted(self, tmp_path):
        # 'private_key' in a value must still trigger DANGER even though it gets redacted.
        with AgentTraceRecorder(directory=str(tmp_path)) as rec:
            event = rec.record_tool_call("store", {"blob": "this is private_key material here"})
        assert event.risk == RiskLevel.DANGER

    def test_redaction_can_be_disabled(self, tmp_path):
        with AgentTraceRecorder(directory=str(tmp_path), redact=False) as rec:
            rec.record_tool_call("cfg", {"password": "keepme"})
            path = rec.session_path
        assert "keepme" in open(path, encoding="utf-8").read()
