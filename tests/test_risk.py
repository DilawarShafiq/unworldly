"""Tests for file risk assessment."""

from unworldly.risk import assess_risk, calculate_risk_score, should_ignore
from unworldly.types import EventType, RiskLevel


class TestShouldIgnore:
    def test_ignore_node_modules(self):
        assert should_ignore("node_modules/lodash/index.js") is True

    def test_ignore_git_directory(self):
        assert should_ignore(".git/HEAD") is True

    def test_ignore_dist_directory(self):
        assert should_ignore("dist/index.js") is True

    def test_ignore_build_directory(self):
        assert should_ignore("build/output.js") is True

    def test_ignore_unworldly_directory(self):
        assert should_ignore(".unworldly/sessions/abc.json") is True

    def test_ignore_ds_store(self):
        assert should_ignore(".DS_Store") is True

    def test_ignore_swp_files(self):
        assert should_ignore("file.ts.swp") is True

    def test_ignore_tmp_files(self):
        assert should_ignore("data.tmp") is True

    def test_ignore_pycache(self):
        assert should_ignore("__pycache__/module.cpython-311.pyc") is True

    def test_not_ignore_regular_source_files(self):
        assert should_ignore("src/index.ts") is False

    def test_not_ignore_readme(self):
        assert should_ignore("README.md") is False

    def test_handle_windows_backslash_paths(self):
        assert should_ignore("node_modules\\lodash\\index.js") is True


class TestAssessRisk:
    class TestDangerFiles:
        def test_flag_env_as_danger(self):
            result = assess_risk(".env", EventType.MODIFY)
            assert result.level == RiskLevel.DANGER
            assert "Credential" in result.reason

        def test_flag_env_production_as_danger(self):
            result = assess_risk(".env.production", EventType.MODIFY)
            assert result.level == RiskLevel.DANGER

        def test_flag_pem_files_as_danger(self):
            result = assess_risk("cert.pem", EventType.CREATE)
            assert result.level == RiskLevel.DANGER
            assert "Certificate" in result.reason

        def test_flag_key_files_as_danger(self):
            result = assess_risk("private.key", EventType.CREATE)
            assert result.level == RiskLevel.DANGER
            assert "Private key" in result.reason

        def test_flag_id_rsa_as_danger(self):
            result = assess_risk(".ssh/id_rsa", EventType.MODIFY)
            assert result.level == RiskLevel.DANGER
            assert "SSH" in result.reason

        def test_flag_id_ed25519_as_danger(self):
            result = assess_risk("id_ed25519", EventType.MODIFY)
            assert result.level == RiskLevel.DANGER

        def test_flag_credentials_files_as_danger(self):
            result = assess_risk("config/credentials.json", EventType.MODIFY)
            assert result.level == RiskLevel.DANGER
            assert "Credentials" in result.reason

        def test_flag_secrets_files_as_danger(self):
            result = assess_risk("secrets.yaml", EventType.CREATE)
            assert result.level == RiskLevel.DANGER
            assert "Secrets" in result.reason

        def test_flag_aws_directory_as_danger(self):
            result = assess_risk(".aws/config", EventType.MODIFY)
            assert result.level == RiskLevel.DANGER
            assert "AWS" in result.reason

        def test_flag_kubeconfig_as_danger(self):
            result = assess_risk("kubeconfig", EventType.MODIFY)
            assert result.level == RiskLevel.DANGER
            assert "Kubernetes" in result.reason

        def test_flag_kube_directory_as_danger(self):
            result = assess_risk(".kube/config", EventType.MODIFY)
            assert result.level == RiskLevel.DANGER

        def test_flag_passwd_as_danger(self):
            result = assess_risk("/etc/passwd", EventType.MODIFY)
            assert result.level == RiskLevel.DANGER
            assert "System user" in result.reason

        def test_flag_shadow_as_danger(self):
            result = assess_risk("/etc/shadow", EventType.MODIFY)
            assert result.level == RiskLevel.DANGER
            assert "System password" in result.reason

    class TestCautionFiles:
        def test_flag_package_json_as_caution(self):
            result = assess_risk("package.json", EventType.MODIFY)
            assert result.level == RiskLevel.CAUTION
            assert "Dependency manifest" in result.reason

        def test_flag_package_lock_as_caution(self):
            result = assess_risk("package-lock.json", EventType.MODIFY)
            assert result.level == RiskLevel.CAUTION
            assert "Lock file" in result.reason

        def test_flag_yarn_lock_as_caution(self):
            result = assess_risk("yarn.lock", EventType.MODIFY)
            assert result.level == RiskLevel.CAUTION

        def test_flag_dockerfile_as_caution(self):
            result = assess_risk("Dockerfile", EventType.MODIFY)
            assert result.level == RiskLevel.CAUTION
            assert "Container" in result.reason

        def test_flag_docker_compose_as_caution(self):
            result = assess_risk("docker-compose.yml", EventType.MODIFY)
            assert result.level == RiskLevel.CAUTION

        def test_flag_github_workflow_as_caution(self):
            result = assess_risk(".github/workflows/ci.yml", EventType.MODIFY)
            assert result.level == RiskLevel.CAUTION
            assert "CI/CD" in result.reason

        def test_flag_gitignore_as_caution(self):
            result = assess_risk(".gitignore", EventType.MODIFY)
            assert result.level == RiskLevel.CAUTION

        def test_flag_tsconfig_as_caution(self):
            result = assess_risk("tsconfig.json", EventType.MODIFY)
            assert result.level == RiskLevel.CAUTION
            assert "TypeScript config" in result.reason

        def test_flag_webpack_config_as_caution(self):
            result = assess_risk("webpack.config.js", EventType.MODIFY)
            assert result.level == RiskLevel.CAUTION
            assert "Build config" in result.reason

        def test_flag_eslint_config_as_caution(self):
            result = assess_risk(".eslintrc.js", EventType.MODIFY)
            assert result.level == RiskLevel.CAUTION
            assert "Linter" in result.reason

        def test_flag_file_deletion_as_caution(self):
            result = assess_risk("src/utils.ts", EventType.DELETE)
            assert result.level == RiskLevel.CAUTION
            assert "File deleted" in result.reason

    class TestSafeFiles:
        def test_flag_regular_ts_files_as_safe(self):
            result = assess_risk("src/index.ts", EventType.MODIFY)
            assert result.level == RiskLevel.SAFE
            assert result.reason is None

        def test_flag_regular_js_files_as_safe(self):
            result = assess_risk("lib/utils.js", EventType.CREATE)
            assert result.level == RiskLevel.SAFE

        def test_flag_md_files_as_safe(self):
            result = assess_risk("README.md", EventType.MODIFY)
            assert result.level == RiskLevel.SAFE

        def test_flag_css_files_as_safe(self):
            result = assess_risk("styles/main.css", EventType.MODIFY)
            assert result.level == RiskLevel.SAFE

        def test_flag_new_file_creation_as_safe(self):
            result = assess_risk("src/newfile.ts", EventType.CREATE)
            assert result.level == RiskLevel.SAFE


class TestCalculateRiskScore:
    def test_return_0_for_empty_session(self):
        assert calculate_risk_score(0, 0, 0) == 0

    def test_return_0_for_all_safe_events(self):
        assert calculate_risk_score(10, 0, 0) == 0

    def test_return_10_for_all_danger_events(self):
        assert calculate_risk_score(0, 0, 1) == 10

    def test_return_moderate_score_for_mixed_events(self):
        score = calculate_risk_score(5, 3, 2)
        assert score > 0
        assert score <= 10

    def test_cap_at_10(self):
        score = calculate_risk_score(0, 0, 100)
        assert score == 10

    def test_weight_danger_higher_than_caution(self):
        caution_score = calculate_risk_score(10, 5, 0)
        danger_score = calculate_risk_score(10, 0, 5)
        assert danger_score > caution_score
