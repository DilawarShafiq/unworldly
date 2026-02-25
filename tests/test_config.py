"""Tests for configuration loader."""

import json
import os
import tempfile
import shutil
import pytest
from unworldly.config import load_config


class TestLoadConfig:
    def setup_method(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="unworldly-test-")

    def teardown_method(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_return_defaults_when_no_config_file_exists(self):
        config = load_config(self.tmp_dir)
        assert config.commands.allowlist == []
        assert config.commands.blocklist == []

    def test_load_config_from_unworldly_config_json(self):
        config_dir = os.path.join(self.tmp_dir, ".unworldly")
        os.makedirs(config_dir, exist_ok=True)
        config_data = {
            "commands": {
                "allowlist": [{"pattern": "my-tool", "risk": "safe", "reason": "Internal tool"}],
                "blocklist": [{"pattern": "evil-pkg", "risk": "danger", "reason": "Malicious"}],
            }
        }
        with open(os.path.join(config_dir, "config.json"), "w") as f:
            json.dump(config_data, f)

        config = load_config(self.tmp_dir)
        assert len(config.commands.allowlist) == 1
        assert config.commands.allowlist[0]["pattern"] == "my-tool"
        assert len(config.commands.blocklist) == 1
        assert config.commands.blocklist[0]["pattern"] == "evil-pkg"

    def test_return_defaults_for_malformed_json(self):
        config_dir = os.path.join(self.tmp_dir, ".unworldly")
        os.makedirs(config_dir, exist_ok=True)
        with open(os.path.join(config_dir, "config.json"), "w") as f:
            f.write("not valid json{{{")

        config = load_config(self.tmp_dir)
        assert config.commands.allowlist == []
        assert config.commands.blocklist == []

    def test_handle_partial_config_gracefully(self):
        config_dir = os.path.join(self.tmp_dir, ".unworldly")
        os.makedirs(config_dir, exist_ok=True)
        config_data = {
            "commands": {
                "allowlist": [{"pattern": "foo", "risk": "safe", "reason": "OK"}]
            }
        }
        with open(os.path.join(config_dir, "config.json"), "w") as f:
            json.dump(config_data, f)

        config = load_config(self.tmp_dir)
        assert len(config.commands.allowlist) == 1
        assert config.commands.blocklist == []
