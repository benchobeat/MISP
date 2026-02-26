"""Tests for configuration loading."""

import os
import tempfile

import pytest

from qradar_misp_sync.config import load_config


def _write_config(content: str) -> str:
    """Write a config string to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


class TestLoadConfig:
    def test_minimal_valid_config(self):
        path = _write_config("""
qradar:
  url: "https://qradar.test.com"
  api_token: "test-token"
misp:
  url: "https://misp.test.com"
  api_key: "test-key"
""")
        try:
            config = load_config(path)
            assert config.qradar.url == "https://qradar.test.com"
            assert config.qradar.api_token == "test-token"
            assert config.misp.url == "https://misp.test.com"
            assert config.misp.api_key == "test-key"
            # Check defaults
            assert config.poller.interval_seconds == 300
            assert config.poller.min_magnitude == 3
            assert config.enrichment.enabled is True
            assert config.sighting.enabled is True
        finally:
            os.unlink(path)

    def test_missing_qradar_url_raises(self):
        path = _write_config("""
qradar:
  api_token: "token"
misp:
  url: "https://misp.test.com"
  api_key: "key"
""")
        try:
            with pytest.raises(ValueError, match="qradar.url"):
                load_config(path)
        finally:
            os.unlink(path)

    def test_missing_misp_key_raises(self):
        path = _write_config("""
qradar:
  url: "https://qradar.test.com"
  api_token: "token"
misp:
  url: "https://misp.test.com"
""")
        try:
            with pytest.raises(ValueError, match="misp.api_key"):
                load_config(path)
        finally:
            os.unlink(path)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_env_override(self):
        path = _write_config("""
qradar:
  url: "https://original.com"
  api_token: "original"
misp:
  url: "https://misp.test.com"
  api_key: "key"
""")
        try:
            os.environ["QRADAR_URL"] = "https://override.com"
            os.environ["QRADAR_TOKEN"] = "override-token"
            config = load_config(path)
            assert config.qradar.url == "https://override.com"
            assert config.qradar.api_token == "override-token"
        finally:
            os.unlink(path)
            os.environ.pop("QRADAR_URL", None)
            os.environ.pop("QRADAR_TOKEN", None)

    def test_full_config(self):
        path = _write_config("""
qradar:
  url: "https://qradar.test.com"
  api_token: "token"
  verify_ssl: false
  timeout: 60
misp:
  url: "https://misp.test.com"
  api_key: "key"
  distribution: 1
  auto_publish: true
  tags:
    - custom-tag
    - tlp:white
poller:
  interval_seconds: 120
  min_magnitude: 5
  max_offenses_per_cycle: 25
enrichment:
  enabled: false
sighting:
  enabled: true
  interval_seconds: 1800
logging:
  level: DEBUG
state_file: /tmp/test-state.json
""")
        try:
            config = load_config(path)
            assert config.qradar.verify_ssl is False
            assert config.qradar.timeout == 60
            assert config.misp.distribution == 1
            assert config.misp.auto_publish is True
            assert config.misp.tags == ["custom-tag", "tlp:white"]
            assert config.poller.interval_seconds == 120
            assert config.poller.min_magnitude == 5
            assert config.enrichment.enabled is False
            assert config.sighting.interval_seconds == 1800
            assert config.logging.level == "DEBUG"
            assert config.state_file == "/tmp/test-state.json"
        finally:
            os.unlink(path)
