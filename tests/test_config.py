"""Tests for reconforgex.config."""

import tempfile
from pathlib import Path

from reconforgex.config import ReconForgeXConfig, load_config, save_default_config
from reconforgex.constants import (
    DEFAULT_LOGGING_LEVEL,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RETRY_COUNT,
    DEFAULT_TIMEOUT,
    DEFAULT_WORKER_COUNT,
)


class TestReconForgeXConfig:
    """Tests for the ReconForgeXConfig dataclass."""

    def test_default_config(self) -> None:
        config = ReconForgeXConfig()
        assert config.worker_count == DEFAULT_WORKER_COUNT
        assert config.timeout == DEFAULT_TIMEOUT
        assert config.rate_limit == DEFAULT_RATE_LIMIT
        assert config.retry_count == DEFAULT_RETRY_COUNT
        assert config.logging_level == DEFAULT_LOGGING_LEVEL
        assert config.output_directory == DEFAULT_OUTPUT_DIR

    def test_from_dict(self) -> None:
        data = {
            "worker_count": 100,
            "timeout": 120,
            "output_directory": "/tmp/reconforgex",
        }
        config = ReconForgeXConfig.from_dict(data, domain="test.com")
        assert config.worker_count == 100
        assert config.timeout == 120
        assert config.output_directory == Path("/tmp/reconforgex")
        assert config.domain == "test.com"

    def test_default_modules(self) -> None:
        config = ReconForgeXConfig()
        assert len(config.modules) == 13  # All 13 modules
        assert "http_fingerprinting" in config.modules
        assert "header_analyzer" in config.modules
        assert "tls_inspector" in config.modules
        assert "risk_scoring" in config.modules

    def test_merged_with_cli(self) -> None:
        config = ReconForgeXConfig(domain="original.com")
        merged = config.merged_with_cli(domain="override.com", workers=100, verbose=True)
        assert merged.domain == "override.com"
        assert merged.worker_count == 100
        assert merged.logging_level == "DEBUG"


class TestLoadConfig:
    """Tests for load_config and save_default_config."""

    def test_save_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.yaml"
            saved = save_default_config(path)
            assert saved.exists()

            data = load_config(path)
            assert data["worker_count"] == DEFAULT_WORKER_COUNT
            assert data["timeout"] == DEFAULT_TIMEOUT
            assert data["logging_level"] == DEFAULT_LOGGING_LEVEL

    def test_load_missing(self) -> None:
        data = load_config(Path("/nonexistent/config.yaml"))
        assert data == {}
