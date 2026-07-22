"""Tests for recon.config."""

import tempfile
from pathlib import Path

import pytest

from recon.config import ReconConfig, load_config, save_default_config
from recon.constants import (
    DEFAULT_LOGGING_LEVEL,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RETRY_COUNT,
    DEFAULT_TIMEOUT,
    DEFAULT_WORKER_COUNT,
    STAGE_LIVE_HOST_DETECTION,
    STAGE_SCREENSHOTS,
    STAGE_SUBDOMAIN_ENUM,
    STAGE_TECH_DETECTION,
)


class TestReconConfig:
    """Tests for the ReconConfig dataclass."""

    def test_default_config(self) -> None:
        config = ReconConfig()
        assert config.worker_count == DEFAULT_WORKER_COUNT
        assert config.timeout == DEFAULT_TIMEOUT
        assert config.rate_limit == DEFAULT_RATE_LIMIT
        assert config.retry_count == DEFAULT_RETRY_COUNT
        assert config.logging_level == DEFAULT_LOGGING_LEVEL
        assert config.output_directory == DEFAULT_OUTPUT_DIR
        assert config.port_scan is False
        assert config.vuln_scan is False

    def test_from_dict(self) -> None:
        data = {
            "worker_count": 5,
            "timeouts": 120,
            "output_directory": "/tmp/recon",
            "port_scan": True,
            "vuln_scan": True,
        }
        config = ReconConfig.from_dict(data, domain="test.com")
        assert config.worker_count == 5
        assert config.timeout == 120
        assert config.output_directory == Path("/tmp/recon")
        assert config.port_scan is True
        assert config.vuln_scan is True
        assert config.domain == "test.com"

    def test_default_modules(self) -> None:
        config = ReconConfig()
        assert STAGE_SUBDOMAIN_ENUM in config.default_modules
        assert STAGE_LIVE_HOST_DETECTION in config.default_modules
        assert STAGE_TECH_DETECTION in config.default_modules
        assert STAGE_SCREENSHOTS in config.default_modules

    def test_resolve_tool_path(self) -> None:
        config = ReconConfig(tool_paths={"subfinder": "/custom/subfinder"})
        assert config.resolve_tool_path("subfinder") == "/custom/subfinder"
        assert config.resolve_tool_path("nmap") == "nmap"  # fallback to name

    def test_merged_with_cli(self) -> None:
        config = ReconConfig(domain="original.com")
        merged = config.merged_with_cli(domain="override.com", port_scan=True, verbose=True)
        assert merged.domain == "override.com"
        assert merged.port_scan is True
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
            assert data["timeouts"] == DEFAULT_TIMEOUT
            assert data["logging_level"] == DEFAULT_LOGGING_LEVEL

    def test_load_missing(self) -> None:
        data = load_config(Path("/nonexistent/config.yaml"))
        assert data == {}