"""
YAML-based configuration for the ReconForgeX framework.

Configuration can be loaded from a file (``recon config.yaml``) or
provided via CLI flags.  CLI flags take precedence over file values.

Example ``config.yaml``::

    worker_count: 100
    timeout: 60
    retry_count: 3
    output_directory: "output"
    logging_level: "INFO"
    modules:
      - http_fingerprinting
      - header_analyzer
      - security_header_scanner
      - tls_inspector
      - csp_analyzer
      - robots_parser
      - sitemap_parser
      - js_collector
      - js_endpoint_extractor
      - js_secret_detector
      - interesting_files
      - http_response_analyzer
      - risk_scoring
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from reconforgex.constants import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_LOGGING_LEVEL,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RETRY_COUNT,
    DEFAULT_TIMEOUT,
    DEFAULT_WORKER_COUNT,
    MODULE_HTTP_FINGERPRINT,
    MODULE_HEADER_ANALYZER,
    MODULE_SECURITY_HEADERS,
    MODULE_TLS_INSPECTOR,
    MODULE_CSP_ANALYZER,
    MODULE_ROBOTS_PARSER,
    MODULE_SITEMAP_PARSER,
    MODULE_JS_COLLECTOR,
    MODULE_JS_ENDPOINTS,
    MODULE_JS_SECRETS,
    MODULE_INTERESTING_FILES,
    MODULE_RESPONSE_ANALYZER,
    MODULE_RISK_SCORING,
)
from reconforgex.exceptions import ConfigurationError

try:
    import yaml as _yaml  # type: ignore[import-untyped]

    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    _yaml = None


ALL_MODULES = [
    MODULE_HTTP_FINGERPRINT,
    MODULE_HEADER_ANALYZER,
    MODULE_SECURITY_HEADERS,
    MODULE_TLS_INSPECTOR,
    MODULE_CSP_ANALYZER,
    MODULE_ROBOTS_PARSER,
    MODULE_SITEMAP_PARSER,
    MODULE_JS_COLLECTOR,
    MODULE_JS_ENDPOINTS,
    MODULE_JS_SECRETS,
    MODULE_INTERESTING_FILES,
    MODULE_RESPONSE_ANALYZER,
    MODULE_RISK_SCORING,
]


@dataclass
class ReconForgeXConfig:
    """Immutable-style configuration dataclass for the framework.

    Attributes
    ----------
    domain:
        Target domain (required).
    output_directory:
        Root output path.
    worker_count:
        Number of concurrent workers (10, 25, 50, 100, 250, 500, 1000).
    timeout:
        Default timeout in seconds for HTTP requests.
    rate_limit:
        Maximum requests per second (where applicable).
    retry_count:
        Number of retries for transient failures.
    logging_level:
        One of ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``.
    modules:
        List of module names to run.
    verbose:
        Enable debug logging.
    html_report:
        Generate HTML report.
    json_report:
        Generate JSON report.
    markdown_report:
        Generate Markdown report.
    """

    domain: str = ""
    output_directory: Path = DEFAULT_OUTPUT_DIR
    worker_count: int = DEFAULT_WORKER_COUNT
    timeout: int = DEFAULT_TIMEOUT
    rate_limit: int = DEFAULT_RATE_LIMIT
    retry_count: int = DEFAULT_RETRY_COUNT
    logging_level: str = DEFAULT_LOGGING_LEVEL
    modules: List[str] = field(default_factory=lambda: list(ALL_MODULES))
    verbose: bool = False
    html_report: bool = True
    json_report: bool = True
    markdown_report: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any], domain: str = "") -> "ReconForgeXConfig":
        """Build a ``ReconForgeXConfig`` from a (possibly partial) dictionary."""
        output_dir = data.get("output_directory", DEFAULT_OUTPUT_DIR)
        if isinstance(output_dir, str):
            output_dir = Path(output_dir)

        return cls(
            domain=domain or data.get("domain", ""),
            output_directory=output_dir,
            worker_count=data.get("worker_count", DEFAULT_WORKER_COUNT),
            timeout=data.get("timeout", DEFAULT_TIMEOUT),
            rate_limit=data.get("rate_limit", DEFAULT_RATE_LIMIT),
            retry_count=data.get("retry_count", DEFAULT_RETRY_COUNT),
            logging_level=data.get("logging_level", DEFAULT_LOGGING_LEVEL),
            modules=data.get("modules", list(ALL_MODULES)),
            verbose=data.get("verbose", False),
            html_report=data.get("html_report", True),
            json_report=data.get("json_report", True),
            markdown_report=data.get("markdown_report", True),
        )

    def merged_with_cli(self, **cli_overrides: Any) -> "ReconForgeXConfig":
        """Return a new config with CLI overrides applied."""
        merged = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        if "output" in cli_overrides and cli_overrides["output"] is not None:
            merged["output_directory"] = Path(cli_overrides["output"])
        if "verbose" in cli_overrides and cli_overrides["verbose"]:
            merged["verbose"] = True
            merged["logging_level"] = "DEBUG"
        if "domain" in cli_overrides and cli_overrides["domain"]:
            merged["domain"] = cli_overrides["domain"]
        if "workers" in cli_overrides and cli_overrides["workers"] is not None:
            merged["worker_count"] = cli_overrides["workers"]
        if "modules" in cli_overrides and cli_overrides["modules"] is not None:
            merged["modules"] = cli_overrides["modules"]
        return ReconForgeXConfig.from_dict(merged)


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from a YAML file.

    Parameters
    ----------
    config_path:
        Path to the YAML config file.  If ``None``, tries the default location.

    Returns
    -------
    Dict[str, Any]
        Parsed configuration dictionary (may be empty on failure).

    Raises
    ------
    ConfigurationError
        If PyYAML is not installed or the file cannot be parsed.
    """
    if not HAS_YAML:
        raise ConfigurationError(
            "PyYAML is required for config file support. "
            "Install it with: pip install pyyaml"
        )

    path = config_path or DEFAULT_CONFIG_PATH
    if not path.exists():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data: Dict[str, Any] = _yaml.safe_load(fh) or {}
        return data
    except Exception as exc:
        raise ConfigurationError(f"Failed to load config from {path}: {exc}") from exc


def save_default_config(path: Optional[Path] = None) -> Path:
    """Write a default configuration file to *path* (or the default location)."""
    target = path or DEFAULT_CONFIG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)

    defaults = {
        "worker_count": DEFAULT_WORKER_COUNT,
        "timeout": DEFAULT_TIMEOUT,
        "rate_limit": DEFAULT_RATE_LIMIT,
        "retry_count": DEFAULT_RETRY_COUNT,
        "output_directory": str(DEFAULT_OUTPUT_DIR),
        "logging_level": DEFAULT_LOGGING_LEVEL,
        "modules": ALL_MODULES,
        "html_report": True,
        "json_report": True,
        "markdown_report": True,
    }

    import yaml as yml

    with open(target, "w", encoding="utf-8") as fh:
        yml.dump(defaults, fh, default_flow_style=False, sort_keys=False)

    return target