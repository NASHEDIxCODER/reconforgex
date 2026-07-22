"""
YAML-based configuration for the recon framework.

Configuration can be loaded from a file (``recon config.yaml``) or
provided via CLI flags.  CLI flags take precedence over file values.

Example ``config.yaml``::

    worker_count: 10
    timeouts: 300
    rate_limit: 50
    retry_count: 3
    output_directory: "output"
    logging_level: "INFO"
    tool_paths:
      subfinder: ""
      assetfinder: ""
      httpx: ""
      aquatone: ""
      nmap: ""
      nuclei: ""
    default_modules:
      - subdomain_enumeration
      - live_host_detection
      - technology_detection
      - screenshots
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from recon.constants import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_LOGGING_LEVEL,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RETRY_COUNT,
    DEFAULT_TIMEOUT,
    DEFAULT_WORKER_COUNT,
    STAGE_SUBDOMAIN_ENUM,
    STAGE_LIVE_HOST_DETECTION,
    STAGE_SCREENSHOTS,
    STAGE_TECH_DETECTION,
)
from recon.exceptions import ConfigurationError

try:
    import yaml as _yaml  # type: ignore[import-untyped]

    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    _yaml = None


@dataclass
class ReconConfig:
    """Immutable-style configuration dataclass for the framework.

    Attributes
    ----------
    domain:
        Target domain (required).
    output_directory:
        Root output path.
    worker_count:
        Number of concurrent workers for parallel stages.
    timeout:
        Default timeout in seconds for external tool execution.
    rate_limit:
        Maximum requests per second (where applicable).
    retry_count:
        Number of retries for transient failures.
    logging_level:
        One of ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``.
    tool_paths:
        Mapping of tool names to explicit binary paths (empty = use PATH).
    default_modules:
        List of module names to run by default.
    port_scan:
        Whether to run Nmap port scanning.
    vuln_scan:
        Whether to run Nuclei vulnerability scanning.
    """

    domain: str = ""
    output_directory: Path = DEFAULT_OUTPUT_DIR
    worker_count: int = DEFAULT_WORKER_COUNT
    timeout: int = DEFAULT_TIMEOUT
    rate_limit: int = DEFAULT_RATE_LIMIT
    retry_count: int = DEFAULT_RETRY_COUNT
    logging_level: str = DEFAULT_LOGGING_LEVEL
    tool_paths: Dict[str, str] = field(default_factory=dict)
    default_modules: List[str] = field(
        default_factory=lambda: [
            STAGE_SUBDOMAIN_ENUM,
            STAGE_LIVE_HOST_DETECTION,
            STAGE_TECH_DETECTION,
            STAGE_SCREENSHOTS,
        ]
    )
    port_scan: bool = False
    vuln_scan: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any], domain: str = "") -> "ReconConfig":
        """Build a ``ReconConfig`` from a (possibly partial) dictionary."""
        output_dir = data.get("output_directory", DEFAULT_OUTPUT_DIR)
        if isinstance(output_dir, str):
            output_dir = Path(output_dir)

        return cls(
            domain=domain or data.get("domain", ""),
            output_directory=output_dir,
            worker_count=data.get("worker_count", DEFAULT_WORKER_COUNT),
            timeout=data.get("timeouts", data.get("timeout", DEFAULT_TIMEOUT)),
            rate_limit=data.get("rate_limit", DEFAULT_RATE_LIMIT),
            retry_count=data.get("retry_count", DEFAULT_RETRY_COUNT),
            logging_level=data.get("logging_level", DEFAULT_LOGGING_LEVEL),
            tool_paths=data.get("tool_paths", {}),
            default_modules=data.get("default_modules", cls.default_modules),
            port_scan=data.get("port_scan", False),
            vuln_scan=data.get("vuln_scan", False),
        )

    def resolve_tool_path(self, tool_name: str) -> str:
        """Return the configured path for *tool_name*, falling back to the tool name itself."""
        return self.tool_paths.get(tool_name) or tool_name

    def merged_with_cli(self, **cli_overrides: Any) -> "ReconConfig":
        """Return a new config with CLI overrides applied."""
        merged = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        # Translate CLI-style overrides
        if "output" in cli_overrides and cli_overrides["output"] is not None:
            merged["output_directory"] = Path(cli_overrides["output"])
        if "port_scan" in cli_overrides:
            merged["port_scan"] = cli_overrides["port_scan"]
        if "vuln_scan" in cli_overrides:
            merged["vuln_scan"] = cli_overrides["vuln_scan"]
        if "verbose" in cli_overrides and cli_overrides["verbose"]:
            merged["logging_level"] = "DEBUG"
        if "domain" in cli_overrides and cli_overrides["domain"]:
            merged["domain"] = cli_overrides["domain"]
        return ReconConfig.from_dict(merged)


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
        "timeouts": DEFAULT_TIMEOUT,
        "rate_limit": DEFAULT_RATE_LIMIT,
        "retry_count": DEFAULT_RETRY_COUNT,
        "output_directory": str(DEFAULT_OUTPUT_DIR),
        "logging_level": DEFAULT_LOGGING_LEVEL,
        "tool_paths": {
            "subfinder": "",
            "assetfinder": "",
            "httpx": "",
            "aquatone": "",
            "nmap": "",
            "nuclei": "",
        },
        "default_modules": [
            STAGE_SUBDOMAIN_ENUM,
            STAGE_LIVE_HOST_DETECTION,
            STAGE_TECH_DETECTION,
            STAGE_SCREENSHOTS,
        ],
    }

    import yaml as yml

    with open(target, "w", encoding="utf-8") as fh:
        yml.dump(defaults, fh, default_flow_style=False, sort_keys=False)

    return target