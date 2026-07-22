"""
Constants used throughout the recon framework.

This module centralizes all magic strings, default paths, and
configuration keys to avoid duplication and improve maintainability.
"""

from pathlib import Path
from typing import Final

# ── Package Metadata ──────────────────────────────────────────────────────────
PACKAGE_NAME: Final[str] = "recon"
VERSION: Final[str] = "1.0.0"
AUTHOR: Final[str] = "nashedi_x_coder"
DESCRIPTION: Final[str] = "An advanced reconnaissance framework for security professionals."

# ── Default Paths ─────────────────────────────────────────────────────────────
DEFAULT_OUTPUT_DIR: Final[Path] = Path("output")
DEFAULT_LOG_DIR: Final[Path] = Path("output/logs")
DEFAULT_REPORT_DIR: Final[Path] = Path("output/reports")
DEFAULT_SCREENSHOT_DIR: Final[Path] = Path("output/screenshots")
DEFAULT_CONFIG_PATH: Final[Path] = Path("configs/default.yaml")

# ── Output File Names ─────────────────────────────────────────────────────────
SUBDOMAINS_FILE: Final[str] = "subdomains.txt"
LIVE_HOSTS_FILE: Final[str] = "live.txt"
TECH_FILE: Final[str] = "technologies.txt"
NMAP_FILE: Final[str] = "nmap_scan.txt"
NUCLEI_FILE: Final[str] = "nuclei_scan.txt"
JSON_REPORT: Final[str] = "report.json"
MARKDOWN_REPORT: Final[str] = "report.md"
HTML_REPORT: Final[str] = "report.html"

# ── Default Configuration Values ──────────────────────────────────────────────
DEFAULT_WORKER_COUNT: Final[int] = 10
DEFAULT_TIMEOUT: Final[int] = 300
DEFAULT_RATE_LIMIT: Final[int] = 50
DEFAULT_RETRY_COUNT: Final[int] = 3
DEFAULT_LOGGING_LEVEL: Final[str] = "INFO"

# ── Tool Commands ─────────────────────────────────────────────────────────────
TOOL_SUBFINDER: Final[str] = "subfinder"
TOOL_ASSETFINDER: Final[str] = "assetfinder"
TOOL_HTPPX: Final[str] = "httpx"
TOOL_AQUATONE: Final[str] = "aquatone"
TOOL_NMAP: Final[str] = "nmap"
TOOL_NUCLEI: Final[str] = "nuclei"

# ── Stage Names ───────────────────────────────────────────────────────────────
STAGE_SUBDOMAIN_ENUM: Final[str] = "subdomain_enumeration"
STAGE_LIVE_HOST_DETECTION: Final[str] = "live_host_detection"
STAGE_TECH_DETECTION: Final[str] = "technology_detection"
STAGE_SCREENSHOTS: Final[str] = "screenshots"
STAGE_PORT_SCAN: Final[str] = "port_scan"
STAGE_VULNERABILITY_SCAN: Final[str] = "vulnerability_scan"
STAGE_REPORT: Final[str] = "report_builder"

# ── ANSI Color Codes ──────────────────────────────────────────────────────────
GREEN: Final[str] = "\033[92m"
YELLOW: Final[str] = "\033[93m"
RED: Final[str] = "\033[91m"
CYAN: Final[str] = "\033[96m"
END_COLOR: Final[str] = "\033[0m"