"""
Constants used throughout the ReconForgeX framework.

Centralizes all magic strings, default paths, and configuration
keys to avoid duplication and improve maintainability.
"""

from pathlib import Path
from typing import Final

# ── Package Metadata ──────────────────────────────────────────────────────────
PACKAGE_NAME: Final[str] = "reconforgex"
VERSION: Final[str] = "2.0.0"
AUTHOR: Final[str] = "nashedi_x_coder"
DESCRIPTION: Final[str] = (
    "ReconForgeX — Asynchronous Python reconnaissance framework"
)

# ── Default Paths ─────────────────────────────────────────────────────────────
DEFAULT_OUTPUT_DIR: Final[Path] = Path("output")
DEFAULT_LOG_DIR: Final[Path] = Path("output/logs")
DEFAULT_REPORT_DIR: Final[Path] = Path("output/reports")
DEFAULT_SCREENSHOT_DIR: Final[Path] = Path("output/screenshots")
DEFAULT_CONFIG_PATH: Final[Path] = Path("reconforgex/config.yaml")

# ── Output File Names ─────────────────────────────────────────────────────────
SUBDOMAINS_FILE: Final[str] = "subdomains.txt"
LIVE_HOSTS_FILE: Final[str] = "live_hosts.json"
TECH_FILE: Final[str] = "technologies.json"
FINGERPRINT_FILE: Final[str] = "fingerprints.json"
HEADER_ANALYSIS_FILE: Final[str] = "header_analysis.json"
SECURITY_HEADERS_FILE: Final[str] = "security_headers.json"
TLS_FILE: Final[str] = "tls_results.json"
CSP_FILE: Final[str] = "csp_analysis.json"
ROBOTS_FILE: Final[str] = "robots_analysis.json"
SITEMAP_FILE: Final[str] = "sitemap_analysis.json"
JS_FILES_FILE: Final[str] = "js_files.json"
JS_ENDPOINTS_FILE: Final[str] = "js_endpoints.json"
JS_SECRETS_FILE: Final[str] = "js_secrets.json"
INTERESTING_FILES_FILE: Final[str] = "interesting_files.json"
RESPONSE_ANALYSIS_FILE: Final[str] = "response_analysis.json"
RISK_SCORE_FILE: Final[str] = "risk_score.json"
JSON_REPORT: Final[str] = "report.json"
MARKDOWN_REPORT: Final[str] = "report.md"
HTML_REPORT: Final[str] = "report.html"

# ── Default Configuration Values ──────────────────────────────────────────────
DEFAULT_WORKER_COUNT: Final[int] = 50
VALID_WORKER_COUNTS: Final[list] = [10, 25, 50, 100, 250, 500, 1000]
DEFAULT_TIMEOUT: Final[int] = 60
DEFAULT_RATE_LIMIT: Final[int] = 100
DEFAULT_RETRY_COUNT: Final[int] = 3
DEFAULT_LOGGING_LEVEL: Final[str] = "INFO"
DEFAULT_MAX_REDIRECTS: Final[int] = 10
DEFAULT_BACKOFF_BASE: Final[float] = 1.0
DEFAULT_BACKOFF_MULTIPLIER: Final[float] = 2.0

# ── Module Names ──────────────────────────────────────────────────────────────
MODULE_HTTP_FINGERPRINT: Final[str] = "http_fingerprinting"
MODULE_HEADER_ANALYZER: Final[str] = "header_analyzer"
MODULE_SECURITY_HEADERS: Final[str] = "security_header_scanner"
MODULE_TLS_INSPECTOR: Final[str] = "tls_inspector"
MODULE_CSP_ANALYZER: Final[str] = "csp_analyzer"
MODULE_ROBOTS_PARSER: Final[str] = "robots_parser"
MODULE_SITEMAP_PARSER: Final[str] = "sitemap_parser"
MODULE_JS_COLLECTOR: Final[str] = "js_collector"
MODULE_JS_ENDPOINTS: Final[str] = "js_endpoint_extractor"
MODULE_JS_SECRETS: Final[str] = "js_secret_detector"
MODULE_INTERESTING_FILES: Final[str] = "interesting_files"
MODULE_RESPONSE_ANALYZER: Final[str] = "http_response_analyzer"
MODULE_RISK_SCORING: Final[str] = "risk_scoring"

# ── Stage Names ───────────────────────────────────────────────────────────────
STAGE_HTTP_FINGERPRINT: Final[str] = "http_fingerprinting"
STAGE_HEADER_ANALYZER: Final[str] = "header_analyzer"
STAGE_SECURITY_HEADERS: Final[str] = "security_header_scanner"
STAGE_TLS_INSPECTOR: Final[str] = "tls_inspector"
STAGE_CSP_ANALYZER: Final[str] = "csp_analyzer"
STAGE_ROBOTS_PARSER: Final[str] = "robots_parser"
STAGE_SITEMAP_PARSER: Final[str] = "sitemap_parser"
STAGE_JS_COLLECTOR: Final[str] = "js_collector"
STAGE_JS_ENDPOINTS: Final[str] = "js_endpoint_extractor"
STAGE_JS_SECRETS: Final[str] = "js_secret_detector"
STAGE_INTERESTING_FILES: Final[str] = "interesting_files"
STAGE_RESPONSE_ANALYZER: Final[str] = "http_response_analyzer"
STAGE_RISK_SCORING: Final[str] = "risk_scoring"
STAGE_REPORT: Final[str] = "report_builder"

# ── Module Names to Class Mapping (strings for dynamic import) ────────────────
MODULE_CLASS_MAP = {
    MODULE_HTTP_FINGERPRINT: "reconforgex.modules.http_fingerprint.HTTPFingerprinting",
    MODULE_HEADER_ANALYZER: "reconforgex.modules.header_analyzer.HeaderAnalyzer",
    MODULE_SECURITY_HEADERS: "reconforgex.modules.security_header_scanner.SecurityHeaderScanner",
    MODULE_TLS_INSPECTOR: "reconforgex.modules.tls_inspector.TLSInspector",
    MODULE_CSP_ANALYZER: "reconforgex.modules.csp_analyzer.CSPAnalyzer",
    MODULE_ROBOTS_PARSER: "reconforgex.modules.robots_parser.RobotsParser",
    MODULE_SITEMAP_PARSER: "reconforgex.modules.sitemap_parser.SitemapParser",
    MODULE_JS_COLLECTOR: "reconforgex.modules.js_collector.JSCollector",
    MODULE_JS_ENDPOINTS: "reconforgex.modules.js_endpoint_extractor.JSEndpointExtractor",
    MODULE_JS_SECRETS: "reconforgex.modules.js_secret_detector.JSSecretDetector",
    MODULE_INTERESTING_FILES: "reconforgex.modules.interesting_files.InterestingFilesFinder",
    MODULE_RESPONSE_ANALYZER: "reconforgex.modules.http_response_analyzer.HTTPResponseAnalyzer",
    MODULE_RISK_SCORING: "reconforgex.modules.risk_scoring.RiskScoringEngine",
}

# ── ANSI Color Codes ──────────────────────────────────────────────────────────
GREEN: Final[str] = "\033[92m"
YELLOW: Final[str] = "\033[93m"
RED: Final[str] = "\033[91m"
CYAN: Final[str] = "\033[96m"
BOLD: Final[str] = "\033[1m"
END_COLOR: Final[str] = "\033[0m"
