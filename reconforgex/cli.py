"""
Command-line interface for the ReconForgeX framework.

Parses arguments, loads configuration, and invokes the pipeline manager.
This module contains *only* argument parsing and dispatching logic.
"""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Optional

from reconforgex.config import ALL_MODULES, ReconForgeXConfig, load_config
from reconforgex.constants import (
    AUTHOR,
    DEFAULT_CONFIG_PATH,
    DESCRIPTION,
    VALID_WORKER_COUNTS,
    VERSION,
)
from reconforgex.exceptions import ConfigurationError, ValidationError
from reconforgex.logger import get_logger, set_log_level
from reconforgex.pipeline.manager import PipelineManager
from reconforgex.utils.validators import validate_domain

log = get_logger()


def _build_banner() -> str:
    """Return the ASCII banner."""
    return f"""
\033[96m
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔══██╗╚════██╗╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝  ▄███╔╝  ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗  ▀▀══╝  ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║  ██║  ██████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝  ╚═════╝╚═╝  ╚═╝

\033[93m               ReconForgeX v{VERSION}
\033[90m   Production-Grade Asynchronous Python Reconnaissance Framework
\033[92m   Created by {AUTHOR}  |  Pure Python · No External Tools\033[0m
"""


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser.

    Returns
    -------
    argparse.ArgumentParser
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description=f"{DESCRIPTION}  (v{VERSION})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  reconforgex -d example.com\n"
            "  reconforgex -d example.com --workers 100 --verbose\n"
            "  reconforgex -d example.com -o /path/to/output --modules header_analyzer tls_inspector\n"
            "  reconforgex my_config.yaml\n"
        ),
    )

    # Positional: config file
    parser.add_argument(
        "config",
        nargs="?",
        type=str,
        help="Path to a YAML configuration file (optional).",
    )

    # Target
    parser.add_argument(
        "-d", "--domain",
        type=str,
        help="Target domain (e.g. example.com).",
    )

    # Output
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Directory to save all output files (default: output/).",
    )

    # Worker count
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=None,
        choices=VALID_WORKER_COUNTS,
        help=f"Number of concurrent workers: {VALID_WORKER_COUNTS} (default: 50).",
    )

    # Module selection
    parser.add_argument(
        "--modules",
        type=str,
        nargs="+",
        default=None,
        help="Specific modules to run (default: all 13 modules). Choices: "
             + ", ".join(ALL_MODULES),
    )

    # List modules
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="List all available modules and exit.",
    )

    # Report format
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip HTML report generation.",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Skip JSON report generation.",
    )
    parser.add_argument(
        "--no-markdown",
        action="store_true",
        help="Skip Markdown report generation.",
    )

    # Options
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"reconforgex v{VERSION}",
    )

    return parser


def _print_module_list() -> None:
    """Print all available modules with descriptions."""
    print("\033[96mAvailable ReconForgeX Modules:\033[0m")
    print("=" * 72)
    modules_info = [
        ("http_fingerprinting", "Identify web servers, frameworks, and technologies"),
        ("header_analyzer", "Analyze HTTP response headers for security issues"),
        ("security_header_scanner", "Check OWASP security header compliance"),
        ("tls_inspector", "Inspect TLS/SSL certificates and protocol versions"),
        ("csp_analyzer", "Analyze Content-Security-Policy for weaknesses"),
        ("robots_parser", "Parse robots.txt for paths and restricted areas"),
        ("sitemap_parser", "Parse XML sitemaps to discover URLs"),
        ("js_collector", "Discover and collect JavaScript files"),
        ("js_endpoint_extractor", "Extract API endpoints from JavaScript"),
        ("js_secret_detector", "Detect secrets, API keys, and tokens in JS"),
        ("interesting_files", "Discover interesting files and endpoints"),
        ("http_response_analyzer", "Analyze HTTP responses for patterns"),
        ("risk_scoring", "Calculate security risk scores from findings"),
    ]
    for name, desc in modules_info:
        print(f"  \033[92m{name:<28}\033[0m {desc}")
    print("=" * 72)


def _create_output_dirs(output_dir: Path) -> None:
    """Create the standard output directory structure."""
    dirs = [
        output_dir,
        output_dir / "reports",
        output_dir / "logs",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


async def async_main(argv: Optional[list[str]] = None) -> int:
    """Async entry point for the CLI.

    Parameters
    ----------
    argv:
        Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns
    -------
    int
        Exit code (0 = success).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # Show banner
    print(_build_banner())

    # Handle --list-modules
    if args.list_modules:
        _print_module_list()
        return 0

    # ── Load configuration ───────────────────────────────────────────────
    config_data: dict = {}
    config_path: Optional[Path] = None

    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            log.error("Configuration file not found: %s", config_path)
            return 1

    if config_path or DEFAULT_CONFIG_PATH.exists():
        try:
            config_data = load_config(config_path)
        except ConfigurationError as exc:
            log.error("Configuration error: %s", exc)
            return 1

    # Build config object
    config = ReconForgeXConfig.from_dict(config_data)

    # Apply CLI overrides
    config = config.merged_with_cli(
        domain=args.domain,
        output=args.output,
        workers=args.workers,
        modules=args.modules,
        verbose=args.verbose,
    )

    # Report format overrides
    if args.no_html:
        config.html_report = False
    if args.no_json:
        config.json_report = False
    if args.no_markdown:
        config.markdown_report = False

    # ── Validate ─────────────────────────────────────────────────────────
    if not config.domain:
        log.error("No domain specified. Use -d/--domain or set 'domain' in config.")
        parser.print_usage()
        return 1

    try:
        config.domain = validate_domain(config.domain)
    except ValidationError as exc:
        log.error("Domain validation failed: %s", exc)
        return 1

    # Configure logging level
    if config.verbose:
        set_log_level("DEBUG")
        log.debug("Verbose mode enabled")

    # Create output directories
    _create_output_dirs(config.output_directory)

    # Log file
    log_file = config.output_directory / "logs" / "reconforgex.log"
    log.info("Log file: %s", log_file)

    # ── Run pipeline ────────────────────────────────────────────────────
    log.info("Target domain: %s", config.domain)
    log.info("Output directory: %s", config.output_directory)
    log.info("Workers: %d", config.worker_count)
    log.info("Modules: %s", ", ".join(config.modules))

    manager = PipelineManager(config)
    pipeline_stats = await manager.run()

    # ── Print summary ───────────────────────────────────────────────────
    stats_dict = pipeline_stats.to_dict() if hasattr(pipeline_stats, "to_dict") else {}

    print(f"\n{'=' * 60}")
    print(f"  Scan complete for {config.domain}")
    print(f"  Duration: {stats_dict.get('execution_time', 0):.2f}s")
    print(f"  Requests: {stats_dict.get('total_requests', 0)}")
    print(f"  Technologies: {stats_dict.get('technologies', 0)}")
    print(f"  Headers analyzed: {stats_dict.get('headers_analyzed', 0)}")
    print(f"  TLS certs: {stats_dict.get('certificates', 0)}")
    print(f"  Redirects: {stats_dict.get('redirects', 0)}")
    print(f"  Errors: {stats_dict.get('errors', 0)}")
    print(f"  Memory: {stats_dict.get('memory_usage_mb', 0):.1f} MB")
    print(f"  Reports: {config.output_directory / 'reports/'}")
    print(f"{'=' * 60}\n")

    return 0


def main() -> None:
    """Synchronous entry point (wraps the async main)."""
    try:
        exit_code = asyncio.run(async_main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        log.info("Scan interrupted by user.")
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        log.exception("Unhandled exception: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
