"""
Command-line interface for the recon framework.

Parses arguments, loads configuration, and invokes the pipeline manager.
This module should contain *only* argument parsing and dispatching logic.
"""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import List, Optional

from recon.config import ReconConfig, load_config
from recon.constants import (
    AUTHOR,
    DESCRIPTION,
    VERSION,
    DEFAULT_CONFIG_PATH,
)
from recon.exceptions import ConfigurationError, ValidationError
from recon.logger import get_logger, set_log_level
from recon.pipeline.manager import PipelineManager
from recon.utils.validators import validate_domain

log = get_logger()


def _build_banner() -> str:
    """Return the ASCII banner."""
    return f"""
\033[93m
>>=========================================================================<<
||  _  _    _    ___  _  _  ___  ___  ___        ___  ___   ___   ___  ___ ||
|| | \\| |  /_\\  / __|| || || __||   \\|_ _|__ __ / __|/ _ \\ |   \\ | __|| _ \\||
|| | .` | / _ \\ \\__ \\| __ || _| | |) || | \\ \\ /| (__| (_) || |) || _| |   /||
|| |_|\\_|/_/ \\_\\|___/|_||_||___||___/|___|/_/_\\ \\___|\\___/ |___/ |___||_|_\\||
||                                                                         ||
>>=========================================================================<<

\033[96m          Created by: {AUTHOR}  v{VERSION}\033[0m
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
            "  recon -d example.com\n"
            "  recon -d example.com --port-scan --vuln-scan\n"
            "  recon -d example.com -o /path/to/output --verbose\n"
            "  recon my_config.yaml\n"
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

    # Options
    parser.add_argument(
        "--port-scan",
        action="store_true",
        help="Run an Nmap port scan on live hosts.",
    )
    parser.add_argument(
        "--vuln-scan",
        action="store_true",
        help="Run a Nuclei vulnerability scan on live hosts.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"recon v{VERSION}",
    )

    return parser


def _create_output_dirs(output_dir: Path) -> None:
    """Create the standard output directory structure."""
    dirs = [
        output_dir,
        output_dir / "reports",
        output_dir / "screenshots",
        output_dir / "logs",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


async def async_main(argv: Optional[List[str]] = None) -> int:
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

    # ── Load configuration ───────────────────────────────────────────────
    config_data: dict = {}
    config_path: Optional[Path] = None

    # Check for positional config argument
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            log.error("Configuration file not found: %s", config_path)
            return 1

    # Load YAML config
    if config_path or DEFAULT_CONFIG_PATH.exists():
        try:
            config_data = load_config(config_path)
        except ConfigurationError as exc:
            log.error("Configuration error: %s", exc)
            return 1

    # Build config object
    config = ReconConfig.from_dict(config_data)

    # Apply CLI overrides
    config = config.merged_with_cli(
        domain=args.domain,
        output=args.output,
        port_scan=args.port_scan,
        vuln_scan=args.vuln_scan,
        verbose=args.verbose,
    )

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
    if args.verbose:
        set_log_level("DEBUG")
        log.debug("Verbose mode enabled")

    # Create output directories
    _create_output_dirs(config.output_directory)

    # Log file
    log_file = config.output_directory / "logs" / "recon.log"
    from recon.logger import ReconLogger

    # ── Run pipeline ────────────────────────────────────────────────────
    log.info("Target domain: %s", config.domain)
    log.info("Output directory: %s", config.output_directory)
    log.debug("Configuration: %s", config)

    manager = PipelineManager(config)
    stats = await manager.run()

    # ── Print summary ───────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  Scan complete for {config.domain}")
    print(f"  Duration: {stats.duration_seconds:.2f}s")
    print(f"  Subdomains: {stats.hosts_found}")
    print(f"  Live hosts: {stats.live_hosts}")
    print(f"  Screenshots: {stats.screenshots_taken}")
    if config.port_scan:
        print(f"  Ports scanned: {stats.ports_scanned}")
    if config.vuln_scan:
        print(f"  Nuclei findings: {stats.nuclei_findings}")
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