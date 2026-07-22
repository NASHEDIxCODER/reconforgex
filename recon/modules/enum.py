"""
Subdomain enumeration module.

Aggregates results from ``subfinder`` and ``assetfinder``, then
deduplicates and returns a sorted list of unique subdomains.
"""

from pathlib import Path
from typing import List, Set

from recon.constants import TOOL_ASSETFINDER, TOOL_SUBFINDER
from recon.exceptions import ToolExecutionError
from recon.logger import get_logger
from recon.utils.files import write_lines
from recon.utils.process import run_command

log = get_logger()


async def enumerate_subdomains(
    domain: str,
    subfinder_path: str = TOOL_SUBFINDER,
    assetfinder_path: str = TOOL_ASSETFINDER,
    timeout: int = 300,
    output_path: Path | None = None,
) -> List[str]:
    """Run subdomain enumeration tools and return a deduplicated, sorted list.

    Parameters
    ----------
    domain:
        The target domain (e.g. ``"example.com"``).
    subfinder_path:
        Path to the ``subfinder`` binary.
    assetfinder_path:
        Path to the ``assetfinder`` binary.
    timeout:
        Maximum seconds per tool.
    output_path:
        If provided, the deduplicated subdomain list is also written to this file.

    Returns
    -------
    List[str]
        Sorted list of unique subdomains.

    Raises
    ------
    ToolExecutionError
        If all tools fail.
    """
    all_subdomains: Set[str] = set()

    tools = [
        ("subfinder", [subfinder_path, "-d", domain]),
        ("assetfinder", [assetfinder_path, "--subs-only", domain]),
    ]

    for tool_name, command in tools:
        log.info("Running %s on %s...", tool_name, domain)
        try:
            stdout, stderr, _ = await run_command(command, timeout=timeout)
            for line in stdout.splitlines():
                line = line.strip().lower()
                if line:
                    all_subdomains.add(line)
            log.debug("%s returned %d subdomains", tool_name, len(all_subdomains))
        except ToolExecutionError as exc:
            log.warning("%s failed: %s", tool_name, exc)

    if not all_subdomains:
        log.warning("No subdomains discovered for %s", domain)
        return []

    result = sorted(all_subdomains)

    if output_path:
        write_lines(output_path, result)
        log.info("Subdomains written to %s (%d unique)", output_path, len(result))

    log.info("Discovered %d unique subdomains for %s", len(result), domain)
    return result