"""
Port scanning module.

Wraps ``nmap`` to discover open ports on live hosts identified during
reconnaissance.
"""

from pathlib import Path
from typing import List, Set

from reconforgex.constants import TOOL_NMAP
from reconforgex.exceptions import ToolExecutionError
from reconforgex.logger import get_logger
from reconforgex.utils.files import write_lines
from reconforgex.utils.process import run_command

log = get_logger()


async def run_port_scan(
    live_urls: List[str],
    nmap_path: str = TOOL_NMAP,
    output_path: Path | None = None,
    timeout: int = 600,
) -> List[str]:
    """Run an Nmap port scan on the extracted hostnames / IPs.

    Parameters
    ----------
    live_urls:
        Live URLs from which hostnames are extracted.
    nmap_path:
        Path to the ``nmap`` binary.
    output_path:
        If provided, raw Nmap output is saved here.
    timeout:
        Maximum seconds for the Nmap scan.

    Returns
    -------
    List[str]
        Raw Nmap output lines.
    """
    if not live_urls:
        log.warning("No live hosts to port-scan.")
        return []

    # Extract unique hostnames / IPs from URLs
    hosts: Set[str] = set()
    for url in live_urls:
        # Strip scheme and path
        netloc = url.split("://")[-1].split("/")[0].split(":")[0]
        if netloc:
            hosts.add(netloc)

    if not hosts:
        log.warning("Could not extract any hostnames from live URLs.")
        return []

    log.info("Running Nmap port scan on %d hosts...", len(hosts))

    # Build command with input file
    stdin_data = "\n".join(sorted(hosts))

    command = [
        nmap_path,
        "-iL", "-",          # Read targets from stdin
        "-oN", "-",          # Normal output to stdout
    ]

    try:
        stdout, stderr, _ = await run_command(
            command,
            timeout=timeout,
            stdin_data=stdin_data,
        )
        lines = [line.rstrip() for line in stdout.splitlines() if line.strip()]

        if output_path:
            write_lines(output_path, lines)
            log.info("Nmap results saved to %s", output_path)

        log.info("Nmap port scan completed (%d hosts scanned)", len(hosts))
        return lines

    except ToolExecutionError as exc:
        log.warning("Nmap port scan failed: %s", exc)
        return []