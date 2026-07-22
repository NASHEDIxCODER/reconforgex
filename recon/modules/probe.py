"""
Live-host detection and technology fingerprinting module.

Uses ``httpx`` to probe discovered subdomains, identify live web servers,
detect technologies, and extract page titles / status codes.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from recon.constants import TOOL_HTPPX
from recon.exceptions import ToolExecutionError
from recon.logger import get_logger
from recon.utils.files import write_lines
from recon.utils.process import run_command

log = get_logger()


@dataclass
class LiveHost:
    """Represents a live web server discovered during probing.

    Attributes
    ----------
    url:
        Full URL (e.g. ``https://admin.example.com``).
    status_code:
        HTTP response status code (may be ``0`` if unknown).
    title:
        HTML page title (may be empty).
    technologies:
        List of detected technologies (e.g. ``["nginx", "React"]``).
    """

    url: str
    status_code: int = 0
    title: str = ""
    technologies: List[str] = field(default_factory=list)


def _parse_httpx_line(line: str) -> LiveHost | None:
    """Parse a single line of httpx JSON output into a ``LiveHost``."""
    import json

    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        # Fall back to whitespace-split parsing for non-JSON output
        parts = line.split()
        if parts:
            return LiveHost(url=parts[0])
        return None

    return LiveHost(
        url=data.get("url", ""),
        status_code=data.get("status_code", 0),
        title=data.get("title", ""),
        technologies=data.get("technologies", []),
    )


async def probe_hosts(
    subdomains: List[str],
    httpx_path: str = TOOL_HTPPX,
    timeout: int = 300,
    output_path: Path | None = None,
) -> List[LiveHost]:
    """Probe subdomains for live web servers and detect technologies.

    Parameters
    ----------
    subdomains:
        List of subdomains to probe.
    httpx_path:
        Path to the ``httpx`` binary.
    timeout:
        Maximum seconds for the httpx scan.
    output_path:
        If provided, the raw httpx output is saved here.

    Returns
    -------
    List[LiveHost]
        Sorted list of live hosts with available metadata.
    """
    if not subdomains:
        log.warning("No subdomains to probe.")
        return []

    log.info("Probing %d subdomains with httpx...", len(subdomains))

    # httpx reads from stdin line by line
    stdin_data = "\n".join(subdomains)

    command = [
        httpx_path,
        "-json",          # JSON output for easy parsing
        "-silent",
        "-tech-detect",
        "-title",
        "-status-code",
    ]

    try:
        stdout, stderr, _ = await run_command(
            command,
            timeout=timeout,
            stdin_data=stdin_data,
        )
    except ToolExecutionError as exc:
        log.warning("httpx probing failed: %s", exc)
        return []

    hosts: List[LiveHost] = []
    for line in stdout.splitlines():
        host = _parse_httpx_line(line)
        if host and host.url:
            hosts.append(host)

    # Save raw output if requested
    if output_path and stdout.strip():
        write_lines(output_path, stdout.strip().splitlines())

    log.info("Found %d live hosts out of %d subdomains", len(hosts), len(subdomains))
    return hosts


async def get_live_urls(hosts: List[LiveHost]) -> List[str]:
    """Extract just the URL strings from a list of ``LiveHost`` objects."""
    return [h.url for h in hosts if h.url]