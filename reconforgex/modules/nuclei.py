"""
Vulnerability scanning module.

Wraps ``nuclei`` to run template-based vulnerability scans against
discovered live hosts.
"""

from pathlib import Path
from typing import List

from reconforgex.constants import TOOL_NUCLEI
from reconforgex.exceptions import ToolExecutionError
from reconforgex.logger import get_logger
from reconforgex.utils.files import write_lines
from reconforgex.utils.process import run_command

log = get_logger()


async def run_vulnerability_scan(
    live_urls: List[str],
    nuclei_path: str = TOOL_NUCLEI,
    output_path: Path | None = None,
    timeout: int = 600,
    templates: str | None = None,
    severity: str | None = None,
) -> List[str]:
    """Run a Nuclei vulnerability scan against live URLs.

    Parameters
    ----------
    live_urls:
        List of live URLs to scan.
    nuclei_path:
        Path to the ``nuclei`` binary.
    output_path:
        If provided, raw Nuclei output is saved here.
    timeout:
        Maximum seconds for the Nuclei scan.
    templates:
        Optional path to custom Nuclei templates (e.g. ``"cves/"``).
    severity:
        Optional severity filter (e.g. ``"critical,high"``).

    Returns
    -------
    List[str]
        Raw Nuclei finding lines.
    """
    if not live_urls:
        log.warning("No live URLs to vulnerability-scan.")
        return []

    log.info("Running Nuclei vulnerability scan on %d hosts...", len(live_urls))

    stdin_data = "\n".join(live_urls)

    command = [
        nuclei_path,
        "-l", "-",           # Read targets from stdin
        "-json",             # JSON output for structured parsing
        "-silent",
    ]

    if templates:
        command.extend(["-t", templates])
    if severity:
        command.extend(["-severity", severity])

    try:
        stdout, stderr, _ = await run_command(
            command,
            timeout=timeout,
            stdin_data=stdin_data,
        )
        lines = [line.rstrip() for line in stdout.splitlines() if line.strip()]

        if output_path:
            write_lines(output_path, lines)
            log.info("Nuclei results saved to %s (%d findings)", output_path, len(lines))

        log.info("Nuclei scan completed: %d findings", len(lines))
        return lines

    except ToolExecutionError as exc:
        log.warning("Nuclei scan failed: %s", exc)
        return []