"""
Screenshot capture module.

Uses ``aquatone`` to take screenshots of live web hosts for visual
reconnaissance.
"""

from pathlib import Path
from typing import List

from recon.constants import TOOL_AQUATONE
from recon.exceptions import ToolExecutionError
from recon.logger import get_logger
from recon.utils.process import run_command_with_input

log = get_logger()


async def take_screenshots(
    live_urls: List[str],
    aquatone_path: str = TOOL_AQUATONE,
    output_dir: Path | None = None,
    timeout: int = 600,
) -> bool:
    """Take screenshots of live URLs using ``aquatone``.

    Parameters
    ----------
    live_urls:
        List of live URLs to screenshot.
    aquatone_path:
        Path to the ``aquatone`` binary.
    output_dir:
        Directory where aquatone stores its results (``aquatone_report/``
        will be created inside).
    timeout:
        Maximum seconds for the screenshot session.

    Returns
    -------
    bool
        ``True`` if the tool ran without fatal errors.
    """
    if not live_urls:
        log.warning("No live URLs to screenshot.")
        return False

    report_dir = (output_dir / "aquatone_report") if output_dir else Path("aquatone_report")
    report_dir.mkdir(parents=True, exist_ok=True)

    command = [aquatone_path, "-out", str(report_dir)]

    log.info("Taking screenshots of %d hosts with aquatone...", len(live_urls))
    log.debug("Aquatone output dir: %s", report_dir)

    try:
        await run_command_with_input(
            command,
            input_lines=live_urls,
            timeout=timeout,
        )
        log.info("Screenshots saved to %s", report_dir)
        return True
    except ToolExecutionError as exc:
        log.warning("Aquatone screenshot failed: %s", exc)
        return False