"""
Async subprocess execution utilities.

Wraps ``asyncio.create_subprocess_exec`` with timeout, retry, and
logging support so that every external tool invocation is consistent.
"""

import asyncio
import shlex
from asyncio.subprocess import PIPE
from typing import List, Optional, Tuple

from recon.exceptions import TimeoutError, ToolExecutionError
from recon.logger import get_logger

log = get_logger()


async def run_command(
    command: List[str],
    timeout: int = 300,
    retries: int = 0,
    stdin_data: Optional[str] = None,
) -> Tuple[str, str, int]:
    """Execute an external command asynchronously.

    Parameters
    ----------
    command:
        The command and its arguments as a list (e.g. ``["subfinder", "-d", "example.com"]``).
    timeout:
        Maximum seconds to wait before raising ``TimeoutError``.
    retries:
        Number of additional attempts on non-zero exit codes.
    stdin_data:
        Optional string to pipe to the process's stdin.

    Returns
    -------
    Tuple[str, str, int]
        ``(stdout, stderr, return_code)``.

    Raises
    ------
    ToolExecutionError
        If the tool is not found or all retries are exhausted.
    TimeoutError
        If the command exceeds *timeout* seconds.
    """
    last_exception: Optional[Exception] = None

    for attempt in range(1 + max(0, retries)):
        if attempt > 0:
            log.warning("Retry %d/%d for %s", attempt, retries, command[0])
            await asyncio.sleep(1 * attempt)  # linear back-off

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=PIPE if stdin_data is not None else None,
                stdout=PIPE,
                stderr=PIPE,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=stdin_data.encode() if stdin_data else None),
                timeout=timeout,
            )

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            if proc.returncode == 0:
                return stdout, stderr, proc.returncode

            # Non-zero exit — retry if attempts remain
            last_exception = ToolExecutionError(
                f"Command {' '.join(shlex.quote(p) for p in command)} "
                f"exited with code {proc.returncode}: {stderr[:500]}"
            )

        except FileNotFoundError:
            raise ToolExecutionError(
                f"Tool not found: {command[0]}. Is it installed and in your PATH?"
            ) from None
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Command {' '.join(shlex.quote(p) for p in command)} "
                f"timed out after {timeout}s"
            ) from None
        except Exception as exc:
            last_exception = exc

    # All retries exhausted
    raise ToolExecutionError(
        f"Command {' '.join(shlex.quote(p) for p in command)} "
        f"failed after {retries + 1} attempt(s)"
    ) from last_exception


async def run_command_with_input(
    command: List[str],
    input_lines: List[str],
    timeout: int = 300,
    retries: int = 0,
) -> Tuple[str, str, int]:
    """Run a command that expects newline-separated input on stdin."""
    return await run_command(
        command,
        timeout=timeout,
        retries=retries,
        stdin_data="\n".join(input_lines),
    )


async def check_tool_exists(tool_name: str) -> bool:
    """Return ``True`` if *tool_name* is available on the system PATH."""
    try:
        await run_command(["which", tool_name], timeout=10)
        return True
    except (ToolExecutionError, TimeoutError):
        return False