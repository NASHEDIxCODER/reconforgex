"""
Structured logging for the recon framework.

Provides a ``ReconLogger`` singleton that writes timestamped, level-aware
log entries to both stdout and an optional log file.

Usage::

    from recon.logger import get_logger

    log = get_logger()
    log.info("Starting scan on %s", domain)
    log.debug("Subdomains found: %d", count)
    log.warning("Tool %s not found", name)
    log.error("Scan failed: %s", reason)
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from recon.constants import DEFAULT_LOGGING_LEVEL, DEFAULT_LOG_DIR

# Module-level singleton
_logger: Optional["ReconLogger"] = None


class ReconLogger:
    """Wraps a standard ``logging.Logger`` with convenient helpers."""

    def __init__(
        self,
        name: str = "recon",
        level: str = DEFAULT_LOGGING_LEVEL,
        log_file: Optional[Path] = None,
    ) -> None:
        self._logger = logging.getLogger(name)
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self._logger.handlers.clear()

        formatter = logging.Formatter(
            fmt="%(asctime)s  %(levelname)-8s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self._logger.addHandler(console_handler)

        # File handler (optional)
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
            file_handler.setFormatter(formatter)
            self._logger.addHandler(file_handler)

    # ── Convenience proxies ──────────────────────────────────────────────────

    def debug(self, msg: str, *args: object, **kwargs: object) -> None:
        """Log at DEBUG level."""
        self._logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args: object, **kwargs: object) -> None:
        """Log at INFO level."""
        self._logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args: object, **kwargs: object) -> None:
        """Log at WARNING level."""
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args: object, **kwargs: object) -> None:
        """Log at ERROR level."""
        self._logger.error(msg, *args, **kwargs)

    def exception(self, msg: str, *args: object, **kwargs: object) -> None:
        """Log at ERROR level with traceback."""
        self._logger.exception(msg, *args, **kwargs)


def get_logger(
    name: str = "recon",
    level: str = DEFAULT_LOGGING_LEVEL,
    log_file: Optional[Path] = None,
) -> ReconLogger:
    """Return the global ``ReconLogger`` singleton.

    Parameters
    ----------
    name:
        Logger name (used primarily for namespace isolation).
    level:
        One of ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``.
    log_file:
        Optional path to a file where logs are also written.

    Returns
    -------
    ReconLogger
        A shared logger instance.
    """
    global _logger
    if _logger is None:
        _logger = ReconLogger(name=name, level=level, log_file=log_file)
    return _logger


def set_log_level(level: str) -> None:
    """Dynamically change the logging level at runtime.

    Parameters
    ----------
    level:
        One of ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``.
    """
    logger_instance = get_logger()
    logger_instance._logger.setLevel(getattr(logging, level.upper(), logging.INFO))  # noqa: SLF001