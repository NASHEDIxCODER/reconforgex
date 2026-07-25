"""
ReconForgeX — Production-Grade Asynchronous Reconnaissance Framework.

A modular, async-first reconnaissance framework built entirely in Python.
No external tool dependencies. Built for security professionals and
bug bounty hunters who demand performance, reliability, and insight.

Typical usage::

    $ reconforgex -d example.com
    $ reconforgex -d example.com --workers 100 --verbose
    $ reconforgex -d example.com --modules tls_inspector risk_scoring
"""

from reconforgex.cli import main
from reconforgex.config import ReconForgeXConfig
from reconforgex.constants import AUTHOR, VERSION
from reconforgex.logger import get_logger
from reconforgex.pipeline.manager import PipelineManager
from reconforgex.pipeline.statistics import PipelineStatistics

__all__ = [
    "main",
    "ReconForgeXConfig",
    "PipelineManager",
    "PipelineStatistics",
    "get_logger",
    "VERSION",
    "AUTHOR",
]

__version__ = VERSION
