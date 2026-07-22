"""
Recon — Advanced Reconnaissance Framework.

A modular, async-first reconnaissance framework for security
professionals and bug bounty hunters.

Orchestrates industry-standard tools (subfinder, assetfinder, httpx,
aquatone, nmap, nuclei) through a clean pipeline architecture.

Typical usage::

    $ recon -d example.com --port-scan --vuln-scan
    $ recon my_config.yaml -d example.com --verbose
"""

from recon.cli import main
from recon.config import ReconConfig
from recon.constants import VERSION, AUTHOR
from recon.logger import get_logger
from recon.pipeline.manager import PipelineManager, ScanStatistics

__all__ = [
    "main",
    "ReconConfig",
    "PipelineManager",
    "ScanStatistics",
    "get_logger",
    "VERSION",
    "AUTHOR",
]

__version__ = VERSION