#!/usr/bin/env python3
"""
ReconForgeX — High-Performance Asynchronous Reconnaissance Framework.

This file is kept as a convenience entry point.  The canonical CLI
entry point is ``reconforgex.cli:main`` (installed via ``pip install -e .``).

Usage:
    python reconforgex.py -d example.com
    python reconforgex.py -d example.com --port-scan --vuln-scan
"""

import sys
from pathlib import Path

# Ensure the package root is on sys.path when running as a script
_package_root = Path(__file__).resolve().parent
if str(_package_root) not in sys.path:
    sys.path.insert(0, str(_package_root))

from reconforgex.cli import main

if __name__ == "__main__":
    main()