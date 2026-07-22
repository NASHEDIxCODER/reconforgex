#!/usr/bin/env python3
"""
Recon — Advanced Reconnaissance Framework.

This file is kept as a convenience entry point.  The canonical CLI
entry point is ``recon.cli:main`` (installed via ``pip install -e .``).

Usage:
    python recon.py -d example.com
    python recon.py -d example.com --port-scan --vuln-scan
"""

import sys
from pathlib import Path

# Ensure the package root is on sys.path when running as a script
_package_root = Path(__file__).resolve().parent
if str(_package_root) not in sys.path:
    sys.path.insert(0, str(_package_root))

from recon.cli import main

if __name__ == "__main__":
    main()