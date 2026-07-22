"""
File-system helpers for the recon framework.

Provides safe directory creation, atomic writes, and structured
output paths that match the ``output/`` directory layout.
"""

from pathlib import Path
from typing import List, Set


def ensure_directory(path: Path) -> Path:
    """Create *path* (and parents) if it does not exist; return the path."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_lines(path: Path, lines: List[str]) -> Path:
    """Write an iterable of strings to *path*, one per line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def read_lines(path: Path) -> List[str]:
    """Read all non-empty, stripped lines from *path*."""
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def read_lines_set(path: Path) -> Set[str]:
    """Read lines into a ``set`` (deduplicated)."""
    return set(read_lines(path))


def append_lines(path: Path, lines: List[str]) -> Path:
    """Append lines to an existing file, creating it if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")
    return path


def safe_remove(path: Path) -> None:
    """Remove a file without raising if it does not exist."""
    try:
        path.unlink(missing_ok=True)
    except PermissionError:
        pass