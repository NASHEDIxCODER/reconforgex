"""
Real-time Progress Monitor.

Displays live pipeline progress including:
- Current stage
- Completed tasks
- Active workers
- Queue depth
- ETA
- Requests/sec
- Average latency

Uses ANSI escape codes for terminal rendering.
"""

import time
import shutil
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class ProgressState:
    """Current state of the pipeline for progress display."""
    current_stage: str = ""
    total_stages: int = 0
    completed_stages: int = 0
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    active_workers: int = 0
    queue_depth: int = 0
    requests_per_second: float = 0.0
    avg_latency: float = 0.0
    memory_mb: float = 0.0
    elapsed: float = 0.0
    eta: float = 0.0
    start_time: float = 0.0


class ProgressMonitor:
    """Real-time progress monitor for the pipeline.

    Renders a live progress bar with statistics to the terminal.
    Uses ANSI escape codes for clean updates.

    Usage::

        monitor = ProgressMonitor()
        monitor.start()
        monitor.update(state)
        monitor.finish()
    """

    def __init__(self, enabled: bool = True, interval: float = 0.5):
        self._enabled = enabled
        self._interval = interval
        self._last_render: float = 0.0
        self._start_time: float = 0.0
        self._state = ProgressState()
        self._terminal_width: int = 80

    def start(self) -> None:
        """Start the progress monitor."""
        if not self._enabled:
            return
        self._start_time = time.monotonic()
        self._state.start_time = self._start_time
        self._update_terminal_width()

    def _update_terminal_width(self) -> None:
        """Get current terminal width."""
        try:
            self._terminal_width = shutil.get_terminal_size().columns
        except Exception:
            self._terminal_width = 80

    def update(self, state: ProgressState) -> None:
        """Update the progress display with new state."""
        if not self._enabled:
            return

        now = time.monotonic()
        if now - self._last_render < self._interval:
            return

        self._last_render = now
        self._state = state
        self._state.elapsed = now - self._start_time
        self._render()

    def _render(self) -> None:
        """Render the progress display."""
        self._update_terminal_width()
        width = min(self._terminal_width, 100)

        # Calculate progress
        stage_progress = 0.0
        if self._state.total_stages > 0:
            stage_progress = self._state.completed_stages / self._state.total_stages

        task_progress = 0.0
        if self._state.total_tasks > 0:
            task_progress = self._state.completed_tasks / self._state.total_tasks

        # Build progress bar
        bar_width = width - 30
        filled = int(bar_width * task_progress)
        bar = "█" * filled + "░" * (bar_width - filled)

        # Build display lines
        lines = [
            f"\r\033[K┌─ {'=' * (width - 4)} ─┐",
            f"\r\033[K│ ReconForgeX Pipeline Progress{' ' * (width - 34)}│",
            f"\r\033[K├─ {'─' * (width - 4)} ─┤",
            f"\r\033[K│ Stage: {self._state.current_stage:<{width - 16}}│",
            f"\r\033[K│ Progress: [{bar}] {task_progress*100:5.1f}%{' ' * (width - 40)}│",
            f"\r\033[K│ Tasks: {self._state.completed_tasks}/{self._state.total_tasks} "
            f"| Failed: {self._state.failed_tasks} "
            f"| Workers: {self._state.active_workers}{' ' * (width - 60)}│",
            f"\r\033[K│ RPS: {self._state.requests_per_second:6.1f} "
            f"| Latency: {self._state.avg_latency*1000:5.0f}ms "
            f"| Memory: {self._state.memory_mb:5.1f}MB{' ' * (width - 60)}│",
            f"\r\033[K│ Elapsed: {self._format_time(self._state.elapsed):>8} "
            f"| ETA: {self._format_time(self._state.eta):>8}{' ' * (width - 40)}│",
            f"\r\033[K└─ {'─' * (width - 4)} ─┘",
        ]

        print("\n".join(lines), end="\r", flush=True)

    def _format_time(self, seconds: float) -> str:
        """Format time in human-readable format."""
        if seconds < 0:
            return "--:--:--"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"

    def finish(self) -> None:
        """Finalize the progress display."""
        if not self._enabled:
            return
        # Clear the progress display
        print("\r\033[K" + " " * self._terminal_width, end="\r")
        print("\r\033[K", end="")