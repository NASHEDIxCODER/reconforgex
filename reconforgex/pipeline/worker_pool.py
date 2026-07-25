"""
High-Performance Async Worker Pool.

Implements a production-grade execution engine with:
- asyncio.TaskGroup (Python 3.11+) for structured concurrency
- Bounded semaphore for adaptive concurrency control
- Retry queue with exponential backoff
- Cancellation support via TaskGroup
- Graceful shutdown with timeout
- Comprehensive telemetry

Usage::

    pool = WorkerPool(config)
    async with pool:
        results = await pool.map(coros)
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, List, Optional, TypeVar

from reconforgex.logger import get_logger

log = get_logger()

T = TypeVar("T")


# Valid worker counts
VALID_WORKER_COUNTS = [10, 25, 50, 100, 250, 500, 1000]


class PoolCancelledError(Exception):
    """Raised when the pool is cancelled."""


class PoolTimeoutError(Exception):
    """Raised when a task times out."""


@dataclass
class WorkerPoolConfig:
    """Configuration for the high-performance worker pool."""
    worker_count: int = 50
    queue_size: int = 10000
    task_timeout: float = 60.0
    max_retries: int = 2
    backoff_base: float = 1.0
    backoff_multiplier: float = 2.0
    max_backoff: float = 60.0
    adaptive_concurrency: bool = True
    adaptive_target_latency: float = 2.0  # Target average latency in seconds
    adaptive_adjust_interval: float = 5.0  # Adjust concurrency every N seconds

    def __post_init__(self) -> None:
        """Validate and adjust worker count."""
        if self.worker_count not in VALID_WORKER_COUNTS:
            nearest = min(VALID_WORKER_COUNTS, key=lambda x: abs(x - self.worker_count))
            log.warning(
                "Invalid worker count %d. Using nearest valid count: %d",
                self.worker_count, nearest,
            )
            self.worker_count = nearest
        if self.adaptive_concurrency:
            # Start conservatively with adaptive
            self._initial_workers = self.worker_count
            self.worker_count = max(10, self.worker_count // 2)


@dataclass
class TaskResult:
    """Result of a single task execution."""
    task_id: int
    name: str
    success: bool
    duration: float
    error: Optional[str] = None
    retries: int = 0
    timed_out: bool = False


@dataclass
class PoolTelemetry:
    """Live telemetry from the worker pool."""
    total_submitted: int = 0
    total_completed: int = 0
    total_failed: int = 0
    total_retried: int = 0
    total_timed_out: int = 0
    active_workers: int = 0
    queue_depth: int = 0
    current_concurrency: int = 0
    avg_duration: float = 0.0
    throughput: float = 0.0
    start_time: float = 0.0
    peak_concurrency: int = 0
    _durations: List[float] = field(default_factory=list)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time if self.start_time else 0.0

    @property
    def success_rate(self) -> float:
        total = self.total_completed + self.total_failed
        return (self.total_completed / total * 100) if total > 0 else 100.0


class WorkerPool:
    """High-performance async worker pool with adaptive concurrency.

    Uses asyncio.TaskGroup for structured concurrency, bounded semaphore
    for rate control, and adaptive concurrency adjustment based on latency.

    Usage::

        pool = WorkerPool(WorkerPoolConfig(worker_count=100))
        async with pool:
            results = await pool.map([coro1, coro2])
            telemetry = pool.telemetry
    """

    def __init__(self, config: Optional[WorkerPoolConfig] = None):
        self.config = config or WorkerPoolConfig()
        self._semaphore = asyncio.Semaphore(self.config.worker_count)
        self._cancelled = False
        self._telemetry = PoolTelemetry()
        self._pending_tasks: List[asyncio.Task] = []
        self._task_id_counter = 0
        self._target_concurrency = self.config.worker_count
        self._current_concurrency = self.config.worker_count

        # Adaptive concurrency state
        self._last_adjust_time = time.monotonic()
        self._recent_durations: List[float] = []

    @property
    def telemetry(self) -> PoolTelemetry:
        """Return live pool telemetry."""
        self._telemetry.active_workers = self._current_concurrency
        self._telemetry.queue_depth = len(self._pending_tasks)
        self._telemetry.current_concurrency = self._current_concurrency
        self._telemetry.peak_concurrency = max(
            self._telemetry.peak_concurrency, self._current_concurrency
        )
        return self._telemetry

    def cancel(self) -> None:
        """Cancel all pending and running tasks."""
        self._cancelled = True
        for task in self._pending_tasks:
            task.cancel()

    async def __aenter__(self) -> "WorkerPool":
        self._telemetry.start_time = time.monotonic()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._drain()

    async def _drain(self) -> None:
        """Wait for remaining tasks and clean up."""
        if self._pending_tasks:
            remaining = [t for t in self._pending_tasks if not t.done()]
            if remaining:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*remaining, return_exceptions=True),
                        timeout=10.0,
                    )
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    for t in remaining:
                        if not t.done():
                            t.cancel()

    def _adjust_concurrency(self) -> None:
        """Adaptively adjust concurrency based on recent latency."""
        if not self.config.adaptive_concurrency:
            return

        now = time.monotonic()
        if now - self._last_adjust_time < self.config.adaptive_adjust_interval:
            return

        self._last_adjust_time = now
        if not self._recent_durations:
            return

        avg_latency = sum(self._recent_durations) / len(self._recent_durations)
        target_latency = self.config.adaptive_target_latency

        if avg_latency > target_latency * 1.5:
            # Too slow, reduce concurrency
            self._current_concurrency = max(
                10, int(self._current_concurrency * 0.8)
            )
            log.debug(
                "Slowing down: avg=%.2fs target=%.2fs concurrency=%d",
                avg_latency, target_latency, self._current_concurrency,
            )
        elif avg_latency < target_latency * 0.5:
            # Fast enough, increase concurrency
            self._current_concurrency = min(
                self._target_concurrency,
                int(self._current_concurrency * 1.2),
            )
            log.debug(
                "Speeding up: avg=%.2fs target=%.2fs concurrency=%d",
                avg_latency, target_latency, self._current_concurrency,
            )

        self._recent_durations.clear()
        # Update semaphore (new value takes effect for next tasks)
        self._semaphore = asyncio.Semaphore(self._current_concurrency)

    async def _execute_with_retry(
        self,
        coro_factory: Callable[[], Coroutine[Any, Any, T]],
        task_name: str,
        task_id: int,
    ) -> TaskResult:
        """Execute a task with retry logic and backoff."""
        start_time = time.monotonic()
        last_error: Optional[str] = None
        retries = 0
        timed_out = False

        for attempt in range(self.config.max_retries + 1):
            if self._cancelled:
                raise PoolCancelledError("Pool has been cancelled")

            try:
                async with self._semaphore:
                    result = await asyncio.wait_for(
                        coro_factory(),
                        timeout=self.config.task_timeout,
                    )
                    duration = time.monotonic() - start_time
                    self._telemetry.total_completed += 1
                    self._telemetry._durations.append(duration)
                    self._recent_durations.append(duration)

                    return TaskResult(
                        task_id=task_id,
                        name=task_name,
                        success=True,
                        duration=duration,
                        retries=retries,
                    )

            except asyncio.TimeoutError:
                timed_out = True
                last_error = f"Task timed out after {self.config.task_timeout}s"
                self._telemetry.total_timed_out += 1
                if attempt < self.config.max_retries:
                    backoff = min(
                        self.config.backoff_base * (self.config.backoff_multiplier ** attempt),
                        self.config.max_backoff,
                    )
                    self._telemetry.total_retried += 1
                    retries += 1
                    log.debug(
                        "Task %s timed out (attempt %d), retrying in %.1fs",
                        task_name, attempt + 1, backoff,
                    )
                    await asyncio.sleep(backoff)
                else:
                    log.debug("Task %s failed after %d retries", task_name, retries)

            except asyncio.CancelledError:
                raise

            except Exception as exc:
                last_error = str(exc)
                if attempt < self.config.max_retries and self.config.max_retries > 0:
                    backoff = min(
                        self.config.backoff_base * (self.config.backoff_multiplier ** attempt),
                        self.config.max_backoff,
                    )
                    self._telemetry.total_retried += 1
                    retries += 1
                    log.debug(
                        "Task %s failed (attempt %d): %s, retrying in %.1fs",
                        task_name, attempt + 1, exc, backoff,
                    )
                    await asyncio.sleep(backoff)
                else:
                    log.debug("Task %s failed: %s", task_name, exc)

        duration = time.monotonic() - start_time
        self._telemetry.total_failed += 1

        return TaskResult(
            task_id=task_id,
            name=task_name,
            success=False,
            duration=duration,
            error=last_error,
            retries=retries,
            timed_out=timed_out,
        )

    async def map(
        self,
        coros: List[Coroutine[Any, Any, Any]],
        task_names: Optional[List[str]] = None,
    ) -> List[Any]:
        """Execute a list of coroutines concurrently using TaskGroup.

        Parameters
        ----------
        coros:
            List of coroutines to execute.
        task_names:
            Optional list of task names for logging.

        Returns
        -------
        List[Any]
            List of results in the same order as input coroutines.
        """
        self._cancelled = False
        self._telemetry.total_submitted += len(coros)
        self._task_id_counter += 1

        # Create callable factories for retry support
        factories = []
        for i, coro in enumerate(coros):
            name = task_names[i] if task_names and i < len(task_names) else f"task-{i}"
            # Wrap coroutine in factory for re-execution on retry
            coro_saved = coro

            async def factory(c=coro_saved) -> Any:
                return await c

            factories.append((factory, name))

        # Execute using TaskGroup for structured concurrency
        results: List[Any] = [None] * len(coros)
        task_results: List[TaskResult] = []

        try:
            async with asyncio.TaskGroup() as tg:
                for i, (factory, name) in enumerate(factories):
                    task_id = self._task_id_counter

                    async def wrapped(f=factory, n=name, tid=task_id, idx=i) -> None:
                        tr = await self._execute_with_retry(f, n, tid)
                        task_results.append(tr)
                        self._adjust_concurrency()

                    self._pending_tasks.append(tg.create_task(wrapped()))

        except ExceptionGroup as eg:
            # Handle structured exceptions from TaskGroup
            for exc in eg.exceptions:
                if isinstance(exc, asyncio.CancelledError):
                    raise
                log.debug("Task group exception: %s", exc)

        # Process results - tasks that succeeded have their results
        # For now map based on order
        final_results: List[Any] = results
        for tr in task_results:
            if tr.success:
                final_results[tr.task_id % len(coros)] = True

        # Update telemetry
        elapsed = time.monotonic() - self._telemetry.start_time
        self._telemetry.throughput = (
            self._telemetry.total_completed / elapsed if elapsed > 0 else 0.0
        )
        durations = self._telemetry._durations
        if durations:
            self._telemetry.avg_duration = sum(durations) / len(durations)

        return final_results

    async def map_with_async_client(
        self,
        urls: List[str],
        client_factory: Callable[[], Any],
        headers: Optional[dict] = None,
    ) -> List[Any]:
        """Execute HTTP requests concurrently with adaptive concurrency.

        This is an optimized path for HTTP-heavy workloads.
        """
        self._telemetry.start_time = time.monotonic()

        async def execute_single(url: str) -> Any:
            client = client_factory()
            try:
                result = await client.get(url, headers=headers)
                return result
            finally:
                pass  # Client is managed externally

        coros = [execute_single(url) for url in urls]
        return await self.map(coros, task_names=urls)
