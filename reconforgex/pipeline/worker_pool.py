"""
Worker Pool Module.

Configurable async worker pool for concurrent task execution.
Supports 10, 25, 50, 100, 250, 500, and 1000 workers with
semaphore-based concurrency control.
"""

import asyncio
import time
from typing import Any, Callable, Coroutine, List, Optional, TypeVar
from dataclasses import dataclass, field

from reconforgex.logger import get_logger

log = get_logger()

T = TypeVar("T")


# Valid worker counts
VALID_WORKER_COUNTS = [10, 25, 50, 100, 250, 500, 1000]


@dataclass
class WorkerPoolConfig:
    """Configuration for the worker pool."""
    worker_count: int = 50
    queue_size: int = 10000
    task_timeout: float = 60.0
    retry_on_failure: bool = True
    max_retries: int = 2

    def __post_init__(self) -> None:
        """Validate worker count."""
        if self.worker_count not in VALID_WORKER_COUNTS:
            # Find nearest valid count
            nearest = min(VALID_WORKER_COUNTS, key=lambda x: abs(x - self.worker_count))
            log.warning(
                "Invalid worker count %d. Using nearest valid count: %d",
                self.worker_count, nearest,
            )
            self.worker_count = nearest


@dataclass
class WorkerTask:
    """A task to be executed by the worker pool."""
    id: int
    name: str
    coro: Coroutine[Any, Any, Any]
    created_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0
    result: Any = None
    error: Optional[str] = None
    retries: int = 0

    @property
    def duration(self) -> float:
        if self.completed_at > self.started_at:
            return self.completed_at - self.started_at
        return 0.0

    @property
    def queue_time(self) -> float:
        if self.started_at > self.created_at:
            return self.started_at - self.created_at
        return 0.0


@dataclass
class WorkerPoolStatistics:
    """Statistics for the worker pool."""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    retried_tasks: int = 0
    total_duration: float = 0.0
    avg_task_duration: float = 0.0
    avg_queue_time: float = 0.0
    throughput: float = 0.0  # tasks per second
    worker_count: int = 50
    peak_concurrency: int = 0


class WorkerPool:
    """Configurable async worker pool.

    Manages concurrent execution of async tasks with configurable
    worker count, retry logic, and comprehensive statistics.

    Usage::

        pool = WorkerPool(WorkerPoolConfig(worker_count=100))
        results = await pool.map([coro1, coro2, coro3])
        stats = pool.statistics
    """

    def __init__(self, config: Optional[WorkerPoolConfig] = None):
        self.config = config or WorkerPoolConfig()
        self._semaphore = asyncio.Semaphore(self.config.worker_count)
        self._tasks: List[WorkerTask] = []
        self._stats = WorkerPoolStatistics(worker_count=self.config.worker_count)
        self._cancelled = False
        self._active_count = 0
        self._task_id_counter = 0

    def cancel(self) -> None:
        """Cancel all pending and running tasks."""
        self._cancelled = True

    async def _execute_task(self, task: WorkerTask) -> Any:
        """Execute a single task with retry logic."""
        task.started_at = time.monotonic()
        self._active_count += 1
        self._stats.peak_concurrency = max(self._stats.peak_concurrency, self._active_count)

        try:
            async with self._semaphore:
                if self._cancelled:
                    raise asyncio.CancelledError("Worker pool cancelled")

                for attempt in range(self.config.max_retries + 1):
                    try:
                        result = await asyncio.wait_for(
                            task.coro,
                            timeout=self.config.task_timeout,
                        )
                        task.result = result
                        task.completed_at = time.monotonic()
                        self._stats.completed_tasks += 1
                        return result
                    except asyncio.TimeoutError:
                        task.retries += 1
                        self._stats.retried_tasks += 1
                        if attempt < self.config.max_retries:
                            log.debug(
                                "Task %s timed out, retrying (%d/%d)",
                                task.name, attempt + 1, self.config.max_retries,
                            )
                            await asyncio.sleep(1 * (attempt + 1))
                        else:
                            raise
                    except Exception as exc:
                        task.retries += 1
                        self._stats.retried_tasks += 1
                        if attempt < self.config.max_retries and self.config.retry_on_failure:
                            log.debug(
                                "Task %s failed: %s, retrying (%d/%d)",
                                task.name, exc, attempt + 1, self.config.max_retries,
                            )
                            await asyncio.sleep(1 * (attempt + 1))
                        else:
                            raise

        except asyncio.CancelledError:
            task.error = "Task cancelled"
            self._stats.failed_tasks += 1
            raise
        except Exception as exc:
            task.error = str(exc)
            task.completed_at = time.monotonic()
            self._stats.failed_tasks += 1
            return None
        finally:
            self._active_count -= 1

    async def map(
        self,
        coros: List[Coroutine[Any, Any, Any]],
        task_names: Optional[List[str]] = None,
    ) -> List[Any]:
        """Execute a list of coroutines concurrently.

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
        start_time = time.monotonic()

        # Create task objects
        tasks: List[WorkerTask] = []
        for i, coro in enumerate(coros):
            name = task_names[i] if task_names and i < len(task_names) else f"task-{i}"
            task = WorkerTask(
                id=self._task_id_counter,
                name=name,
                coro=coro,
                created_at=time.monotonic(),
            )
            self._task_id_counter += 1
            tasks.append(task)

        self._tasks = tasks
        self._stats.total_tasks = len(tasks)

        # Execute all tasks concurrently
        execution_coros = [self._execute_task(task) for task in tasks]
        results = await asyncio.gather(*execution_coros, return_exceptions=True)

        # Process results
        final_results: List[Any] = []
        for task, result in zip(tasks, results):
            if isinstance(result, Exception):
                task.error = str(result)
                self._stats.failed_tasks += 1
                final_results.append(None)
            else:
                final_results.append(result)

        # Update statistics
        elapsed = time.monotonic() - start_time
        self._stats.total_duration = elapsed
        self._stats.throughput = len(tasks) / elapsed if elapsed > 0 else 0.0

        durations = [t.duration for t in tasks if t.duration > 0]
        queue_times = [t.queue_time for t in tasks if t.queue_time > 0]
        self._stats.avg_task_duration = sum(durations) / len(durations) if durations else 0.0
        self._stats.avg_queue_time = sum(queue_times) / len(queue_times) if queue_times else 0.0

        return final_results

    @property
    def statistics(self) -> WorkerPoolStatistics:
        """Return current pool statistics."""
        return self._stats

    @property
    def is_running(self) -> bool:
        """Check if the pool has active tasks."""
        return self._active_count > 0

    @property
    def queue_depth(self) -> int:
        """Return the number of queued tasks."""
        return max(0, self._stats.total_tasks - self._stats.completed_tasks - self._stats.failed_tasks)