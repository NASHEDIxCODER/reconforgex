"""
Pipeline stage scheduler.

Defines the ``Stage`` dataclass and the ``PipelineScheduler`` that
orchestrates the execution order, concurrency, and data flow between
stages.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from reconforgex.logger import get_logger

log = get_logger()


class StageStatus(Enum):
    """Execution status of a pipeline stage."""

    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    SKIPPED = auto()
    FAILED = auto()


@dataclass
class StageResult:
    """Result produced by a single pipeline stage.

    Attributes
    ----------
    stage_name:
        Unique name of the stage.
    status:
        Final execution status.
    data:
        Arbitrary data produced by the stage (e.g. list of subdomains).
    error:
        Error message if the stage failed.
    duration_seconds:
        Wall-clock time the stage took to execute.
    """

    stage_name: str
    status: StageStatus
    data: Any = None
    error: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class Stage:
    """Describes a single pipeline stage.

    Attributes
    ----------
    name:
        Unique stage identifier (e.g. ``"subdomain_enumeration"``).
    description:
        Human-readable description.
    depends_on:
        List of stage names that must complete before this one runs.
    run_async:
        If ``True``, this stage can run concurrently with other async stages.
    func:
        The async callable that implements the stage logic.
        Receives ``(data_store, output_dir, config)``.
    """

    name: str
    description: str
    depends_on: List[str] = field(default_factory=list)
    run_async: bool = False
    func: Optional[Callable[..., Awaitable[StageResult]]] = None


class PipelineScheduler:
    """Determines the execution order and concurrency of pipeline stages.

    Builds a DAG from stage dependencies and provides methods to
    retrieve the topological execution order.
    """

    def __init__(self, stages: Optional[List[Stage]] = None) -> None:
        self._stages: Dict[str, Stage] = {}
        if stages:
            for stage in stages:
                self.register(stage)

    def register(self, stage: Stage) -> None:
        """Register a new stage."""
        if stage.name in self._stages:
            log.warning("Overwriting existing stage: %s", stage.name)
        self._stages[stage.name] = stage

    def get_stage(self, name: str) -> Optional[Stage]:
        """Look up a stage by name."""
        return self._stages.get(name)

    def get_execution_order(self) -> List[List[Stage]]:
        """Return stages grouped by execution wave.

        Stages in the same inner list can run concurrently (no
        interdependencies).  Stages in later waves depend on at least
        one stage in a previous wave.
        """
        # Topological sort using Kahn's algorithm
        in_degree: Dict[str, int] = {name: 0 for name in self._stages}
        dependents: Dict[str, List[str]] = {name: [] for name in self._stages}

        for name, stage in self._stages.items():
            for dep in stage.depends_on:
                if dep in self._stages:
                    in_degree[name] = in_degree.get(name, 0) + 1
                    dependents[dep].append(name)

        waves: List[List[Stage]] = []
        queue = [name for name, deg in in_degree.items() if deg == 0]

        while queue:
            wave: List[Stage] = []
            next_queue: List[str] = []
            for name in queue:
                wave.append(self._stages[name])
                for dep_name in dependents[name]:
                    in_degree[dep_name] -= 1
                    if in_degree[dep_name] == 0:
                        next_queue.append(dep_name)
            waves.append(wave)
            queue = next_queue

        # Check for cycles
        total_scheduled = sum(len(w) for w in waves)
        if total_scheduled != len(self._stages):
            unscheduled = set(self._stages.keys()) - {
                s.name for w in waves for s in w
            }
            log.error("Cycle detected among stages: %s", unscheduled)

        return waves

    @property
    def stage_names(self) -> List[str]:
        """Return all registered stage names in registration order."""
        return list(self._stages.keys())

    def __len__(self) -> int:
        return len(self._stages)