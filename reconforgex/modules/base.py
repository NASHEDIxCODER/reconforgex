"""
Abstract base class for all ReconForgeX modules.

Every module must expose:
    - run()        : Execute the module's core logic
    - metadata()   : Return module metadata (name, description, version, author)
    - statistics() : Return execution statistics
    - health()     : Return health check status
    - configuration() : Return current configuration
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional


class ModuleStatus(Enum):
    """Execution status of a module."""
    IDLE = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass
class ModuleMetadata:
    """Metadata describing a module."""
    name: str
    description: str
    version: str = "1.0.0"
    author: str = "ReconForgeX"
    tags: List[str] = field(default_factory=list)
    requires_network: bool = True
    requires_domain: bool = True
    timeout_default: int = 30


@dataclass
class ModuleStatistics:
    """Execution statistics for a module."""
    execution_time: float = 0.0
    items_found: int = 0
    items_processed: int = 0
    errors: int = 0
    retries: int = 0
    status: ModuleStatus = ModuleStatus.IDLE
    start_time: float = 0.0
    end_time: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_percent: float = 0.0

    @property
    def duration(self) -> float:
        if self.end_time > self.start_time:
            return self.end_time - self.start_time
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_time": self.execution_time,
            "items_found": self.items_found,
            "items_processed": self.items_processed,
            "errors": self.errors,
            "retries": self.retries,
            "status": self.status.name,
            "duration": self.duration,
            "memory_usage_mb": self.memory_usage_mb,
            "cpu_percent": self.cpu_percent,
        }


@dataclass
class ModuleHealth:
    """Health check result for a module."""
    healthy: bool
    message: str = ""
    dependencies_available: bool = True
    last_check: float = 0.0


@dataclass
class ModuleConfiguration:
    """Configuration for a module."""
    enabled: bool = True
    timeout: int = 30
    max_retries: int = 3
    concurrency: int = 10
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "concurrency": self.concurrency,
            **self.extra,
        }


class BaseModule(ABC):
    """Abstract base class for all ReconForgeX modules.

    All modules inherit from this class and implement the required methods.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        self.config = config or ModuleConfiguration()
        self.stats = ModuleStatistics()
        self._results: List[Any] = []
        self._errors: List[str] = []
        self._shared_client: Optional[Any] = None

    def set_http_client(self, client: Any) -> None:
        """Inject a shared HTTP client from the pipeline manager.
        
        All modules MUST use this shared client rather than creating
        their own, to enable connection pooling and unified statistics.
        """
        self._shared_client = client

    @abstractmethod
    async def run(self, target: str, **kwargs: Any) -> List[Any]:
        """Execute the module's core logic.

        Parameters
        ----------
        target:
            The target domain, URL, or identifier to analyze.
        **kwargs:
            Additional module-specific parameters.

        Returns
        -------
        List[Any]
            List of results produced by the module.
        """
        ...

    def metadata(self) -> ModuleMetadata:
        """Return metadata describing this module.

        Override in subclasses to provide custom metadata.
        """
        return ModuleMetadata(
            name=self.__class__.__name__,
            description=self.__doc__ or "No description available",
        )

    def statistics(self) -> ModuleStatistics:
        """Return current execution statistics."""
        return self.stats

    def health(self) -> ModuleHealth:
        """Return health check status.

        Override in subclasses to provide custom health checks.
        """
        return ModuleHealth(
            healthy=True,
            message="Module is operational",
            last_check=time.time(),
        )

    def configuration(self) -> ModuleConfiguration:
        """Return current module configuration."""
        return self.config

    def reset(self) -> None:
        """Reset module state for a new execution."""
        self.stats = ModuleStatistics()
        self._results = []
        self._errors = []

    def _record_error(self, error: str) -> None:
        """Record an error that occurred during execution."""
        self._errors.append(error)
        self.stats.errors += 1
