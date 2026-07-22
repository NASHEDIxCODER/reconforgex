"""
Pipeline Statistics Module.

Collects and computes comprehensive execution statistics including
timing percentiles, throughput, resource usage, and error rates.
"""

import time
import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from statistics import median


@dataclass
class PipelineStatistics:
    """Comprehensive pipeline execution statistics.

    Attributes
    ----------
    start_time:
        Unix timestamp when the pipeline started.
    end_time:
        Unix timestamp when the pipeline finished.
    execution_time:
        Total wall-clock execution time in seconds.
    avg_response_time:
        Average HTTP response time in seconds.
    median_response_time:
        Median HTTP response time in seconds.
    p95_response_time:
        95th percentile response time in seconds.
    p99_response_time:
        99th percentile response time in seconds.
    requests_per_second:
        Average requests per second.
    domains_processed:
        Number of domains processed.
    live_hosts:
        Number of live hosts discovered.
    technologies:
        Number of unique technologies detected.
    headers_analyzed:
        Number of HTTP headers analyzed.
    tls_versions:
        Distribution of TLS versions found.
    certificates:
        Number of TLS certificates inspected.
    redirects:
        Number of redirects followed.
    errors:
        Total number of errors encountered.
    retries:
        Total number of retries performed.
    memory_usage_mb:
        Peak memory usage in MB.
    cpu_percent:
        Average CPU usage percentage.
    total_requests:
        Total number of HTTP requests made.
    """

    start_time: float = 0.0
    end_time: float = 0.0
    execution_time: float = 0.0
    avg_response_time: float = 0.0
    median_response_time: float = 0.0
    p95_response_time: float = 0.0
    p99_response_time: float = 0.0
    requests_per_second: float = 0.0
    domains_processed: int = 0
    live_hosts: int = 0
    technologies: int = 0
    headers_analyzed: int = 0
    tls_versions: Dict[str, int] = field(default_factory=dict)
    certificates: int = 0
    redirects: int = 0
    errors: int = 0
    retries: int = 0
    memory_usage_mb: float = 0.0
    cpu_percent: float = 0.0
    total_requests: int = 0

    def compute_percentiles(self, timings: List[float]) -> None:
        """Compute timing percentiles from a list of response times."""
        if not timings:
            return

        sorted_timings = sorted(timings)
        n = len(sorted_timings)

        self.avg_response_time = sum(sorted_timings) / n
        self.median_response_time = median(sorted_timings)

        p95_idx = int(n * 0.95)
        p99_idx = int(n * 0.99)
        self.p95_response_time = sorted_timings[min(p95_idx, n - 1)]
        self.p99_response_time = sorted_timings[min(p99_idx, n - 1)]

        elapsed = self.end_time - self.start_time
        if elapsed > 0:
            self.requests_per_second = n / elapsed

    def update_resource_usage(self) -> None:
        """Update memory and CPU usage statistics."""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            self.memory_usage_mb = process.memory_info().rss / (1024 * 1024)
            self.cpu_percent = process.cpu_percent(interval=0.1)
        except ImportError:
            # Fallback to /proc/self/status on Linux
            try:
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            parts = line.split()
                            if len(parts) >= 2:
                                self.memory_usage_mb = float(parts[1]) / 1024
                        elif line.startswith("VmSize:"):
                            parts = line.split()
                            if len(parts) >= 2:
                                self.memory_usage_mb = max(
                                    self.memory_usage_mb, float(parts[1]) / 1024
                                )
            except (FileNotFoundError, IOError):
                pass

    def to_dict(self) -> Dict[str, Any]:
        """Serialize statistics to a dictionary."""
        return {
            "execution_time": round(self.execution_time, 3),
            "avg_response_time": round(self.avg_response_time, 3),
            "median_response_time": round(self.median_response_time, 3),
            "p95_response_time": round(self.p95_response_time, 3),
            "p99_response_time": round(self.p99_response_time, 3),
            "requests_per_second": round(self.requests_per_second, 2),
            "domains_processed": self.domains_processed,
            "live_hosts": self.live_hosts,
            "technologies": self.technologies,
            "headers_analyzed": self.headers_analyzed,
            "tls_versions": self.tls_versions,
            "certificates": self.certificates,
            "redirects": self.redirects,
            "errors": self.errors,
            "retries": self.retries,
            "memory_usage_mb": round(self.memory_usage_mb, 1),
            "cpu_percent": round(self.cpu_percent, 1),
            "total_requests": self.total_requests,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PipelineStatistics":
        """Create statistics from a dictionary."""
        return cls(
            execution_time=data.get("execution_time", 0.0),
            avg_response_time=data.get("avg_response_time", 0.0),
            median_response_time=data.get("median_response_time", 0.0),
            p95_response_time=data.get("p95_response_time", 0.0),
            p99_response_time=data.get("p99_response_time", 0.0),
            requests_per_second=data.get("requests_per_second", 0.0),
            domains_processed=data.get("domains_processed", 0),
            live_hosts=data.get("live_hosts", 0),
            technologies=data.get("technologies", 0),
            headers_analyzed=data.get("headers_analyzed", 0),
            tls_versions=data.get("tls_versions", {}),
            certificates=data.get("certificates", 0),
            redirects=data.get("redirects", 0),
            errors=data.get("errors", 0),
            retries=data.get("retries", 0),
            memory_usage_mb=data.get("memory_usage_mb", 0.0),
            cpu_percent=data.get("cpu_percent", 0.0),
            total_requests=data.get("total_requests", 0),
        )