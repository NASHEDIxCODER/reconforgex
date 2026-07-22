#!/usr/bin/env python3
"""
Basic benchmarks for the recon framework.

Measures execution time, approximate memory usage (via /proc/self/status),
and CPU time (via resource module) for key operations.

Usage:
    python benchmarks/bench_basic.py
"""

import os
import sys
import time
import tracemalloc
from pathlib import Path

# Ensure the project root is on sys.path
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))


def _get_memory_kb() -> int:
    """Return approximate RSS in kB from /proc/self/status (Linux only)."""
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, IndexError, ValueError):
        pass
    return 0


def _run_benchmark(name: str, fn, iterations: int = 1000) -> dict:
    """Run a benchmark and return timing / memory statistics."""
    # Warmup
    fn()

    # Memory before
    mem_before = _get_memory_kb()

    # Timing
    tracemalloc.start()
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    mem_after = _get_memory_kb()

    return {
        "name": name,
        "iterations": iterations,
        "total_seconds": round(elapsed, 4),
        "avg_ms": round(elapsed / iterations * 1000, 4),
        "ops_per_sec": round(iterations / elapsed, 2) if elapsed > 0 else float("inf"),
        "memory_delta_kb": mem_after - mem_before,
        "traced_peak_mb": round(peak / 1024 / 1024, 4),
    }


def _print_results(results: list) -> None:
    """Pretty-print benchmark results."""
    print(f"\n{'=' * 80}")
    print(f"{'Benchmark':<30} {'Iterations':<12} {'Avg (ms)':<12} {'Ops/s':<12} {'Mem Δ (KB)':<12}")
    print(f"{'-' * 80}")
    for r in results:
        print(
            f"{r['name']:<30} {r['iterations']:<12} {r['avg_ms']:<12} "
            f"{r['ops_per_sec']:<12} {r['memory_delta_kb']:<12}"
        )
    print(f"{'=' * 80}\n")


def bench_validators() -> None:
    """Benchmark domain/URL validation."""
    from recon.utils.validators import validate_domain, validate_url

    domains = ["example.com", "sub.domain.example.com", "a.b.c.d.example.org"]
    for d in domains:
        validate_domain(d)

    urls = [
        "https://example.com",
        "https://sub.example.com/path?q=hello",
    ]
    for u in urls:
        validate_url(u)


def bench_config() -> None:
    """Benchmark config creation."""
    from recon.config import ReconConfig

    config = ReconConfig(domain="test.com", port_scan=True, vuln_scan=True)
    _ = config.merged_with_cli(verbose=True)


def bench_scheduler() -> None:
    """Benchmark pipeline scheduler DAG creation."""
    from recon.pipeline.scheduler import PipelineScheduler, Stage

    scheduler = PipelineScheduler()
    for i in range(10):
        deps = [f"stage_{j}" for j in range(max(0, i - 2))]
        scheduler.register(
            Stage(
                name=f"stage_{i}",
                description=f"Stage {i}",
                depends_on=deps,
            )
        )
    scheduler.get_execution_order()


def bench_statistics() -> None:
    """Benchmark ScanStatistics creation and serialization."""
    from recon.pipeline.manager import ScanStatistics
    from recon.pipeline.scheduler import StageResult, StageStatus

    stats = ScanStatistics(
        start_time=1000.0,
        end_time=1200.0,
        hosts_found=100,
        live_hosts=50,
        screenshots_taken=30,
        ports_scanned=10,
        nuclei_findings=5,
        stage_results=[
            StageResult(f"stage_{i}", StageStatus.COMPLETED, duration_seconds=i * 10.0)
            for i in range(7)
        ],
    )
    stats.to_dict()


def main() -> int:
    """Run all benchmarks."""
    print("Recon Framework Benchmarks")
    print("==========================")
    print(f"Python: {sys.version}")
    print(f"Platform: {sys.platform}")

    results = [
        _run_benchmark("validators", bench_validators, iterations=2000),
        _run_benchmark("config", bench_config, iterations=5000),
        _run_benchmark("scheduler", bench_scheduler, iterations=5000),
        _run_benchmark("statistics", bench_statistics, iterations=5000),
    ]

    _print_results(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())