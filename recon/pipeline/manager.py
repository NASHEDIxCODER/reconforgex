"""
Pipeline execution manager.

Orchestrates the full reconnaissance workflow: registers all stages,
resolves their dependencies, executes them in topological order (with
concurrency where possible), collects statistics, and returns the
aggregated results.
"""

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from recon.config import ReconConfig
from recon.constants import (
    DEFAULT_SCREENSHOT_DIR,
    LIVE_HOSTS_FILE,
    NMAP_FILE,
    NUCLEI_FILE,
    STAGE_LIVE_HOST_DETECTION,
    STAGE_PORT_SCAN,
    STAGE_REPORT,
    STAGE_SCREENSHOTS,
    STAGE_SUBDOMAIN_ENUM,
    STAGE_TECH_DETECTION,
    STAGE_VULNERABILITY_SCAN,
    SUBDOMAINS_FILE,
)
from recon.logger import get_logger
from recon.modules.enum import enumerate_subdomains
from recon.modules.nuclei import run_vulnerability_scan
from recon.modules.ports import run_port_scan
from recon.modules.probe import LiveHost, probe_hosts
from recon.modules.screenshot import take_screenshots
from recon.pipeline.scheduler import (
    PipelineScheduler,
    Stage,
    StageResult,
    StageStatus,
)
from recon.utils.files import ensure_directory, write_lines

log = get_logger()


@dataclass
class ScanStatistics:
    """Execution statistics collected during a scan.

    Attributes
    ----------
    start_time:
        Unix timestamp when the scan started.
    end_time:
        Unix timestamp when the scan finished.
    hosts_found:
        Number of unique subdomains discovered.
    live_hosts:
        Number of live web servers found.
    screenshots_taken:
        Number of screenshots captured (0 if skipped).
    ports_scanned:
        Number of hosts port-scanned (0 if skipped).
    nuclei_findings:
        Number of Nuclei findings (0 if skipped).
    stage_results:
        Detailed results for each pipeline stage.
    """

    start_time: float = 0.0
    end_time: float = 0.0
    hosts_found: int = 0
    live_hosts: int = 0
    screenshots_taken: int = 0
    ports_scanned: int = 0
    nuclei_findings: int = 0
    stage_results: List[StageResult] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        """Total wall-clock duration of the scan."""
        if self.end_time > self.start_time:
            return self.end_time - self.start_time
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize statistics to a plain dictionary for reporting."""
        return {
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "hosts_found": self.hosts_found,
            "live_hosts": self.live_hosts,
            "screenshots_taken": self.screenshots_taken,
            "ports_scanned": self.ports_scanned,
            "nuclei_findings": self.nuclei_findings,
            "stages": [
                {
                    "name": r.stage_name,
                    "status": r.status.name,
                    "error": r.error,
                    "duration_seconds": r.duration_seconds,
                }
                for r in self.stage_results
            ],
        }


class PipelineManager:
    """Top-level orchestrator for the reconnaissance pipeline.

    Usage::

        manager = PipelineManager(config)
        results = await manager.run()
    """

    def __init__(self, config: ReconConfig) -> None:
        self.config = config
        self.stats = ScanStatistics()
        self._data_store: Dict[str, Any] = {}
        self._scheduler = PipelineScheduler()
        self._register_default_stages()

    # ── Stage Registration ───────────────────────────────────────────────────

    def _register_default_stages(self) -> None:
        """Register all built-in pipeline stages with their dependencies."""

        self._scheduler.register(
            Stage(
                name=STAGE_SUBDOMAIN_ENUM,
                description="Discover subdomains using subfinder & assetfinder",
                depends_on=[],
                run_async=False,
                func=self._run_subdomain_enum,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_LIVE_HOST_DETECTION,
                description="Probe subdomains for live web servers",
                depends_on=[STAGE_SUBDOMAIN_ENUM],
                run_async=False,
                func=self._run_live_host_detection,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_TECH_DETECTION,
                description="Detect technologies on live hosts",
                depends_on=[STAGE_LIVE_HOST_DETECTION],
                run_async=False,
                func=self._run_tech_detection,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_SCREENSHOTS,
                description="Capture screenshots of live hosts",
                depends_on=[STAGE_LIVE_HOST_DETECTION],
                run_async=True,
                func=self._run_screenshots,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_PORT_SCAN,
                description="Run Nmap port scan on live hosts",
                depends_on=[STAGE_LIVE_HOST_DETECTION],
                run_async=True,
                func=self._run_port_scan,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_VULNERABILITY_SCAN,
                description="Run Nuclei vulnerability scan on live hosts",
                depends_on=[STAGE_LIVE_HOST_DETECTION],
                run_async=True,
                func=self._run_vuln_scan,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_REPORT,
                description="Build final reports (JSON, Markdown, HTML)",
                depends_on=[
                    STAGE_SUBDOMAIN_ENUM,
                    STAGE_LIVE_HOST_DETECTION,
                    STAGE_TECH_DETECTION,
                    STAGE_SCREENSHOTS,
                ],
                run_async=False,
                func=self._run_report_builder,
            )
        )

    # ── Stage Implementations ────────────────────────────────────────────────

    async def _run_subdomain_enum(self) -> StageResult:
        start = time.monotonic()
        try:
            output_path = self._output_dir / SUBDOMAINS_FILE
            subdomains = await enumerate_subdomains(
                domain=self.config.domain,
                subfinder_path=self.config.resolve_tool_path("subfinder"),
                assetfinder_path=self.config.resolve_tool_path("assetfinder"),
                timeout=self.config.timeout,
                output_path=output_path,
            )
            self._data_store["subdomains"] = subdomains
            self.stats.hosts_found = len(subdomains)
            return StageResult(
                stage_name=STAGE_SUBDOMAIN_ENUM,
                status=StageStatus.COMPLETED,
                data=subdomains,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("Subdomain enumeration failed")
            return StageResult(
                stage_name=STAGE_SUBDOMAIN_ENUM,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_live_host_detection(self) -> StageResult:
        start = time.monotonic()
        subdomains = self._data_store.get("subdomains", [])
        if not subdomains:
            return StageResult(
                stage_name=STAGE_LIVE_HOST_DETECTION,
                status=StageStatus.SKIPPED,
                error="No subdomains to probe",
                duration_seconds=time.monotonic() - start,
            )
        try:
            hosts = await probe_hosts(
                subdomains=subdomains,
                httpx_path=self.config.resolve_tool_path("httpx"),
                timeout=self.config.timeout,
            )
            self._data_store["live_hosts"] = hosts
            self.stats.live_hosts = len(hosts)

            # Write live URLs to file
            live_urls = [h.url for h in hosts if h.url]
            if live_urls:
                write_lines(self._output_dir / LIVE_HOSTS_FILE, live_urls)

            return StageResult(
                stage_name=STAGE_LIVE_HOST_DETECTION,
                status=StageStatus.COMPLETED,
                data=hosts,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("Live host detection failed")
            return StageResult(
                stage_name=STAGE_LIVE_HOST_DETECTION,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_tech_detection(self) -> StageResult:
        start = time.monotonic()
        hosts: List[LiveHost] = self._data_store.get("live_hosts", [])
        if not hosts:
            return StageResult(
                stage_name=STAGE_TECH_DETECTION,
                status=StageStatus.SKIPPED,
                error="No live hosts to fingerprint",
                duration_seconds=time.monotonic() - start,
            )
        # Technology detection is embedded in the httpx probe; we just
        # surface the data here.
        tech_summary = []
        for host in hosts:
            if host.technologies:
                tech_summary.append(f"{host.url}: {', '.join(host.technologies)}")
        self._data_store["technologies"] = tech_summary
        return StageResult(
            stage_name=STAGE_TECH_DETECTION,
            status=StageStatus.COMPLETED,
            data=tech_summary,
            duration_seconds=time.monotonic() - start,
        )

    async def _run_screenshots(self) -> StageResult:
        start = time.monotonic()
        hosts: List[LiveHost] = self._data_store.get("live_hosts", [])
        live_urls = [h.url for h in hosts if h.url]
        if not live_urls:
            return StageResult(
                stage_name=STAGE_SCREENSHOTS,
                status=StageStatus.SKIPPED,
                error="No live URLs to screenshot",
                duration_seconds=time.monotonic() - start,
            )
        try:
            success = await take_screenshots(
                live_urls=live_urls,
                aquatone_path=self.config.resolve_tool_path("aquatone"),
                output_dir=self._output_dir,
                timeout=self.config.timeout * 2,
            )
            self.stats.screenshots_taken = len(live_urls) if success else 0
            return StageResult(
                stage_name=STAGE_SCREENSHOTS,
                status=StageStatus.COMPLETED if success else StageStatus.FAILED,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("Screenshot stage failed")
            return StageResult(
                stage_name=STAGE_SCREENSHOTS,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_port_scan(self) -> StageResult:
        start = time.monotonic()
        if not self.config.port_scan:
            return StageResult(
                stage_name=STAGE_PORT_SCAN,
                status=StageStatus.SKIPPED,
                error="Port scan not requested",
                duration_seconds=time.monotonic() - start,
            )
        hosts: List[LiveHost] = self._data_store.get("live_hosts", [])
        live_urls = [h.url for h in hosts if h.url]
        if not live_urls:
            return StageResult(
                stage_name=STAGE_PORT_SCAN,
                status=StageStatus.SKIPPED,
                error="No live hosts to scan",
                duration_seconds=time.monotonic() - start,
            )
        try:
            output_path = self._output_dir / NMAP_FILE
            results = await run_port_scan(
                live_urls=live_urls,
                nmap_path=self.config.resolve_tool_path("nmap"),
                output_path=output_path,
                timeout=self.config.timeout * 2,
            )
            self._data_store["port_scan_results"] = results
            self.stats.ports_scanned = len(
                {u.split("://")[-1].split("/")[0].split(":")[0] for u in live_urls}
            )
            return StageResult(
                stage_name=STAGE_PORT_SCAN,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("Port scan failed")
            return StageResult(
                stage_name=STAGE_PORT_SCAN,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_vuln_scan(self) -> StageResult:
        start = time.monotonic()
        if not self.config.vuln_scan:
            return StageResult(
                stage_name=STAGE_VULNERABILITY_SCAN,
                status=StageStatus.SKIPPED,
                error="Vulnerability scan not requested",
                duration_seconds=time.monotonic() - start,
            )
        hosts: List[LiveHost] = self._data_store.get("live_hosts", [])
        live_urls = [h.url for h in hosts if h.url]
        if not live_urls:
            return StageResult(
                stage_name=STAGE_VULNERABILITY_SCAN,
                status=StageStatus.SKIPPED,
                error="No live hosts to scan",
                duration_seconds=time.monotonic() - start,
            )
        try:
            output_path = self._output_dir / NUCLEI_FILE
            findings = await run_vulnerability_scan(
                live_urls=live_urls,
                nuclei_path=self.config.resolve_tool_path("nuclei"),
                output_path=output_path,
                timeout=self.config.timeout * 2,
            )
            self._data_store["nuclei_findings"] = findings
            self.stats.nuclei_findings = len(findings)
            return StageResult(
                stage_name=STAGE_VULNERABILITY_SCAN,
                status=StageStatus.COMPLETED,
                data=findings,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("Vulnerability scan failed")
            return StageResult(
                stage_name=STAGE_VULNERABILITY_SCAN,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_report_builder(self) -> StageResult:
        start = time.monotonic()
        try:
            from recon.report.json_report import build_json_report
            from recon.report.markdown_report import build_markdown_report
            from recon.report.html_report import build_html_report

            report_dir = ensure_directory(self._output_dir / "reports")

            json_path = report_dir / "report.json"
            md_path = report_dir / "report.md"
            html_path = report_dir / "report.html"

            build_json_report(self._data_store, self.stats, json_path)
            build_markdown_report(self._data_store, self.stats, md_path)
            build_html_report(self._data_store, self.stats, html_path)

            log.info("Reports generated: %s, %s, %s", json_path, md_path, html_path)
            return StageResult(
                stage_name=STAGE_REPORT,
                status=StageStatus.COMPLETED,
                data={"json": str(json_path), "md": str(md_path), "html": str(html_path)},
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("Report generation failed")
            return StageResult(
                stage_name=STAGE_REPORT,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    # ── Execution ────────────────────────────────────────────────────────────

    async def run(self) -> ScanStatistics:
        """Execute the full reconnaissance pipeline.

        Returns
        -------
        ScanStatistics
            Aggregated statistics and stage results.
        """
        self.stats.start_time = time.time()
        self._output_dir = ensure_directory(self.config.output_directory)

        log.info("=" * 60)
        log.info("Starting reconnaissance pipeline for: %s", self.config.domain)
        log.info("Output directory: %s", self._output_dir)
        log.info("=" * 60)

        waves = self._scheduler.get_execution_order()

        for wave_idx, wave in enumerate(waves):
            log.info("--- Wave %d: %d stage(s) ---", wave_idx + 1, len(wave))

            # Run stages in this wave concurrently
            tasks = []
            for stage in wave:
                if stage.func is None:
                    log.warning("Stage %s has no function, skipping", stage.name)
                    continue
                tasks.append(self._execute_stage(stage))

            if tasks:
                results = await asyncio.gather(*tasks)
                self.stats.stage_results.extend(results)

        self.stats.end_time = time.time()

        log.info("=" * 60)
        log.info("Pipeline complete. Duration: %.2f seconds", self.stats.duration_seconds)
        log.info("=" * 60)

        return self.stats

    async def _execute_stage(self, stage: Stage) -> StageResult:
        """Execute a single stage and return its result."""
        log.info("▶ %s: %s", stage.name, stage.description)
        assert stage.func is not None
        result = await stage.func()
        if result.status == StageStatus.COMPLETED:
            log.info("✓ %s completed in %.2fs", stage.name, result.duration_seconds)
        elif result.status == StageStatus.SKIPPED:
            log.info("− %s skipped: %s", stage.name, result.error or "")
        else:
            log.error("✗ %s failed: %s", stage.name, result.error or "")
        return result