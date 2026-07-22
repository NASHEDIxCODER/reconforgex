"""
Pipeline execution manager.

Orchestrates the full reconnaissance workflow: registers all 13 pure-Python
modules, resolves their dependencies, executes them in topological order
(with concurrency where possible), collects statistics, and returns the
aggregated results.

No external tool dependencies. Every module is implemented in pure Python.
"""

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from reconforgex.config import ReconForgeXConfig
from reconforgex.constants import (
    STAGE_HTTP_FINGERPRINT,
    STAGE_HEADER_ANALYZER,
    STAGE_SECURITY_HEADERS,
    STAGE_TLS_INSPECTOR,
    STAGE_CSP_ANALYZER,
    STAGE_ROBOTS_PARSER,
    STAGE_SITEMAP_PARSER,
    STAGE_JS_COLLECTOR,
    STAGE_JS_ENDPOINTS,
    STAGE_JS_SECRETS,
    STAGE_INTERESTING_FILES,
    STAGE_RESPONSE_ANALYZER,
    STAGE_RISK_SCORING,
    STAGE_REPORT,
    MODULE_CLASS_MAP,
)
from reconforgex.logger import get_logger
from reconforgex.modules.base import BaseModule, ModuleConfiguration
from reconforgex.pipeline.scheduler import PipelineScheduler, Stage, StageResult, StageStatus
from reconforgex.pipeline.statistics import PipelineStatistics
from reconforgex.pipeline.worker_pool import WorkerPool, WorkerPoolConfig

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
    stage_results:
        Detailed results for each pipeline stage.
    """

    start_time: float = 0.0
    end_time: float = 0.0
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

    Uses only pure-Python modules. No external tool dependencies.

    Usage::

        manager = PipelineManager(config)
        results = await manager.run()
    """

    def __init__(self, config: ReconForgeXConfig) -> None:
        self.config = config
        self.stats = ScanStatistics()
        self.pipeline_stats = PipelineStatistics()
        self._data_store: Dict[str, Any] = {}
        self._scheduler = PipelineScheduler()
        self._modules: Dict[str, BaseModule] = {}
        self._register_default_stages()

    # ── Stage Registration ───────────────────────────────────────────────────

    def _register_default_stages(self) -> None:
        """Register all 13 pure-Python reconnaissance modules as pipeline stages."""

        # Wave 1: HTTP fingerprinting + header analysis (no dependencies)
        self._scheduler.register(
            Stage(
                name=STAGE_HTTP_FINGERPRINT,
                description="Identify web servers, frameworks, and technologies via HTTP response analysis",
                depends_on=[],
                run_async=True,
                func=self._run_http_fingerprint,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_HEADER_ANALYZER,
                description="Analyze HTTP response headers for security and configuration issues",
                depends_on=[],
                run_async=True,
                func=self._run_header_analyzer,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_SECURITY_HEADERS,
                description="Scan HTTP response headers for OWASP security header compliance",
                depends_on=[],
                run_async=True,
                func=self._run_security_header_scanner,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_TLS_INSPECTOR,
                description="Inspect TLS/SSL certificates, protocol versions, and security configurations",
                depends_on=[],
                run_async=True,
                func=self._run_tls_inspector,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_CSP_ANALYZER,
                description="Analyze Content-Security-Policy headers for weaknesses and bypass vectors",
                depends_on=[],
                run_async=True,
                func=self._run_csp_analyzer,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_ROBOTS_PARSER,
                description="Download and parse robots.txt to discover paths, sitemaps, and restricted areas",
                depends_on=[],
                run_async=True,
                func=self._run_robots_parser,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_SITEMAP_PARSER,
                description="Download and parse XML sitemaps to discover URLs and paths",
                depends_on=[],
                run_async=True,
                func=self._run_sitemap_parser,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_JS_COLLECTOR,
                description="Discover and collect JavaScript files from web pages",
                depends_on=[],
                run_async=True,
                func=self._run_js_collector,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_INTERESTING_FILES,
                description="Discover interesting files, directories, and endpoints on web servers",
                depends_on=[],
                run_async=True,
                func=self._run_interesting_files,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_RESPONSE_ANALYZER,
                description="Analyze HTTP responses for status codes, redirects, content types, and patterns",
                depends_on=[],
                run_async=True,
                func=self._run_response_analyzer,
            )
        )

        # Wave 2: JS analysis depends on JS collector
        self._scheduler.register(
            Stage(
                name=STAGE_JS_ENDPOINTS,
                description="Extract API endpoints, routes, and URLs from JavaScript source code",
                depends_on=[STAGE_JS_COLLECTOR],
                run_async=False,
                func=self._run_js_endpoint_extractor,
            )
        )
        self._scheduler.register(
            Stage(
                name=STAGE_JS_SECRETS,
                description="Detect potential secrets, API keys, tokens, and credentials in JavaScript code",
                depends_on=[STAGE_JS_COLLECTOR],
                run_async=False,
                func=self._run_js_secret_detector,
            )
        )

        # Wave 3: Risk scoring depends on all analysis modules
        self._scheduler.register(
            Stage(
                name=STAGE_RISK_SCORING,
                description="Calculate security risk scores based on findings from all analysis modules",
                depends_on=[
                    STAGE_HEADER_ANALYZER,
                    STAGE_SECURITY_HEADERS,
                    STAGE_TLS_INSPECTOR,
                    STAGE_CSP_ANALYZER,
                    STAGE_JS_SECRETS,
                ],
                run_async=False,
                func=self._run_risk_scoring,
            )
        )

        # Wave 4: Report generation depends on all modules
        self._scheduler.register(
            Stage(
                name=STAGE_REPORT,
                description="Build final reports (HTML, JSON, Markdown)",
                depends_on=[
                    STAGE_HTTP_FINGERPRINT,
                    STAGE_HEADER_ANALYZER,
                    STAGE_SECURITY_HEADERS,
                    STAGE_TLS_INSPECTOR,
                    STAGE_CSP_ANALYZER,
                    STAGE_ROBOTS_PARSER,
                    STAGE_SITEMAP_PARSER,
                    STAGE_JS_COLLECTOR,
                    STAGE_JS_ENDPOINTS,
                    STAGE_JS_SECRETS,
                    STAGE_INTERESTING_FILES,
                    STAGE_RESPONSE_ANALYZER,
                    STAGE_RISK_SCORING,
                ],
                run_async=False,
                func=self._run_report_builder,
            )
        )

    def _get_module(self, module_name: str) -> BaseModule:
        """Get or create a module instance by name."""
        if module_name not in self._modules:
            class_path = MODULE_CLASS_MAP[module_name]
            module_path, class_name = class_path.rsplit(".", 1)
            import importlib
            module = importlib.import_module(module_path)
            cls = getattr(module, class_name)
            mod_config = ModuleConfiguration(
                timeout=self.config.timeout,
                max_retries=self.config.retry_count,
                concurrency=self.config.worker_count,
            )
            self._modules[module_name] = cls(config=mod_config)
        return self._modules[module_name]

    # ── Stage Implementations ────────────────────────────────────────────────

    async def _run_http_fingerprint(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_HTTP_FINGERPRINT)
            results = await module.run(self.config.domain)
            self._data_store["fingerprints"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            self._data_store["technologies"] = list(set(
                tech for r in results for tech in r.technologies
            ))
            self.pipeline_stats.technologies = len(self._data_store["technologies"])
            return StageResult(
                stage_name=STAGE_HTTP_FINGERPRINT,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("HTTP fingerprinting failed")
            return StageResult(
                stage_name=STAGE_HTTP_FINGERPRINT,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_header_analyzer(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_HEADER_ANALYZER)
            results = await module.run(self.config.domain)
            self._data_store["header_analysis"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            self.pipeline_stats.headers_analyzed = sum(len(r.findings) for r in results)
            return StageResult(
                stage_name=STAGE_HEADER_ANALYZER,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("Header analysis failed")
            return StageResult(
                stage_name=STAGE_HEADER_ANALYZER,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_security_header_scanner(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_SECURITY_HEADERS)
            results = await module.run(self.config.domain)
            self._data_store["security_headers"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            return StageResult(
                stage_name=STAGE_SECURITY_HEADERS,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("Security header scan failed")
            return StageResult(
                stage_name=STAGE_SECURITY_HEADERS,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_tls_inspector(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_TLS_INSPECTOR)
            results = await module.run(self.config.domain)
            self._data_store["tls_results"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            # Track TLS versions
            tls_versions = {}
            for r in results:
                ver = r.tls_version or "Unknown"
                tls_versions[ver] = tls_versions.get(ver, 0) + 1
            self.pipeline_stats.tls_versions = tls_versions
            self.pipeline_stats.certificates = sum(1 for r in results if r.certificate_issuer)
            return StageResult(
                stage_name=STAGE_TLS_INSPECTOR,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("TLS inspection failed")
            return StageResult(
                stage_name=STAGE_TLS_INSPECTOR,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_csp_analyzer(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_CSP_ANALYZER)
            results = await module.run(self.config.domain)
            self._data_store["csp_analysis"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            return StageResult(
                stage_name=STAGE_CSP_ANALYZER,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("CSP analysis failed")
            return StageResult(
                stage_name=STAGE_CSP_ANALYZER,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_robots_parser(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_ROBOTS_PARSER)
            results = await module.run(self.config.domain)
            self._data_store["robots_analysis"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            return StageResult(
                stage_name=STAGE_ROBOTS_PARSER,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("robots.txt parsing failed")
            return StageResult(
                stage_name=STAGE_ROBOTS_PARSER,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_sitemap_parser(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_SITEMAP_PARSER)
            results = await module.run(self.config.domain)
            self._data_store["sitemap_analysis"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            return StageResult(
                stage_name=STAGE_SITEMAP_PARSER,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("sitemap.xml parsing failed")
            return StageResult(
                stage_name=STAGE_SITEMAP_PARSER,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_js_collector(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_JS_COLLECTOR)
            results = await module.run(self.config.domain)
            self._data_store["js_files"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            # Collect JS contents for downstream modules
            js_contents = []
            for result in results:
                for js_file in result.js_files:
                    js_contents.append((js_file.url, js_file.content))
            self._data_store["js_contents"] = js_contents
            return StageResult(
                stage_name=STAGE_JS_COLLECTOR,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("JS collection failed")
            return StageResult(
                stage_name=STAGE_JS_COLLECTOR,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_js_endpoint_extractor(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_JS_ENDPOINTS)
            js_contents = self._data_store.get("js_contents", [])
            results = await module.run(self.config.domain, js_contents=js_contents)
            self._data_store["js_endpoints"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            return StageResult(
                stage_name=STAGE_JS_ENDPOINTS,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("JS endpoint extraction failed")
            return StageResult(
                stage_name=STAGE_JS_ENDPOINTS,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_js_secret_detector(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_JS_SECRETS)
            js_contents = self._data_store.get("js_contents", [])
            results = await module.run(self.config.domain, js_contents=js_contents)
            self._data_store["js_secrets"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            return StageResult(
                stage_name=STAGE_JS_SECRETS,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("JS secret detection failed")
            return StageResult(
                stage_name=STAGE_JS_SECRETS,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_interesting_files(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_INTERESTING_FILES)
            results = await module.run(self.config.domain)
            self._data_store["interesting_files"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            return StageResult(
                stage_name=STAGE_INTERESTING_FILES,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("Interesting files discovery failed")
            return StageResult(
                stage_name=STAGE_INTERESTING_FILES,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_response_analyzer(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_RESPONSE_ANALYZER)
            results = await module.run(self.config.domain)
            self._data_store["response_analysis"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            # Track redirects
            total_redirects = sum(r.redirect_count for r in results)
            self.pipeline_stats.redirects = total_redirects
            return StageResult(
                stage_name=STAGE_RESPONSE_ANALYZER,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("HTTP response analysis failed")
            return StageResult(
                stage_name=STAGE_RESPONSE_ANALYZER,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_risk_scoring(self) -> StageResult:
        start = time.monotonic()
        try:
            module = self._get_module(STAGE_RISK_SCORING)
            results = await module.run(
                target=self.config.domain,
                header_results=self._data_store.get("header_analysis", []),
                tls_results=self._data_store.get("tls_results", []),
                csp_results=self._data_store.get("csp_analysis", []),
                secret_results=self._data_store.get("js_secrets", []),
            )
            self._data_store["risk_score"] = [r.__dict__ if hasattr(r, "__dict__") else r for r in results]
            return StageResult(
                stage_name=STAGE_RISK_SCORING,
                status=StageStatus.COMPLETED,
                data=results,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            log.exception("Risk scoring failed")
            return StageResult(
                stage_name=STAGE_RISK_SCORING,
                status=StageStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    async def _run_report_builder(self) -> StageResult:
        start = time.monotonic()
        try:
            from reconforgex.report.json_report import build_json_report
            from reconforgex.report.markdown_report import build_markdown_report
            from reconforgex.report.html_report import build_html_report

            report_dir = self._output_dir / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)

            json_path = report_dir / "report.json"
            md_path = report_dir / "report.md"
            html_path = report_dir / "report.html"

            # Build data store for reports
            self._data_store["domain"] = self.config.domain
            self._data_store["worker_count"] = self.config.worker_count
            self._data_store["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

            # Count total findings
            total_findings = 0
            for key in ["header_analysis", "js_secrets", "csp_analysis", "security_headers"]:
                items = self._data_store.get(key, [])
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            total_findings += len(item.get("findings", item.get("checks", [])))
            self._data_store["findings_count"] = total_findings

            # Count live hosts
            live_hosts = len(self._data_store.get("fingerprints", []))
            self._data_store["live_host_count"] = live_hosts
            self.pipeline_stats.live_hosts = live_hosts
            self.pipeline_stats.domains_processed = 1

            # Build reports
            build_json_report(self._data_store, self.pipeline_stats, json_path)
            build_markdown_report(self._data_store, self.pipeline_stats, md_path)
            build_html_report(self._data_store, self.pipeline_stats, html_path)

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

    async def run(self) -> PipelineStatistics:
        """Execute the full reconnaissance pipeline.

        Returns
        -------
        PipelineStatistics
            Aggregated statistics and stage results.
        """
        self.stats.start_time = time.time()
        self.pipeline_stats.start_time = self.stats.start_time
        self._output_dir = self.config.output_directory
        self._output_dir.mkdir(parents=True, exist_ok=True)

        log.info("=" * 60)
        log.info("Starting ReconForgeX pipeline for: %s", self.config.domain)
        log.info("Output directory: %s", self._output_dir)
        log.info("Workers: %d", self.config.worker_count)
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
        self.pipeline_stats.end_time = self.stats.end_time
        self.pipeline_stats.execution_time = self.stats.duration_seconds
        self.pipeline_stats.update_resource_usage()

        log.info("=" * 60)
        log.info("Pipeline complete. Duration: %.2f seconds", self.stats.duration_seconds)
        log.info("=" * 60)

        return self.pipeline_stats

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