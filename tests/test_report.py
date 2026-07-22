"""Tests for recon.report.* report builders."""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from recon.modules.probe import LiveHost
from recon.pipeline.manager import ScanStatistics
from recon.pipeline.scheduler import StageResult, StageStatus
from recon.report.html_report import build_html_report
from recon.report.json_report import build_json_report
from recon.report.markdown_report import build_markdown_report


def _sample_data_store() -> Dict[str, Any]:
    return {
        "domain": "example.com",
        "subdomains": ["admin.example.com", "www.example.com"],
        "live_hosts": [
            LiveHost(
                url="https://www.example.com",
                status_code=200,
                title="Example Domain",
                technologies=["nginx", "React"],
            ),
            LiveHost(
                url="https://admin.example.com",
                status_code=403,
                title="Forbidden",
                technologies=["nginx"],
            ),
        ],
        "technologies": [
            "https://www.example.com: nginx, React",
            "https://admin.example.com: nginx",
        ],
        "port_scan_results": ["22/tcp open  ssh", "80/tcp open  http"],
        "nuclei_findings": [
            '{"template-id": "test", "info": {"severity": "medium"}}',
        ],
    }


def _sample_stats() -> ScanStatistics:
    return ScanStatistics(
        start_time=1000.0,
        end_time=1200.0,
        hosts_found=2,
        live_hosts=2,
        screenshots_taken=2,
        ports_scanned=1,
        nuclei_findings=1,
        stage_results=[
            StageResult("subdomain_enumeration", StageStatus.COMPLETED, duration_seconds=30.0),
            StageResult("live_host_detection", StageStatus.COMPLETED, duration_seconds=45.0),
            StageResult("screenshots", StageStatus.COMPLETED, duration_seconds=120.0),
            StageResult("port_scan", StageStatus.SKIPPED, duration_seconds=0.0),
            StageResult("vulnerability_scan", StageStatus.COMPLETED, duration_seconds=5.0),
        ],
    )


class TestJsonReport:
    """Tests for JSON report generation."""

    def test_build_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.json"
            build_json_report(_sample_data_store(), _sample_stats(), path)

            assert path.exists()
            with open(path) as fh:
                report = json.load(fh)

            assert report["summary"]["domain"] == "example.com"
            assert report["summary"]["subdomains_discovered"] == 2
            assert report["summary"]["live_hosts_found"] == 2
            assert report["statistics"]["duration_seconds"] == 200.0
            assert len(report["subdomains"]) == 2
            assert len(report["live_hosts"]) == 2


class TestMarkdownReport:
    """Tests for Markdown report generation."""

    def test_build_markdown_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.md"
            build_markdown_report(_sample_data_store(), _sample_stats(), path)

            assert path.exists()
            content = path.read_text()
            assert "# Reconnaissance Report" in content
            assert "example.com" in content
            assert "www.example.com" in content
            assert "nginx" in content
            assert "200" in content


class TestHtmlReport:
    """Tests for HTML report generation."""

    def test_build_html_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.html"
            build_html_report(_sample_data_store(), _sample_stats(), path)

            assert path.exists()
            content = path.read_text()
            assert "<!DOCTYPE html>" in content
            assert "example.com" in content
            assert "www.example.com" in content
            assert "nginx" in content
            assert "stats-grid" in content