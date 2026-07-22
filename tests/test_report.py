"""Tests for reconforgex.report.* report builders."""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict

from reconforgex.pipeline.statistics import PipelineStatistics
from reconforgex.report.html_report import build_html_report
from reconforgex.report.json_report import build_json_report
from reconforgex.report.markdown_report import build_markdown_report


def _sample_data_store() -> Dict[str, Any]:
    return {
        "domain": "example.com",
        "worker_count": 50,
        "generated_at": "2026-07-22 00:00:00 UTC",
        "live_host_count": 2,
        "findings_count": 5,
        "technologies": ["nginx", "React"],
        "fingerprints": [
            {
                "url": "https://www.example.com",
                "status_code": 200,
                "server": "nginx",
                "technologies": ["nginx", "React"],
                "title": "Example Domain",
            }
        ],
        "security_headers": [
            {
                "url": "https://www.example.com",
                "status_code": 200,
                "compliance_score": 75.0,
                "checks": [
                    {"header": "Strict-Transport-Security", "present": True, "compliant": True}
                ],
            }
        ],
        "tls_results": [
            {
                "host": "example.com",
                "port": 443,
                "tls_version": "TLSv1.3",
                "certificate_issuer": "Let's Encrypt",
                "days_remaining": 45,
                "is_expired": False,
            }
        ],
        "csp_analysis": [
            {
                "url": "https://www.example.com",
                "policy": "default-src 'self'",
                "score": 70,
                "weaknesses": ["No script-src directive"],
                "strengths": [],
            }
        ],
        "js_secrets": [
            {
                "source_url": "https://www.example.com/app.js",
                "findings": [
                    {
                        "type": "API Key",
                        "severity": "high",
                        "value": "sk_live_***",
                        "source_url": "https://www.example.com/app.js",
                    }
                ],
                "total_found": 1,
            }
        ],
        "interesting_files": [
            {
                "base_url": "https://www.example.com",
                "files": [
                    {
                        "url": "https://www.example.com/.env",
                        "status_code": 200,
                        "category": "config",
                    }
                ],
                "total_found": 1,
            }
        ],
        "response_analysis": [
            {
                "base_url": "https://www.example.com",
                "total_requests": 1,
                "redirect_count": 0,
            }
        ],
        "risk_score": [
            {
                "overall_score": 72.5,
                "risk_level": "Low Risk",
                "category_scores": {
                    "security_headers": 75.0,
                    "tls": 85.0,
                    "csp": 70.0,
                    "secrets": 60.0,
                },
            }
        ],
    }


def _sample_stats() -> PipelineStatistics:
    stats = PipelineStatistics(
        start_time=1000.0,
        end_time=1200.0,
        execution_time=200.0,
        domains_processed=1,
        live_hosts=2,
        technologies=2,
        headers_analyzed=10,
        certificates=1,
        redirects=0,
        errors=0,
        retries=2,
        total_requests=15,
        avg_response_time=0.234,
        median_response_time=0.189,
        p95_response_time=0.456,
        p99_response_time=0.678,
        requests_per_second=5.3,
    )
    stats.tls_versions = {"TLSv1.3": 1, "TLSv1.2": 1}
    return stats


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
            assert report["summary"]["technologies_found"] == 2
            assert "http_fingerprinting" in report["modules"]
            assert "risk_scoring" in report["modules"]


class TestMarkdownReport:
    """Tests for Markdown report generation."""

    def test_build_markdown_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.md"
            build_markdown_report(_sample_data_store(), _sample_stats(), path)

            assert path.exists()
            content = path.read_text()
            assert "# ReconForgeX Reconnaissance Report" in content
            assert "example.com" in content
            assert "nginx" in content
            assert "Risk Level" in content


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
            assert "nginx" in content