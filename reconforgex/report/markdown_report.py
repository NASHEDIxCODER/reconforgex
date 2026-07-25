"""
Markdown report builder.

Generates a comprehensive ``report.md`` with formatted sections for
every module of the reconnaissance pipeline.
"""

from pathlib import Path
from typing import Any, Dict, List

from reconforgex.logger import get_logger
from reconforgex.pipeline.statistics import PipelineStatistics

log = get_logger()


def _format_duration(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"


def build_markdown_report(
    data_store: Dict[str, Any],
    stats: PipelineStatistics,
    output_path: Path,
) -> None:
    """Generate a Markdown report from the pipeline data store.

    Parameters
    ----------
    data_store:
        Shared pipeline data store containing scan results.
    stats:
        Aggregated pipeline statistics.
    output_path:
        Destination file path for the Markdown report.
    """
    stats_dict = stats.to_dict() if hasattr(stats, "to_dict") else {}
    lines: List[str] = []

    # ── Header ───────────────────────────────────────────────────────────────
    lines.append("# ReconForgeX Reconnaissance Report")
    lines.append("")
    lines.append(f"**Domain:** `{data_store.get('domain', 'Unknown')}`")
    lines.append(f"**Generated:** `{data_store.get('generated_at', '')}`")
    lines.append(f"**Duration:** {_format_duration(stats_dict.get('execution_time', 0))}")
    lines.append(f"**Workers:** {data_store.get('worker_count', 50)}")
    lines.append("")

    # ── Summary ──────────────────────────────────────────────────────────────
    lines.append("## 📊 Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|------:|")
    lines.append(f"| Live Hosts | {data_store.get('live_host_count', 0)} |")
    lines.append(f"| Technologies Found | {stats_dict.get('technologies', 0)} |")
    lines.append(f"| Headers Analyzed | {stats_dict.get('headers_analyzed', 0)} |")
    lines.append(f"| TLS Certificates | {stats_dict.get('certificates', 0)} |")
    lines.append(f"| Redirects | {stats_dict.get('redirects', 0)} |")
    lines.append(f"| Security Findings | {data_store.get('findings_count', 0)} |")
    lines.append(f"| Errors | {stats_dict.get('errors', 0)} |")
    lines.append("")

    # ── Execution Statistics ─────────────────────────────────────────────────
    lines.append("## ⏱️ Execution Statistics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|------:|")
    lines.append(f"| Execution Time | {_format_duration(stats_dict.get('execution_time', 0))} |")
    lines.append(f"| Avg Response Time | {stats_dict.get('avg_response_time', 0):.3f}s |")
    lines.append(f"| Median Response Time | {stats_dict.get('median_response_time', 0):.3f}s |")
    lines.append(f"| P95 Response Time | {stats_dict.get('p95_response_time', 0):.3f}s |")
    lines.append(f"| P99 Response Time | {stats_dict.get('p99_response_time', 0):.3f}s |")
    lines.append(f"| Requests/sec | {stats_dict.get('requests_per_second', 0):.1f} |")
    lines.append(f"| Total Requests | {stats_dict.get('total_requests', 0)} |")
    lines.append(f"| Retries | {stats_dict.get('retries', 0)} |")
    lines.append(f"| Peak Memory | {stats_dict.get('memory_usage_mb', 0):.1f} MB |")
    lines.append(f"| CPU Usage | {stats_dict.get('cpu_percent', 0):.1f}% |")
    lines.append("")

    # ── HTTP Fingerprinting ──────────────────────────────────────────────────
    fingerprints = data_store.get("fingerprints", [])
    lines.append("## 🌐 HTTP Fingerprinting")
    lines.append("")
    if fingerprints:
        for fp in fingerprints:
            if isinstance(fp, dict):
                lines.append(f"- **{fp.get('url', 'Unknown')}** (HTTP {fp.get('status_code', '?')})")
                techs = fp.get('technologies', [])
                if techs:
                    lines.append(f"  - Technologies: {', '.join(techs)}")
                if fp.get('server'):
                    lines.append(f"  - Server: {fp['server']}")
    else:
        lines.append("*No fingerprint data available.*")
    lines.append("")

    # ── Security Headers ─────────────────────────────────────────────────────
    security_headers = data_store.get("security_headers", [])
    lines.append("## 🛡️ Security Headers")
    lines.append("")
    if security_headers:
        for sh in security_headers:
            if isinstance(sh, dict):
                lines.append(f"- **{sh.get('url', 'Unknown')}**: Score {sh.get('compliance_score', 'N/A')}/100")
    else:
        lines.append("*No security header data available.*")
    lines.append("")

    # ── TLS Inspection ──────────────────────────────────────────────────────
    tls_results = data_store.get("tls_results", [])
    lines.append("## 🔒 TLS/SSL Inspection")
    lines.append("")
    if tls_results:
        for tls in tls_results:
            if isinstance(tls, dict):
                status = "❌ Expired" if tls.get('is_expired') else "✅ Valid"
                lines.append(f"- **{tls.get('host', 'Unknown')}:{tls.get('port', 443)}**")
                lines.append(f"  - TLS: {tls.get('tls_version', 'Unknown')}")
                lines.append(f"  - Status: {status} ({tls.get('days_remaining', 0)} days)")
                lines.append(f"  - Issuer: {tls.get('certificate_issuer', 'N/A')}")
    else:
        lines.append("*No TLS data available.*")
    lines.append("")

    # ── CSP Analysis ─────────────────────────────────────────────────────────
    csp_analysis = data_store.get("csp_analysis", [])
    lines.append("## 📝 Content Security Policy")
    lines.append("")
    if csp_analysis:
        for csp in csp_analysis:
            if isinstance(csp, dict):
                lines.append(f"- **{csp.get('url', 'Unknown')}**: Score {csp.get('score', 'N/A')}/100")
                for weakness in csp.get('weaknesses', []):
                    lines.append(f"  - ⚠️ {weakness}")
    else:
        lines.append("*No CSP data available.*")
    lines.append("")

    # ── JS Secrets ───────────────────────────────────────────────────────────
    js_secrets = data_store.get("js_secrets", [])
    lines.append("## 🔑 JavaScript Secrets")
    lines.append("")
    total_secrets = sum(s.get('total_found', 0) for s in js_secrets) if js_secrets else 0
    if total_secrets > 0:
        lines.append(f"**Total secrets found:** {total_secrets}")
        lines.append("")
        for secret in js_secrets:
            if isinstance(secret, dict):
                for finding in secret.get('findings', []):
                    if isinstance(finding, dict):
                        lines.append(f"- **{finding.get('type', 'Unknown')}** ({finding.get('severity', 'info')})")
                        lines.append(f"  - Source: {finding.get('source_url', 'N/A')}")
    else:
        lines.append("*No secrets detected.*")
    lines.append("")

    # ── Interesting Files ────────────────────────────────────────────────────
    interesting_files = data_store.get("interesting_files", [])
    lines.append("## 📁 Interesting Files")
    lines.append("")
    total_files = sum(f.get('total_found', 0) for f in interesting_files) if interesting_files else 0
    if total_files > 0:
        lines.append(f"**Total files found:** {total_files}")
        lines.append("")
        for result in interesting_files:
            if isinstance(result, dict):
                for file_entry in result.get('files', []):
                    if isinstance(file_entry, dict):
                        lines.append(f"- [{file_entry.get('status_code', '?')}] {file_entry.get('url', '')}")
    else:
        lines.append("*No interesting files found.*")
    lines.append("")

    # ── Risk Score ──────────────────────────────────────────────────────────
    risk_score = data_store.get("risk_score", [])
    lines.append("## 🎯 Risk Assessment")
    lines.append("")
    if risk_score:
        for risk in risk_score:
            if isinstance(risk, dict):
                lines.append(f"**Overall Score:** {risk.get('overall_score', 'N/A')}/100")
                lines.append(f"**Risk Level:** {risk.get('risk_level', 'Unknown')}")
                lines.append("")
                for cat, score in risk.get('category_scores', {}).items():
                    lines.append(f"- **{cat}**: {score}/100")
    else:
        lines.append("*No risk assessment available.*")
    lines.append("")

    # ── Footer ───────────────────────────────────────────────────────────────
    lines.append("---")
    lines.append(
        "*Generated by [ReconForgeX](https://github.com/NASHEDIxCODER/reconforgex) "
        "— Production-Grade Asynchronous Python Reconnaissance Framework*"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    log.debug("Markdown report written to %s", output_path)
