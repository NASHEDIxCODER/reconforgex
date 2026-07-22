"""
Markdown report builder.

Generates a comprehensive ``report.md`` with formatted sections for
every stage of the reconnaissance pipeline.
"""

from pathlib import Path
from typing import Any, Dict, List

from recon.logger import get_logger
from recon.modules.probe import LiveHost
from recon.pipeline.manager import ScanStatistics

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
    stats: ScanStatistics,
    output_path: Path,
) -> None:
    """Generate a Markdown report from the pipeline data store.

    Parameters
    ----------
    data_store:
        Shared pipeline data store containing scan results.
    stats:
        Aggregated scan statistics.
    output_path:
        Destination file path for the Markdown report.
    """
    subdomains: List[str] = data_store.get("subdomains", [])
    live_hosts: List[LiveHost] = data_store.get("live_hosts", [])
    technologies: List[str] = data_store.get("technologies", [])
    port_scan_results: List[str] = data_store.get("port_scan_results", [])
    nuclei_findings: List[str] = data_store.get("nuclei_findings", [])

    lines: List[str] = []

    # ── Header ───────────────────────────────────────────────────────────────
    lines.append("# Reconnaissance Report")
    lines.append("")
    lines.append(f"**Domain:** `{data_store.get('domain', 'Unknown')}`")
    lines.append(f"**Generated:** `{stats.start_time}`")
    lines.append(f"**Duration:** {_format_duration(stats.duration_seconds)}")
    lines.append("")

    # ── Summary ──────────────────────────────────────────────────────────────
    lines.append("## 📊 Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|------:|")
    lines.append(f"| Subdomains Discovered | {len(subdomains)} |")
    lines.append(f"| Live Hosts | {len(live_hosts)} |")
    lines.append(f"| Screenshots Taken | {stats.screenshots_taken} |")
    lines.append(f"| Ports Scanned | {stats.ports_scanned} |")
    lines.append(f"| Nuclei Findings | {stats.nuclei_findings} |")
    lines.append("")

    # ── Execution Statistics ─────────────────────────────────────────────────
    lines.append("## ⏱️ Execution Statistics")
    lines.append("")
    lines.append("| Stage | Status | Duration |")
    lines.append("|-------|--------|---------:|")
    for stage in stats.stage_results:
        status_icon = {
            "COMPLETED": "✅",
            "SKIPPED": "⏭️",
            "FAILED": "❌",
            "PENDING": "⏳",
            "RUNNING": "🔄",
        }.get(stage.status.name, "❓")
        lines.append(
            f"| {stage.stage_name} | {status_icon} {stage.status.name} | "
            f"{_format_duration(stage.duration_seconds)} |"
        )
    lines.append("")

    # ── Subdomains ───────────────────────────────────────────────────────────
    lines.append("## 🌐 Subdomains")
    lines.append("")
    if subdomains:
        lines.append(f"**Total:** {len(subdomains)}")
        lines.append("")
        lines.append("```")
        for sd in subdomains:
            lines.append(sd)
        lines.append("```")
    else:
        lines.append("*No subdomains discovered.*")
    lines.append("")

    # ── Live Hosts ───────────────────────────────────────────────────────────
    lines.append("## 🟢 Live Hosts")
    lines.append("")
    if live_hosts:
        lines.append("| URL | Status | Title | Technologies |")
        lines.append("|-----|-------:|-------|--------------|")
        for host in live_hosts:
            tech_str = ", ".join(host.technologies) if host.technologies else "-"
            # Escape pipe characters in title
            title = host.title.replace("|", "\\|")
            lines.append(
                f"| {host.url} | {host.status_code} | {title} | {tech_str} |"
            )
    else:
        lines.append("*No live hosts found.*")
    lines.append("")

    # ── Technologies ─────────────────────────────────────────────────────────
    lines.append("## 🔧 Technology Detection")
    lines.append("")
    if technologies:
        for tech in technologies:
            lines.append(f"- {tech}")
    else:
        lines.append("*No technologies detected.*")
    lines.append("")

    # ── Port Scan ────────────────────────────────────────────────────────────
    lines.append("## 🔌 Port Scan (Nmap)")
    lines.append("")
    if port_scan_results:
        lines.append("```")
        lines.extend(port_scan_results)
        lines.append("```")
    else:
        lines.append("*Port scan not performed or no results.*")
    lines.append("")

    # ── Nuclei Findings ──────────────────────────────────────────────────────
    lines.append("## ⚠️ Vulnerability Scan (Nuclei)")
    lines.append("")
    if nuclei_findings:
        lines.append(f"**Total findings:** {len(nuclei_findings)}")
        lines.append("")
        lines.append("```json")
        for finding in nuclei_findings:
            lines.append(finding)
        lines.append("```")
    else:
        lines.append("*No vulnerabilities found or scan not performed.*")
    lines.append("")

    # ── Footer ───────────────────────────────────────────────────────────────
    lines.append("---")
    lines.append(
        "*Generated by [Recon](https://github.com/NASHEDIxCODER/recon) "
        "— Advanced Reconnaissance Framework*"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    log.debug("Markdown report written to %s", output_path)