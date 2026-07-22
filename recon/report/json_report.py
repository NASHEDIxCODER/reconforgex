"""
JSON report builder.

Serialises all scan data and statistics into a single ``report.json``
file.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from recon.logger import get_logger
from recon.modules.probe import LiveHost
from recon.pipeline.manager import ScanStatistics
from recon.utils.files import write_lines

log = get_logger()


def build_json_report(
    data_store: Dict[str, Any],
    stats: ScanStatistics,
    output_path: Path,
) -> None:
    """Generate a JSON report from the pipeline data store.

    Parameters
    ----------
    data_store:
        Shared pipeline data store containing scan results.
    stats:
        Aggregated scan statistics.
    output_path:
        Destination file path for the JSON report.
    """
    subdomains: List[str] = data_store.get("subdomains", [])
    live_hosts: List[LiveHost] = data_store.get("live_hosts", [])
    technologies: List[str] = data_store.get("technologies", [])
    port_scan_results: List[str] = data_store.get("port_scan_results", [])
    nuclei_findings: List[str] = data_store.get("nuclei_findings", [])

    report: Dict[str, Any] = {
        "summary": {
            "domain": data_store.get("domain", ""),
            "subdomains_discovered": len(subdomains),
            "live_hosts_found": len(live_hosts),
            "technologies_detected": len(technologies),
            "ports_scanned": stats.ports_scanned,
            "nuclei_findings": stats.nuclei_findings,
            "screenshots_taken": stats.screenshots_taken,
        },
        "statistics": stats.to_dict(),
        "subdomains": sorted(subdomains),
        "live_hosts": [
            {
                "url": host.url,
                "status_code": host.status_code,
                "title": host.title,
                "technologies": host.technologies,
            }
            for host in live_hosts
        ],
        "technologies": technologies,
        "port_scan": port_scan_results,
        "nuclei_findings": nuclei_findings,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    log.debug("JSON report written to %s", output_path)