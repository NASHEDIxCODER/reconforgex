"""
JSON report builder.

Serialises all scan data and statistics into a single ``report.json``
file.
"""

import json
from pathlib import Path
from typing import Any, Dict

from reconforgex.logger import get_logger
from reconforgex.pipeline.statistics import PipelineStatistics

log = get_logger()


def build_json_report(
    data_store: Dict[str, Any],
    stats: PipelineStatistics,
    output_path: Path,
) -> None:
    """Generate a JSON report from the pipeline data store.

    Parameters
    ----------
    data_store:
        Shared pipeline data store containing scan results.
    stats:
        Aggregated pipeline statistics.
    output_path:
        Destination file path for the JSON report.
    """
    stats_dict = stats.to_dict() if hasattr(stats, "to_dict") else {}

    # Extract module results
    fingerprints = data_store.get("fingerprints", [])
    header_analysis = data_store.get("header_analysis", [])
    security_headers = data_store.get("security_headers", [])
    tls_results = data_store.get("tls_results", [])
    csp_analysis = data_store.get("csp_analysis", [])
    robots_analysis = data_store.get("robots_analysis", [])
    sitemap_analysis = data_store.get("sitemap_analysis", [])
    js_files = data_store.get("js_files", [])
    js_endpoints = data_store.get("js_endpoints", [])
    js_secrets = data_store.get("js_secrets", [])
    interesting_files = data_store.get("interesting_files", [])
    response_analysis = data_store.get("response_analysis", [])
    risk_score = data_store.get("risk_score", [])

    report: Dict[str, Any] = {
        "summary": {
            "domain": data_store.get("domain", ""),
            "generated_at": data_store.get("generated_at", ""),
            "worker_count": data_store.get("worker_count", 50),
            "findings_count": data_store.get("findings_count", 0),
            "live_host_count": data_store.get("live_host_count", 0),
            "technologies_found": stats_dict.get("technologies", 0),
            "headers_analyzed": stats_dict.get("headers_analyzed", 0),
            "tls_certificates": stats_dict.get("certificates", 0),
            "redirects": stats_dict.get("redirects", 0),
            "errors": stats_dict.get("errors", 0),
        },
        "statistics": stats_dict,
        "modules": {
            "http_fingerprinting": fingerprints,
            "header_analyzer": header_analysis,
            "security_header_scanner": security_headers,
            "tls_inspector": tls_results,
            "csp_analyzer": csp_analysis,
            "robots_parser": robots_analysis,
            "sitemap_parser": sitemap_analysis,
            "js_collector": js_files,
            "js_endpoint_extractor": js_endpoints,
            "js_secret_detector": js_secrets,
            "interesting_files": interesting_files,
            "http_response_analyzer": response_analysis,
            "risk_scoring": risk_score,
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    log.debug("JSON report written to %s", output_path)
