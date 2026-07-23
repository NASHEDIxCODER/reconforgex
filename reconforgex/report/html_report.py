"""
HTML Report Builder.

Generates standalone HTML reports with embedded CSS and JavaScript
for interactive charts, summary cards, and execution timeline.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

from reconforgex.logger import get_logger
from reconforgex.pipeline.statistics import PipelineStatistics

log = get_logger()


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconForgeX Report — {domain}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #1c2128;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #6e7681;
    --accent-blue: #58a6ff;
    --accent-green: #3fb950;
    --accent-yellow: #d29922;
    --accent-red: #f85149;
    --accent-purple: #bc8cff;
    --accent-orange: #f0883e;
    --accent-cyan: #39d2c0;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
  }}

  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}

  /* Header */
  .header {{
    text-align: center;
    padding: 3rem 0 2rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
  }}
  .header h1 {{
    font-size: 2.5rem;
    font-weight: 700;
    background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0.5rem;
  }}
  .header .subtitle {{
    color: var(--text-secondary);
    font-size: 1.1rem;
  }}
  .header .meta {{
    display: flex;
    justify-content: center;
    gap: 2rem;
    margin-top: 1rem;
    color: var(--text-muted);
    font-size: 0.9rem;
  }}

  /* Summary Cards */
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .summary-card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    text-align: center;
    transition: transform 0.2s, box-shadow 0.2s;
  }}
  .summary-card:hover {{
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(0,0,0,0.3);
  }}
  .summary-card .value {{
    font-size: 2.2rem;
    font-weight: 700;
    margin-bottom: 0.25rem;
  }}
  .summary-card .label {{
    color: var(--text-secondary);
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .summary-card .icon {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
  .card-blue .value {{ color: var(--accent-blue); }}
  .card-green .value {{ color: var(--accent-green); }}
  .card-yellow .value {{ color: var(--accent-yellow); }}
  .card-red .value {{ color: var(--accent-red); }}
  .card-purple .value {{ color: var(--accent-purple); }}
  .card-orange .value {{ color: var(--accent-orange); }}
  .card-cyan .value {{ color: var(--accent-cyan); }}

  /* Section */
  .section {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }}
  .section h2 {{
    font-size: 1.3rem;
    color: var(--text-primary);
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
  }}
  .section h3 {{
    font-size: 1.1rem;
    color: var(--accent-orange);
    margin: 1rem 0 0.5rem;
  }}

  /* Charts */
  .chart-container {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
  }}
  .chart-box {{
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
  }}
  .chart-box.full-width {{ grid-column: 1 / -1; }}
  .chart-box canvas {{ width: 100% !important; height: 300px !important; }}

  /* Tables */
  .data-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
  }}
  .data-table th {{
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.8rem;
    letter-spacing: 0.05em;
    padding: 0.75rem;
    text-align: left;
    border-bottom: 2px solid var(--border);
  }}
  .data-table td {{
    padding: 0.75rem;
    border-bottom: 1px solid var(--border);
  }}
  .data-table tr:hover {{ background: var(--bg-tertiary); }}

  /* Status Badges */
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 2rem;
    font-size: 0.75rem;
    font-weight: 600;
  }}
  .badge-green {{ background: #1b4727; color: var(--accent-green); }}
  .badge-red {{ background: #491c1c; color: var(--accent-red); }}
  .badge-yellow {{ background: #4d3a1a; color: var(--accent-yellow); }}
  .badge-blue {{ background: #0c2d6b; color: var(--accent-blue); }}
  .badge-gray {{ background: var(--bg-tertiary); color: var(--text-muted); }}

  /* Timeline */
  .timeline {{
    position: relative;
    padding-left: 2rem;
    margin: 1rem 0;
  }}
  .timeline::before {{
    content: '';
    position: absolute;
    left: 0.5rem;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--border);
  }}
  .timeline-item {{
    position: relative;
    margin-bottom: 1rem;
    padding: 0.75rem;
    background: var(--bg-tertiary);
    border-radius: 8px;
    border: 1px solid var(--border);
  }}
  .timeline-item::before {{
    content: '';
    position: absolute;
    left: -1.65rem;
    top: 1rem;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid var(--accent-blue);
    background: var(--bg-primary);
  }}
  .timeline-item .stage-name {{ font-weight: 600; color: var(--accent-blue); }}
  .timeline-item .stage-duration {{ color: var(--text-muted); font-size: 0.85rem; }}
  .timeline-item .stage-status {{ float: right; }}

  /* Risk Score */
  .risk-gauge {{
    text-align: center;
    padding: 2rem;
  }}
  .risk-gauge .score {{
    font-size: 4rem;
    font-weight: 700;
  }}
  .risk-gauge .level {{
    font-size: 1.5rem;
    margin-top: 0.5rem;
  }}
  .risk-gauge .progress-ring {{
    width: 200px;
    height: 200px;
    margin: 1rem auto;
    position: relative;
  }}

  /* Footer */
  .footer {{
    text-align: center;
    padding: 2rem 0;
    color: var(--text-muted);
    font-size: 0.85rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
  }}
  .footer a {{ color: var(--accent-blue); text-decoration: none; }}

  /* Responsive */
  @media (max-width: 768px) {{
    .chart-container {{ grid-template-columns: 1fr; }}
    .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .header .meta {{ flex-direction: column; gap: 0.5rem; }}
  }}

  /* Findings List */
  .finding {{
    padding: 0.75rem;
    margin: 0.5rem 0;
    border-radius: 6px;
    border-left: 4px solid var(--border);
  }}
  .finding.critical {{ border-left-color: var(--accent-red); background: rgba(248,81,73,0.1); }}
  .finding.high {{ border-left-color: var(--accent-orange); background: rgba(240,136,62,0.1); }}
  .finding.medium {{ border-left-color: var(--accent-yellow); background: rgba(210,153,34,0.1); }}
  .finding.low {{ border-left-color: var(--accent-blue); background: rgba(88,166,255,0.1); }}
  .finding .finding-header {{
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.25rem;
  }}
  .finding .finding-title {{ font-weight: 600; }}
  .finding .finding-desc {{ color: var(--text-secondary); font-size: 0.85rem; }}
  .finding .finding-rec {{ color: var(--accent-green); font-size: 0.85rem; margin-top: 0.25rem; }}
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <h1>🔍 ReconForgeX Report</h1>
    <div class="subtitle">Security Reconnaissance Analysis</div>
    <div class="meta">
      <span>🎯 Target: <strong>{domain}</strong></span>
      <span>⏱️ Duration: <strong>{duration}</strong></span>
      <span>📅 Generated: <strong>{generated_at}</strong></span>
      <span>⚙️ Workers: <strong>{worker_count}</strong></span>
    </div>
  </div>

  <!-- Summary Cards -->
  <div class="summary-grid">
    <div class="summary-card card-blue">
      <div class="icon">🌐</div>
      <div class="value">{domains_processed}</div>
      <div class="label">Domains Processed</div>
    </div>
    <div class="summary-card card-green">
      <div class="icon">🟢</div>
      <div class="value">{live_hosts}</div>
      <div class="label">Live Hosts</div>
    </div>
    <div class="summary-card card-purple">
      <div class="icon">🔧</div>
      <div class="value">{technologies}</div>
      <div class="label">Technologies Found</div>
    </div>
    <div class="summary-card card-orange">
      <div class="icon">⚠️</div>
      <div class="value">{findings_count}</div>
      <div class="label">Security Findings</div>
    </div>
    <div class="summary-card card-red">
      <div class="icon">❌</div>
      <div class="value">{errors}</div>
      <div class="label">Errors</div>
    </div>
    <div class="summary-card card-cyan">
      <div class="icon">🚀</div>
      <div class="value">{requests_per_second}</div>
      <div class="label">Requests/s</div>
    </div>
    <div class="summary-card card-yellow">
      <div class="icon">💾</div>
      <div class="value">{memory_usage} MB</div>
      <div class="label">Peak Memory</div>
    </div>
    <div class="summary-card card-blue">
      <div class="icon">⚡</div>
      <div class="value">{avg_response_time} ms</div>
      <div class="label">Avg Response</div>
    </div>
  </div>

  <!-- Charts Section -->
  <div class="section">
    <h2>📊 Performance Analytics</h2>
    <div class="chart-container">
      <div class="chart-box">
        <h3>Response Time Distribution</h3>
        <canvas id="responseTimeChart"></canvas>
      </div>
      <div class="chart-box">
        <h3>Status Code Distribution</h3>
        <canvas id="statusCodeChart"></canvas>
      </div>
      <div class="chart-box full-width">
        <h3>Execution Timeline</h3>
        <canvas id="timelineChart"></canvas>
      </div>
    </div>
  </div>

  <!-- Execution Timeline -->
  <div class="section">
    <h2>⏱️ Execution Timeline</h2>
    <div class="timeline">
      {timeline_html}
    </div>
  </div>

  <!-- Risk Score -->
  <div class="section">
    <h2>🎯 Risk Assessment</h2>
    {risk_score_html}
  </div>

  <!-- Technology Distribution -->
  <div class="section">
    <h2>🔧 Technology Distribution</h2>
    <div class="chart-container">
      <div class="chart-box">
        <canvas id="techChart"></canvas>
      </div>
      <div class="chart-box">
        <h3>TLS Version Distribution</h3>
        <canvas id="tlsChart"></canvas>
      </div>
    </div>
  </div>

  <!-- Security Headers Matrix -->
  <div class="section">
    <h2>🛡️ Security Header Compliance</h2>
    {security_headers_html}
  </div>

  <!-- Pipeline Statistics -->
  <div class="section">
    <h2>📈 Pipeline Statistics</h2>
    <div class="chart-container">
      <div class="chart-box full-width">
        <h3>Performance Metrics</h3>
        <canvas id="pipelineChart"></canvas>
      </div>
    </div>
    <table class="data-table">
      <thead>
        <tr>
          <th>Metric</th>
          <th>Value</th>
          <th>Metric</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Execution Time</td><td>{execution_time}s</td>
          <td>Avg Response Time</td><td>{avg_response_time}s</td>
        </tr>
        <tr>
          <td>Median Response</td><td>{median_response_time}s</td>
          <td>P95 Response</td><td>{p95_response_time}s</td>
        </tr>
        <tr>
          <td>P99 Response</td><td>{p99_response_time}s</td>
          <td>Requests/sec</td><td>{requests_per_second}</td>
        </tr>
        <tr>
          <td>Total Requests</td><td>{total_requests}</td>
          <td>Retries</td><td>{retries}</td>
        </tr>
        <tr>
          <td>Peak Memory</td><td>{memory_usage} MB</td>
          <td>CPU Usage</td><td>{cpu_percent}%</td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- Findings -->
  <div class="section">
    <h2>🔍 Detailed Findings</h2>
    {findings_html}
  </div>

  <div class="footer">
    Generated by <a href="https://github.com/NASHEDIxCODER/reconforgex">ReconForgeX</a> v{version}
    &mdash; Production-Grade Asynchronous Python Reconnaissance Framework
  </div>
</div>

<script>
// Response Time Distribution Chart
new Chart(document.getElementById('responseTimeChart'), {{
  type: 'bar',
  data: {{
    labels: ['Avg', 'Median', 'P95', 'P99'],
    datasets: [{{
      label: 'Response Time (s)',
      data: [{avg_resp}, {median_resp}, {p95_resp}, {p99_resp}],
      backgroundColor: ['rgba(88,166,255,0.7)', 'rgba(63,185,80,0.7)', 'rgba(210,153,34,0.7)', 'rgba(248,81,73,0.7)'],
      borderColor: ['#58a6ff', '#3fb950', '#d29922', '#f85149'],
      borderWidth: 2,
      borderRadius: 6,
    }}
]  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      y: {{ beginAtZero: true, grid: {{ color: 'rgba(255,255,255,0.05)' }} }},
      x: {{ grid: {{ display: false }} }}
    }}
  }}
}});

// Status Code Distribution Chart
new Chart(document.getElementById('statusCodeChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['2xx Success', '3xx Redirect', '4xx Client Error', '5xx Server Error', 'Errors'],
    datasets: [{{
      data: [{success_count}, {redirect_count}, {error_4xx}, {error_5xx}, {error_count}],
      backgroundColor: ['rgba(63,185,80,0.8)', 'rgba(88,166,255,0.8)', 'rgba(210,153,34,0.8)', 'rgba(240,136,62,0.8)', 'rgba(248,81,73,0.8)'],
      borderWidth: 0,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ position: 'bottom', labels: {{ color: '#8b949e', padding: 12 }} }}
    }}
  }}
}});

// Technology Distribution Chart
new Chart(document.getElementById('techChart'), {{
  type: 'doughnut',
  data: {{
    labels: {tech_labels},
    datasets: [{{
      data: {tech_counts},
      backgroundColor: {tech_colors},
      borderWidth: 0,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ position: 'bottom', labels: {{ color: '#8b949e', padding: 12, font: {{ size: 10 }} }} }}
    }}
  }}
}});

// TLS Version Chart
new Chart(document.getElementById('tlsChart'), {{
  type: 'bar',
  data: {{
    labels: {tls_labels},
    datasets: [{{
      label: 'Count',
      data: {tls_counts},
      backgroundColor: ['rgba(88,166,255,0.7)', 'rgba(63,185,80,0.7)', 'rgba(210,153,34,0.7)', 'rgba(188,140,255,0.7)'],
      borderColor: ['#58a6ff', '#3fb950', '#d29922', '#bc8cff'],
      borderWidth: 2,
      borderRadius: 6,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      y: {{ beginAtZero: true, grid: {{ color: 'rgba(255,255,255,0.05)' }} }},
      x: {{ grid: {{ display: false }} }}
    }}
  }}
}});

// Execution Timeline Chart
new Chart(document.getElementById('timelineChart'), {{
  type: 'bar',
  data: {{
    labels: {stage_labels},
    datasets: [{{
      label: 'Duration (s)',
      data: {stage_durations},
      backgroundColor: {stage_colors},
      borderColor: 'transparent',
      borderRadius: 4,
    }}]
  }},
  options: {{
    indexAxis: 'y',
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ beginAtZero: true, grid: {{ color: 'rgba(255,255,255,0.05)' }} }},
      y: {{ grid: {{ display: false }} }}
    }}
  }}
}});

// Pipeline Statistics Chart
new Chart(document.getElementById('pipelineChart'), {{
  type: 'radar',
  data: {{
    labels: ['Throughput', 'Success Rate', 'Worker Efficiency', 'Memory Efficiency', 'Latency'],
    datasets: [{{
      label: 'Performance',
      data: [{throughput_norm}, {success_rate}, {worker_efficiency}, {memory_efficiency}, {latency_score}],
      backgroundColor: 'rgba(88,166,255,0.2)',
      borderColor: '#58a6ff',
      borderWidth: 2,
      pointBackgroundColor: '#58a6ff',
      pointBorderColor: '#fff',
      pointHoverBackgroundColor: '#fff',
      pointHoverBorderColor: '#58a6ff',
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      r: {{
        beginAtZero: true,
        max: 100,
        grid: {{ color: 'rgba(255,255,255,0.05)' }},
        angleLines: {{ color: 'rgba(255,255,255,0.05)' }},
        pointLabels: {{ color: '#8b949e', font: {{ size: 11 }} }}
      }}
    }}
  }}
}});
</script>
</body>
</html>
"""


def _format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"


def _status_badge(status_name: str) -> str:
    badges = {
        "COMPLETED": "badge badge-green",
        "SKIPPED": "badge badge-yellow",
        "FAILED": "badge badge-red",
        "PENDING": "badge badge-gray",
        "RUNNING": "badge badge-blue",
    }
    cls = badges.get(status_name, "badge badge-gray")
    return f'<span class="{cls}">{status_name}</span>'


def _generate_risk_score_html(data: Dict[str, Any]) -> str:
    """Generate risk score display HTML."""
    risk = data.get("risk_score", {})
    if isinstance(risk, dict):
        score = risk.get("overall_score", 0)
        level = risk.get("risk_level", "Unknown")
        factors = risk.get("factors", [])
    else:
        score = 0
        level = "N/A"
        factors = []

    score_color = "var(--accent-green)" if score >= 70 else "var(--accent-yellow)" if score >= 50 else "var(--accent-red)"
    level_icon = "🟢" if score >= 90 else "🔵" if score >= 70 else "🟡" if score >= 50 else "🟠" if score >= 30 else "🔴"

    html = f"""
    <div class="risk-gauge">
        <div class="score" style="color: {score_color};">{score:.1f}</div>
        <div class="level">{level_icon} {level}</div>
    </div>
    """

    if factors:
        html += "<h3>Risk Factors</h3>"
        for factor in factors[:10]:  # Top 10 factors
            severity = factor.get("severity", "low")
            html += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <span class="finding-title">{factor.get('name', 'Unknown')}</span>
                    <span class="badge badge-{'red' if severity == 'critical' else 'yellow' if severity == 'high' else 'blue'}">{severity}</span>
                </div>
                <div class="finding-desc">{factor.get('description', '')}</div>
                <div class="finding-rec">{factor.get('recommendation', '')}</div>
            </div>
            """

    return html


def _generate_security_headers_html(data: Dict[str, Any]) -> str:
    """Generate security headers matrix HTML."""
    # security_headers is a list of URL results, each with a "checks" array
    sec_headers = data.get("security_headers", [])

    # Flatten all checks across all URLs
    all_checks: List[Dict[str, Any]] = []
    for entry in sec_headers:
        if isinstance(entry, dict):
            checks = entry.get("checks", [])
            if isinstance(checks, list):
                for check in checks:
                    all_checks.append(check)
        elif hasattr(entry, 'checks'):
            for check in entry.checks:
                all_checks.append(check.__dict__ if hasattr(check, '__dict__') else check)

    if not all_checks:
        return "<p><em>No security header data available.</em></p>"

    html = '<table class="data-table"><thead><tr><th>Header</th><th>Present</th><th>Value</th><th>Compliant</th><th>Severity</th></tr></thead><tbody>'
    for h in all_checks:
        if isinstance(h, dict):
            present = "✅" if h.get("present") else "❌"
            compliant = "✅" if h.get("compliant") else "❌"
            severity = h.get("severity", "info")
            header_name = h.get("header", "")
            header_value = h.get("value", "-")
        else:
            present = "✅" if getattr(h, 'present', False) else "❌"
            compliant = "✅" if getattr(h, 'compliant', False) else "❌"
            severity = getattr(h, 'severity', 'info')
            header_name = getattr(h, 'header', '')
            header_value = getattr(h, 'value', '-')

        badge_class = 'red' if severity in ('critical','high') else 'yellow' if severity == 'medium' else 'blue'
        html += f"<tr><td><code>{header_name}</code></td><td>{present}</td><td>{header_value}</td><td>{compliant}</td><td><span class='badge badge-{badge_class}'>{severity}</span></td></tr>"
    html += "</tbody></table>"
    return html


def _generate_findings_html(data: Dict[str, Any]) -> str:
    """Generate detailed findings HTML."""
    findings = data.get("findings", [])
    if not findings:
        return "<p><em>No security findings.</em></p>"

    html = ""
    for finding in findings:
        severity = finding.get("severity", "low")
        html += f"""
        <div class="finding {severity}">
            <div class="finding-header">
                <span class="finding-title">{finding.get('title', finding.get('name', 'Finding'))}</span>
                <span class="badge badge-{'red' if severity == 'critical' else 'yellow' if severity in ('high','medium') else 'blue'}">{severity}</span>
            </div>
            <div class="finding-desc">{finding.get('description', finding.get('message', ''))}</div>
            <div class="finding-rec">{finding.get('recommendation', finding.get('solution', ''))}</div>
        </div>
        """
    return html


def _generate_timeline_html(data: Dict[str, Any], stats: "PipelineStatistics") -> str:
    """Generate execution timeline HTML."""
    stages = data.get("stages", [])
    if not stages:
        return "<p><em>No stage data available.</em></p>"

    html = ""
    for stage in stages:
        name = stage.get("name", stage.get("stage_name", "Unknown"))
        status = stage.get("status", "PENDING")
        duration = stage.get("duration_seconds", stage.get("duration", 0))
        html += f"""
        <div class="timeline-item">
            <span class="stage-name">{name}</span>
            <span class="stage-status">{_status_badge(status)}</span>
            <div class="stage-duration">⏱️ {_format_duration(duration)}</div>
        </div>
        """
    return html


def build_html_report(
    data_store: Dict[str, Any],
    stats: PipelineStatistics,
    output_path: Path,
) -> None:
    """Generate a standalone HTML report with charts and analytics.

    Parameters
    ----------
    data_store:
        Shared pipeline data store containing scan results.
    stats:
        Aggregated scan statistics.
    output_path:
        Destination file path for the HTML report.
    """
    stats_dict = stats.to_dict() if hasattr(stats, "to_dict") else {}

    # Extract data
    domain = data_store.get("domain", "Unknown")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Timeline
    timeline_html = _generate_timeline_html(data_store, stats)

    # Risk score
    risk_score_html = _generate_risk_score_html(data_store)

    # Security headers
    security_headers_html = _generate_security_headers_html(data_store)

    # Findings
    findings_html = _generate_findings_html(data_store)

    # Tech distribution
    technologies = data_store.get("technologies", [])
    if isinstance(technologies, list) and len(technologies) > 0:
        from collections import Counter
        tech_counter = Counter(technologies)
        tech_labels = json.dumps([t[:20] for t in tech_counter.keys()])
        tech_counts = json.dumps(list(tech_counter.values()))
        tech_colors = json.dumps([
            f"hsla({(i * 37) % 360}, 70%, 60%, 0.8)"
            for i in range(len(tech_counter))
        ])
    else:
        tech_labels = "[]"
        tech_counts = "[]"
        tech_colors = "[]"

    # TLS versions
    tls_versions = stats_dict.get("tls_versions", {})
    if tls_versions:
        tls_labels = json.dumps(list(tls_versions.keys()))
        tls_counts = json.dumps(list(tls_versions.values()))
    else:
        tls_labels = "['Unknown']"
        tls_counts = "[0]"

    # Stage data for timeline chart
    stages = data_store.get("stages", [])
    if not stages:
        stage_labels = "[]"
        stage_durations = "[]"
        stage_colors = "[]"
    else:
        stage_labels = json.dumps([s.get("name", s.get("stage_name", f"Stage {i}")) for i, s in enumerate(stages)])
        stage_durations = json.dumps([s.get("duration_seconds", s.get("duration", 0)) for s in stages])
        stage_colors = json.dumps([
            f"hsla({(i * 40) % 360}, 70%, 60%, 0.7)"
            for i in range(len(stages))
        ])

    # Normalized metrics for radar chart
    throughput_norm = min(100, (stats_dict.get("requests_per_second", 0) / 50) * 100)
    success_rate_val = stats_dict.get("total_requests", 1)
    error_count = stats_dict.get("errors", 0)
    success_rate = max(0, 100 - (error_count / max(success_rate_val, 1) * 100))
    worker_efficiency_val = min(100, (stats_dict.get("requests_per_second", 0) / 10) * 100)
    memory_usage = stats_dict.get("memory_usage_mb", 0)
    memory_efficiency_val = max(0, 100 - (memory_usage / 500) * 100)
    latency_score_val = max(0, 100 - (stats_dict.get("avg_response_time", 0) * 100))

    html = HTML_TEMPLATE.format(
        domain=domain,
        duration=_format_duration(stats_dict.get("execution_time", 0)),
        generated_at=generated_at,
        worker_count=stats_dict.get("worker_count", data_store.get("worker_count", 50)),
        domains_processed=stats_dict.get("domains_processed", data_store.get("total_domains", 0)),
        live_hosts=stats_dict.get("live_hosts", data_store.get("live_host_count", 0)),
        technologies=stats_dict.get("technologies", len(technologies)),
        findings_count=data_store.get("findings_count", 0),
        errors=stats_dict.get("errors", 0),
        requests_per_second=round(stats_dict.get("requests_per_second", 0), 1),
        memory_usage=round(stats_dict.get("memory_usage_mb", 0), 1),
        avg_response_time=round(stats_dict.get("avg_response_time", 0) * 1000, 1),
        execution_time=round(stats_dict.get("execution_time", 0), 2),
        avg_resp=round(stats_dict.get("avg_response_time", 0), 3),
        median_resp=round(stats_dict.get("median_response_time", 0), 3),
        p95_resp=round(stats_dict.get("p95_response_time", 0), 3),
        p99_resp=round(stats_dict.get("p99_response_time", 0), 3),
        success_count=stats_dict.get("total_requests", 0) - stats_dict.get("errors", 0),
        redirect_count=stats_dict.get("redirects", 0),
        error_4xx=stats_dict.get("client_errors", 0),
        error_5xx=stats_dict.get("server_errors", 0),
        error_count=stats_dict.get("errors", 0),
        median_response_time=round(stats_dict.get("median_response_time", 0), 3),
        p95_response_time=round(stats_dict.get("p95_response_time", 0), 3),
        p99_response_time=round(stats_dict.get("p99_response_time", 0), 3),
        total_requests=stats_dict.get("total_requests", 0),
        retries=stats_dict.get("retries", 0),
        cpu_percent=round(stats_dict.get("cpu_percent", 0), 1),
        timeline_html=timeline_html,
        risk_score_html=risk_score_html,
        security_headers_html=security_headers_html,
        findings_html=findings_html,
        tech_labels=tech_labels,
        tech_counts=tech_counts,
        tech_colors=tech_colors,
        tls_labels=tls_labels,
        tls_counts=tls_counts,
        stage_labels=stage_labels,
        stage_durations=stage_durations,
        stage_colors=stage_colors,
        throughput_norm=round(throughput_norm, 1),
        success_rate=round(success_rate, 1),
        worker_efficiency=round(worker_efficiency_val, 1),
        memory_efficiency=round(memory_efficiency_val, 1),
        latency_score=round(latency_score_val, 1),
        version="2.0.0",
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    log.debug("HTML report written to %s", output_path)