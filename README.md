# ReconForgeX

Asynchronous Python reconnaissance framework. Runs 13 analysis modules against a target domain using pure Python — no external tools required.

## Why

Web reconnaissance typically requires installing and orchestrating multiple external tools (subfinder, httpx, nuclei, aquatone, etc.), each with its own output format and failure modes. ReconForgeX replaces that stack with a single `pip install`, a single CLI, and a unified pipeline that handles dependency ordering, concurrent execution, and report generation automatically.

## Features

- **13 built-in modules** — HTTP fingerprinting, header analysis, TLS inspection, CSP analysis, robots.txt/sitemap parsing, JS collection/analysis, endpoint extraction, secret detection, risk scoring
- **Async-first** — Built on `asyncio` and `httpx` for concurrent I/O
- **No external tool dependencies** — Everything runs in pure Python
- **DAG-based pipeline** — Stages execute in dependency order with automatic wave scheduling
- **Configurable concurrency** — 10 to 1000 workers
- **Multiple report formats** — HTML, JSON, Markdown
- **Flexible configuration** — YAML config file + CLI overrides
- **Comprehensive statistics** — Timing percentiles, throughput, resource usage, error rates

## Architecture

```
CLI (argparse) → Config (YAML/CLI) → PipelineManager → Scheduler → Wave 0 → Wave 1 → ... → Reports
                    ↓                       ↓
              ModuleRegistry          Shared HTTP client
                    ↓                       ↓
              13 modules           Connection pooling, rate limiting
```

The pipeline uses a topological sort (Kahn's algorithm) to determine execution order. Independent stages run concurrently; dependent stages wait for their inputs. All modules share a single HTTP client for connection pooling.

### Directory Structure

```
reconforgex/
├── cli.py                  # Argument parsing and dispatch
├── config.py               # YAML/CLI configuration
├── constants.py            # Centralized constants
├── exceptions.py           # Custom exceptions
├── logger.py               # Structured logging
├── __init__.py             # Package exports
├── __main__.py             # python -m entry point
├── modules/                # 13 reconnaissance modules
│   ├── base.py             # Abstract base class
│   ├── csp_analyzer.py
│   ├── header_analyzer.py
│   ├── http_fingerprint.py
│   ├── http_response_analyzer.py
│   ├── interesting_files.py
│   ├── js_collector.py
│   ├── js_endpoint_extractor.py
│   ├── js_secret_detector.py
│   ├── risk_scoring.py
│   ├── robots_parser.py
│   ├── security_header_scanner.py
│   ├── sitemap_parser.py
│   └── tls_inspector.py
├── pipeline/               # Orchestration
│   ├── manager.py          # Pipeline manager
│   ├── scheduler.py        # DAG stage scheduler
│   ├── statistics.py       # Execution statistics
│   └── worker_pool.py      # Worker pool
├── report/                 # Report generators
│   ├── html_report.py
│   ├── json_report.py
│   └── markdown_report.py
└── utils/                  # Shared utilities
    ├── http_client.py      # Async HTTP client
    ├── rate_limiter.py     # Token bucket rate limiter
    └── validators.py       # Domain/URL validation
tests/                      # Test suite (34 tests)
benchmarks/                 # Performance benchmarks
```

## Installation

```bash
pip install reconforgex
```

For development:

```bash
git clone https://github.com/NASHEDIxCODER/reconforgex.git
cd reconforgex
pip install -e ".[dev]"
```

Requires Python 3.11+.

Dependencies: `httpx`, `pyyaml` (installed automatically).

## Quick Start

```bash
# Basic scan
reconforgex -d example.com

# With more workers and verbose output
reconforgex -d example.com --workers 100 --verbose

# Run specific modules only
reconforgex -d example.com --modules header_analyzer tls_inspector

# Skip specific report formats
reconforgex -d example.com --no-json --no-html

# Using a YAML config file
reconforgex my_config.yaml

# List available modules
reconforgex --list-modules

# Run as a module
python -m reconforgex -d example.com
```

## Configuration

CLI flags take precedence over config file values. Example `config.yaml`:

```yaml
worker_count: 100
timeout: 60
retry_count: 3
output_directory: "output"
logging_level: "INFO"
modules:
  - http_fingerprinting
  - header_analyzer
  - security_header_scanner
  - tls_inspector
  - csp_analyzer
  - robots_parser
  - sitemap_parser
  - js_collector
  - js_endpoint_extractor
  - js_secret_detector
  - interesting_files
  - http_response_analyzer
  - risk_scoring
```

### CLI Options

| Flag | Description |
|------|-------------|
| `-d, --domain` | Target domain |
| `-o, --output` | Output directory (default: `output/`) |
| `-w, --workers` | Worker count: 10, 25, 50, 100, 250, 500, 1000 (default: 50) |
| `--modules` | Space-separated module names |
| `--list-modules` | Print module list and exit |
| `--no-html` | Skip HTML report |
| `--no-json` | Skip JSON report |
| `--no-markdown` | Skip Markdown report |
| `--verbose` | Enable debug logging |
| `--version` | Print version and exit |

## Pipeline Overview

The pipeline executes stages in four waves:

1. **Wave 0** — 10 independent modules run concurrently (fingerprinting, headers, TLS, CSP, robots, sitemap, JS collection, interesting files, response analysis)
2. **Wave 1** — JS endpoint extraction and secret detection (depend on JS collection)
3. **Wave 2** — Risk scoring (depends on header, TLS, CSP, and secret results)
4. **Wave 3** — Report generation

## Modules

| Module | What it does |
|--------|-------------|
| `http_fingerprinting` | Identifies web servers, frameworks, and technologies |
| `header_analyzer` | Analyzes HTTP response headers for security issues |
| `security_header_scanner` | Checks OWASP security header compliance |
| `tls_inspector` | Inspects TLS/SSL certificates and protocol versions |
| `csp_analyzer` | Analyzes Content-Security-Policy for weaknesses |
| `robots_parser` | Parses robots.txt for paths and restricted areas |
| `sitemap_parser` | Parses XML sitemaps to discover URLs |
| `js_collector` | Discovers and collects JavaScript files |
| `js_endpoint_extractor` | Extracts API endpoints from JavaScript |
| `js_secret_detector` | Detects secrets, API keys, and tokens in JS |
| `interesting_files` | Discovers interesting files and endpoints |
| `http_response_analyzer` | Analyzes HTTP responses for patterns |
| `risk_scoring` | Calculates security risk scores from findings |

## Reports

Three report formats are generated in the output directory:

- `reports/report.html` — Interactive HTML with charts and summaries
- `reports/report.json` — Structured data for programmatic consumption
- `reports/report.md` — Markdown for version control / CI

Each report includes execution statistics (timing percentiles, throughput, error rates, memory usage) per module.

## Benchmarks

```bash
# Full benchmark suite
python -m benchmarks.bench_basic

# Quick test (fewer iterations)
python -m benchmarks.bench_basic --quick

# CI-friendly JSON output
python -m benchmarks.bench_basic --ci
```

The benchmark suite measures throughput, latency percentiles (P50/P95/P99), resource usage, and error rates across different domain counts (10-1000) and worker configurations (10-1000).

## Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=reconforgex

# Development checks
ruff check reconforgex/ tests/ benchmarks/
mypy reconforgex/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for any new functionality
4. Run `ruff check` and `pytest` before submitting
5. Submit a pull request

## License

MIT