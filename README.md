# Recon — Advanced Reconnaissance Framework

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

**A modular, async-first reconnaissance framework for security professionals and bug bounty hunters.**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Directory Structure](#-directory-structure)
- [Features](#-features)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Output](#-output)
- [Pipeline](#-pipeline)
- [Reporting](#-reporting)
- [Development](#-development)
- [Testing](#-testing)
- [Benchmarks](#-benchmarks)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

Recon orchestrates industry-standard security tools through a clean, extensible pipeline architecture. It automates the entire reconnaissance workflow — from subdomain discovery through vulnerability scanning — producing comprehensive reports in JSON, Markdown, and HTML formats.

Designed for **backend engineers and security professionals**, Recon emphasizes:

- **Clean architecture** — modular, testable, single-responsibility components
- **Async execution** — `asyncio`-first design for concurrent stage execution
- **Type safety** — fully type-annotated Python 3.11+ codebase
- **Configurability** — YAML configuration with CLI overrides
- **Extensibility** — plugin-style stage registration in the pipeline scheduler

---

## 🏗️ Architecture

```
                            ┌──────────────┐
                            │   CLI Parser  │
                            │  (argparse)   │
                            └──────┬───────┘
                                   │
                            ┌──────▼───────┐
                            │   Config     │
                            │  (YAML/CLI)  │
                            └──────┬───────┘
                                   │
                            ┌──────▼───────┐
                            │   Pipeline   │
                            │   Manager    │
                            └──────┬───────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
              ┌─────▼─────┐  ┌────▼─────┐  ┌─────▼─────┐
              │  Wave 0   │  │  Wave 1  │  │  Wave 2   │
              │ (async)   │  │ (async)  │  │ (sync)    │
              └─────┬─────┘  └────┬─────┘  └─────┬─────┘
                    │              │              │
         ┌──────────┼──┐    ┌─────┴─────┐   ┌────┴────┐
         ▼          ▼    ▼    ▼           ▼   ▼        ▼
    Subfinder  Assetfinder  httpx    Aquatone  Report Builder
```

### Pipeline Stages

| Stage | Tool | Description | Async |
|-------|------|-------------|-------|
| `subdomain_enumeration` | subfinder, assetfinder | Discover subdomains | No |
| `live_host_detection` | httpx | Probe for live web servers | No |
| `technology_detection` | httpx (embedded) | Fingerprint technologies | No |
| `screenshots` | aquatone | Capture visual screenshots | Yes |
| `port_scan` | nmap | Discover open ports | Yes |
| `vulnerability_scan` | nuclei | Template-based vuln scanning | Yes |
| `report_builder` | — | Generate JSON/MD/HTML reports | No |

Stages are organized as a **DAG** (directed acyclic graph). The pipeline scheduler computes topological execution order, running independent stages concurrently.

---

## 📁 Directory Structure

```
recon/
├── recon/                          # Package root
│   ├── __init__.py                 # Public API exports
│   ├── cli.py                      # CLI argument parsing & entry point
│   ├── config.py                   # YAML configuration loader
│   ├── constants.py                # Centralized constants
│   ├── exceptions.py               # Custom exception hierarchy
│   ├── logger.py                   # Structured logging
│   ├── pipeline/
│   │   ├── manager.py              # Pipeline orchestrator & statistics
│   │   └── scheduler.py            # DAG-based stage scheduler
│   ├── modules/
│   │   ├── enum.py                 # Subdomain enumeration
│   │   ├── probe.py                # Live host detection & tech fingerprinting
│   │   ├── screenshot.py           # Screenshot capture
│   │   ├── ports.py                # Nmap port scanning
│   │   └── nuclei.py               # Vulnerability scanning
│   ├── report/
│   │   ├── json_report.py          # JSON report builder
│   │   ├── markdown_report.py      # Markdown report builder
│   │   └── html_report.py          # Standalone HTML report builder
│   └── utils/
│       ├── files.py                # File I/O helpers
│       ├── process.py              # Async subprocess execution
│       └── validators.py           # Input validation
├── tests/                          # pytest test suite
├── benchmarks/                     # Performance benchmarks
├── configs/                        # YAML configuration examples
├── docs/                           # Documentation
├── examples/                       # Usage examples
├── pyproject.toml                  # Project metadata & dependencies
├── requirements.txt                # pip requirements
└── README.md                       # This file
```

---

## ✨ Features

- **Multi-source subdomain discovery** — aggregates results from subfinder and assetfinder
- **Live host detection & fingerprinting** — uses httpx with JSON output parsing
- **Technology detection** — automatic identification of web frameworks, servers, and libraries
- **Visual reconnaissance** — automated screenshots via aquatone
- **Port scanning** — optional Nmap integration for open port discovery
- **Vulnerability scanning** — optional Nuclei integration with severity filters
- **Concurrent execution** — async pipeline with DAG-based wave scheduling
- **Structured logging** — timestamped, level-aware logs to console and file
- **YAML configuration** — full configuration via YAML files with CLI overrides
- **Multi-format reporting** — JSON, Markdown, and standalone HTML reports
- **Execution statistics** — timing, stage status, and resource metrics
- **Extensible architecture** — plugin-style stage registration

---

## 🚀 Installation

### Prerequisites

The following external tools must be installed on your system:

| Tool | Purpose | Installation |
|------|---------|-------------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain discovery | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Subdomain discovery | `go install -v github.com/tomnomnom/assetfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | Live host detection | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [aquatone](https://github.com/michenriksen/aquatone) | Screenshots | `go install -v github.com/michenriksen/aquatone@latest` |
| [nmap](https://nmap.org/) | Port scanning | `sudo apt install nmap` (or `brew install nmap`) |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

### Install Recon

```bash
# Clone the repository
git clone https://github.com/NASHEDIxCODER/recon.git
cd recon

# Install dependencies
pip install -r requirements.txt

# Install in development mode (recommended)
pip install -e ".[dev]"

# Verify installation
recon --version
# or
python3 recon.py --version
```

---

## ⚙️ Configuration

Recon supports YAML configuration files. By default, it looks for `configs/default.yaml`.

### Configuration File

```yaml
# configs/default.yaml
worker_count: 10
timeouts: 300
rate_limit: 50
retry_count: 3
output_directory: "output"
logging_level: "INFO"

# Custom tool paths (empty = use system PATH)
tool_paths:
  subfinder: ""
  assetfinder: ""
  httpx: ""
  aquatone: ""
  nmap: ""
  nuclei: ""

# Default modules to run
default_modules:
  - subdomain_enumeration
  - live_host_detection
  - technology_detection
  - screenshots
```

**CLI flags override configuration file values.**

---

## 💻 Usage

### Basic Scan

```bash
# Minimal scan (subdomains → live hosts → screenshots)
recon -d example.com
```

### Full Scan

```bash
# Full reconnaissance including port scan and vulnerability scan
recon -d example.com --port-scan --vuln-scan
```

### Custom Output Directory

```bash
recon -d example.com -o /path/to/results --port-scan --vuln-scan
```

### Using a Configuration File

```bash
recon my_config.yaml -d example.com
# or for implicit config
recon -d example.com  # auto-loads configs/default.yaml if present
```

### Verbose/Debug Mode

```bash
recon -d example.com --verbose
```

### All Options

```
positional arguments:
  config                Path to a YAML configuration file (optional).

options:
  -h, --help            Show this help message and exit
  -d, --domain DOMAIN   Target domain (e.g. example.com).
  -o, --output OUTPUT   Directory to save all output files (default: output/).
  --port-scan           Run an Nmap port scan on live hosts.
  --vuln-scan           Run a Nuclei vulnerability scan on live hosts.
  --verbose             Enable DEBUG-level logging.
  --version             Show program's version number and exit.
```

---

## 📂 Output

All scan results are organized under the output directory (default: `output/`):

```
output/
├── subdomains.txt           # Discovered subdomains (one per line)
├── live.txt                 # Live host URLs
├── screenshots/
│   └── aquatone_report/     # Screenshot files (if aquatone ran)
├── reports/
│   ├── report.json          # Structured JSON report
│   ├── report.md            # Formatted Markdown report
│   └── report.html          # Standalone HTML report (dark theme)
├── logs/
│   └── recon.log            # Timestamped execution log
├── nmap_scan.txt            # Nmap results (if --port-scan)
└── nuclei_scan.txt          # Nuclei findings (if --vuln-scan)
```

---

## 📊 Pipeline

The pipeline is implemented as a **DAG** (directed acyclic graph) where:

1. **Wave 0** — Independent stages that can run first (subdomain enumeration)
2. **Wave 1** — Stages that depend on Wave 0 (live host detection)
3. **Wave 2+** — Stages that depend on earlier waves (screenshots, port scan, vulnerability scan, reports)

Within each wave, stages without interdependencies run **concurrently** via `asyncio.gather()`.

### Adding Custom Stages

```python
from recon.pipeline.scheduler import Stage
from recon.pipeline.manager import PipelineManager

# Create a custom stage
custom_stage = Stage(
    name="custom_scan",
    description="My custom reconnaissance module",
    depends_on=["live_host_detection"],
    run_async=True,
    func=my_async_function,
)

# Register it
manager = PipelineManager(config)
manager._scheduler.register(custom_stage)
await manager.run()
```

---

## 📈 Reporting

Reports are automatically generated in three formats after each scan:

### JSON Report (`report.json`)

Structured data for programmatic consumption — includes summary, statistics, subdomains, live hosts, technologies, port scan results, and nuclei findings.

### Markdown Report (`report.md`)

Formatted report with tables, code blocks, and clear sectioning — ideal for embedding in wikis or sharing on GitHub.

### HTML Report (`report.html`)

Standalone dark-themed HTML page with embedded CSS — perfect for sharing with team members or attaching to bug bounty reports. Features:

- Summary statistics cards
- Stage execution timeline
- Subdomain listing
- Live host table with status codes, titles, and technologies
- Port scan and vulnerability findings sections

---

## 🧪 Development

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=recon --cov-report=term-missing

# Run specific test file
pytest tests/test_validators.py -v
```

### Code Style

The project follows [PEP 8](https://www.python.org/dev/peps/pep-0008/) conventions with type annotations throughout.

```bash
# Check typing
mypy recon/ --strict

# Format code
black recon/ tests/
```

### Adding a New Module

1. Create a new file in `recon/modules/` (e.g., `recon/modules/new_scan.py`)
2. Implement an async function that accepts configurable parameters
3. Add a stage in `recon/pipeline/manager.py` or register it externally
4. Write tests in `tests/`
5. Update the report builders in `recon/report/`

---

## ⏱️ Benchmarks

```bash
python3 benchmarks/bench_basic.py
```

Measures:
- **Execution time** — per-operation timing
- **Memory usage** — RSS delta and traced peak allocation
- **Throughput** — operations per second

---

## 🗺️ Roadmap

- [x] Modular package structure
- [x] YAML configuration
- [x] Async pipeline execution
- [x] Structured logging
- [x] Multi-format reporting (JSON, Markdown, HTML)
- [x] Execution statistics
- [x] Comprehensive test suite
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Docker containerization
- [ ] Plugin system for custom modules
- [ ] Real-time WebSocket progress updates
- [ ] Distributed scanning across multiple workers
- [ ] Web dashboard

---

## 🤝 Contributing

Contributions are welcome! Please follow the standard fork-and-pull-request workflow.

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Guidelines

- Write type-annotated Python (3.11+)
- Include tests for new functionality
- Update documentation as needed
- Follow the existing code style
- Keep modules independently testable

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

<div align="center">
  <sub>Built with ❤️ by <a href="https://github.com/NASHEDIxCODER">nashedi_x_coder</a></sub>
</div>