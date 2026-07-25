# ReconForgeX — Internal Technical Documentation

## Project Goals

ReconForgeX is a pure-Python reconnaissance framework that replaces the typical stack of external tools (subfinder, httpx, nuclei, aquatone, etc.) with a single, installable package. The goals are:

1. **Zero external tool dependencies** — Everything runs in pure Python. No `subfinder`, `nmap`, `nuclei`, `aquatone`, or `httpx` binaries required.
2. **Unified pipeline** — A single CLI that runs all modules, handles dependency ordering, concurrency, and report generation.
3. **Async-first** — Built on `asyncio` and `httpx` for efficient concurrent I/O.
4. **Extensible** — New modules implement `BaseModule` and register themselves in the pipeline.

## Architecture

### High-Level Flow

```
┌─────────┐    ┌──────────┐    ┌────────────────┐    ┌────────────┐    ┌─────────┐
│  CLI    │───▶│  Config  │───▶│ PipelineManager │───▶│  Scheduler │───▶│ Reports │
│ argparse│    │ YAML/CLI │    │  orchestrator   │    │  DAG sort  │    │ HTML/   │
└─────────┘    └──────────┘    └────────────────┘    └────────────┘    │ JSON/MD │
                                      │                                └─────────┘
                                      ▼
                              ┌────────────────┐
                              │  Shared HTTP   │
                              │    Client      │
                              │ (connection    │
                              │  pooling)      │
                              └────────────────┘
                                      │
                                      ▼
                              ┌────────────────┐
                              │    Modules     │
                              │  (13 total)    │
                              └────────────────┘
```

### Design Decisions

**Why a single shared HTTP client?**
- Connection pooling across all modules reduces overhead
- Unified rate limiting and retry logic
- Single source of truth for HTTP statistics (timing, errors, redirects)

**Why DAG-based scheduling?**
- Some modules depend on others (e.g., JS endpoint extraction depends on JS collection)
- Independent modules should run concurrently
- Topological sort (Kahn's algorithm) provides deterministic execution order

**Why pure Python?**
- Eliminates installation friction (no external binaries)
- Cross-platform by default
- Easier to debug and extend

## Directory Layout

```
reconforgex/
├── cli.py                  # Argument parsing, banner, dispatch
├── config.py               # ReconForgeXConfig dataclass, YAML loading
├── constants.py            # All magic strings, paths, module names
├── exceptions.py           # Custom exception hierarchy
├── logger.py               # ReconForgeXLogger singleton
├── __init__.py             # Public API exports
├── __main__.py             # python -m entry point
├── modules/                # Reconnaissance modules
│   ├── base.py             # BaseModule ABC, ModuleConfiguration, etc.
│   ├── csp_analyzer.py     # CSPAnalyzer
│   ├── header_analyzer.py  # HeaderAnalyzer
│   ├── http_fingerprint.py # HTTPFingerprinting
│   ├── http_response_analyzer.py  # HTTPResponseAnalyzer
│   ├── interesting_files.py       # InterestingFilesFinder
│   ├── js_collector.py     # JSCollector
│   ├── js_endpoint_extractor.py   # JSEndpointExtractor
│   ├── js_secret_detector.py      # JSSecretDetector
│   ├── risk_scoring.py     # RiskScoringEngine
│   ├── robots_parser.py    # RobotsParser
│   ├── security_header_scanner.py # SecurityHeaderScanner
│   ├── sitemap_parser.py   # SitemapParser
│   └── tls_inspector.py    # TLSInspector
├── pipeline/               # Orchestration
│   ├── manager.py          # PipelineManager — registers stages, runs pipeline
│   ├── scheduler.py        # PipelineScheduler — DAG topological sort
│   ├── statistics.py       # PipelineStatistics — timing, throughput, resource usage
│   └── worker_pool.py      # WorkerPool — concurrent task execution
├── report/                 # Report generators
│   ├── html_report.py      # build_html_report
│   ├── json_report.py      # build_json_report
│   └── markdown_report.py  # build_markdown_report
└── utils/                  # Shared utilities
    ├── http_client.py      # AsyncHTTPClient — httpx-based with retry, rate limiting
    ├── rate_limiter.py     # TokenBucketRateLimiter
    └── validators.py       # Domain, URL, hostname validation
tests/                      # pytest test suite
benchmarks/                 # Performance benchmarks
```

## Pipeline

### Stage Registration

The `PipelineManager._register_default_stages()` method registers 14 stages:

**Wave 0 (10 concurrent stages, no dependencies):**
- `http_fingerprinting`
- `header_analyzer`
- `security_header_scanner`
- `tls_inspector`
- `csp_analyzer`
- `robots_parser`
- `sitemap_parser`
- `js_collector`
- `interesting_files`
- `http_response_analyzer`

**Wave 1 (2 stages, depend on JS collector):**
- `js_endpoint_extractor` (depends on `js_collector`)
- `js_secret_detector` (depends on `js_collector`)

**Wave 2 (1 stage, depends on multiple analyzers):**
- `risk_scoring` (depends on `header_analyzer`, `security_header_scanner`, `tls_inspector`, `csp_analyzer`, `js_secret_detector`)

**Wave 3 (1 stage, depends on all):**
- `report_builder` (depends on all 12 analysis stages + risk scoring)

### Execution

```python
waves = scheduler.get_execution_order()  # Kahn's algorithm
for wave in waves:
    tasks = [execute_stage(stage) for stage in wave]
    results = await asyncio.gather(*tasks)
```

### Data Flow

Modules write results to `self._data_store` (a `Dict[str, Any]`). Downstream modules read from it. The data store is also passed to report generators.

## Worker Pool

The `WorkerPool` manages concurrent task execution:

- **Configurable size**: 10-1000 workers
- **Task queue**: asyncio.Queue for backpressure
- **Graceful shutdown**: Drains pending tasks on close
- **Error handling**: Failed tasks are logged, not silently dropped

```python
pool = WorkerPool(config=WorkerPoolConfig(max_workers=50))
await pool.start()
results = await pool.map(tasks)
await pool.stop()
```

## Scheduler

The `PipelineScheduler` implements Kahn's algorithm for topological sort:

1. Compute in-degree for each stage
2. Start with stages that have zero in-degree (no dependencies)
3. Process each wave, decrementing in-degree of dependents
4. Detect cycles if not all stages are scheduled

```python
scheduler = PipelineScheduler()
scheduler.register(Stage(name="a", depends_on=[]))
scheduler.register(Stage(name="b", depends_on=["a"]))
waves = scheduler.get_execution_order()  # [[a], [b]]
```

## HTTP Client

`AsyncHTTPClient` wraps `httpx.AsyncClient` with:

- **Connection pooling**: Reuses connections across all modules
- **Retry with backoff**: Configurable retry count and exponential backoff
- **Rate limiting**: Token bucket algorithm (optional)
- **Statistics**: Tracks request count, error count, timing, status codes
- **HTTP/2 support**: Via httpx

```python
config = HTTPClientConfig(timeout=30, max_retries=3, max_concurrency=50)
client = AsyncHTTPClient(config)
response = await client.get("https://example.com/")
```

## Rate Limiter

Token bucket implementation:

- **Capacity**: Maximum burst size
- **Rate**: Tokens added per second
- **Blocking**: `acquire()` blocks until a token is available
- **Non-blocking**: `try_acquire()` returns immediately

## Statistics

`PipelineStatistics` collects:

- **Timing**: Average, median, P95, P99 response times
- **Throughput**: Requests per second
- **Resource usage**: Memory (current + peak), CPU percentage
- **Error rates**: Total errors, retries, timeouts, client/server errors
- **Connection metrics**: Open/peak connections, bytes sent/received

Resource usage is read from `/proc/self/status` on Linux (fallback when `psutil` is not installed).

## Reports

Three report generators produce output in `output/reports/`:

- **JSON** (`build_json_report`): Structured data, machine-readable
- **Markdown** (`build_markdown_report`): Human-readable, CI-friendly
- **HTML** (`build_html_report`): Interactive with CSS styling

Each report includes:
- Scan metadata (domain, timestamp, duration)
- Per-module results
- Execution statistics
- Error summary

## Modules

### BaseModule (ABC)

```python
class BaseModule(ABC):
    async def run(self, target: str, **kwargs) -> List[Any]: ...
    def metadata(self) -> ModuleMetadata: ...
    def statistics(self) -> ModuleStatistics: ...
    def health(self) -> ModuleHealth: ...
    def configuration(self) -> ModuleConfiguration: ...
    def set_http_client(self, client: Any): ...
```

### Module List

| Module | Class | Input | Output |
|--------|-------|-------|--------|
| http_fingerprinting | HTTPFingerprinting | domain | List[FingerprintResult] |
| header_analyzer | HeaderAnalyzer | domain | List[HeaderAnalysisResult] |
| security_header_scanner | SecurityHeaderScanner | domain | List[SecurityHeaderResult] |
| tls_inspector | TLSInspector | domain | List[TLSResult] |
| csp_analyzer | CSPAnalyzer | domain | List[CSPAnalysis] |
| robots_parser | RobotsParser | domain | List[RobotsResult] |
| sitemap_parser | SitemapParser | domain | List[SitemapResult] |
| js_collector | JSCollector | domain | List[JSCollectionResult] |
| js_endpoint_extractor | JSEndpointExtractor | domain, js_contents | List[EndpointExtractionResult] |
| js_secret_detector | JSSecretDetector | domain, js_contents | List[SecretDetectionResult] |
| interesting_files | InterestingFilesFinder | domain | List[InterestingFilesResult] |
| http_response_analyzer | HTTPResponseAnalyzer | domain | List[HTTPResponseAnalysisResult] |
| risk_scoring | RiskScoringEngine | target, header_results, tls_results, csp_results, secret_results | List[RiskScoreResult] |

## Testing

34 tests across 5 test files:

- `test_cli.py` — Argument parsing (8 tests)
- `test_config.py` — Configuration loading and merging (6 tests)
- `test_pipeline_scheduler.py` — DAG scheduling (8 tests)
- `test_report.py` — Report generation (3 tests)
- `test_validators.py` — Input validation (9 tests)

Run with: `pytest`

## Benchmark Methodology

The benchmark suite (`benchmarks/bench_basic.py`) measures:

1. **Domain counts**: 10, 100, 500, 1000
2. **Worker counts**: 10, 25, 50, 100, 250, 500, 1000
3. **Metrics**: Runtime, throughput (req/s), latency percentiles (P50/P95/P99), memory, CPU, error rate

Each combination sends concurrent HEAD requests to real domains and collects timing/resource data.

## Current Limitations

1. **No subdomain enumeration** — The framework analyzes a single target domain. Subdomain discovery was removed because it required external tools.
2. **No port scanning** — Port scanning was removed because it required external tools.
3. **No screenshots** — Screenshot capture was removed because it required external tools.
4. **Single-domain only** — The pipeline processes one domain per invocation.
5. **No plugin system** — Adding a new module requires modifying `constants.py` and `manager.py`.
6. **No authentication** — The HTTP client does not handle authenticated sessions.

## Maintenance Notes

### Adding a New Module

1. Create `reconforgex/modules/your_module.py` with a class extending `BaseModule`
2. Add module name constant to `constants.py`
3. Add stage name constant to `constants.py`
4. Add class path to `MODULE_CLASS_MAP` in `constants.py`
5. Register the stage in `PipelineManager._register_default_stages()`
6. Add the module to `ALL_MODULES` in `config.py`
7. Export from `reconforgex/modules/__init__.py`
8. Add to `_print_module_list()` in `cli.py`

### Removing a Module

1. Remove from `MODULE_CLASS_MAP` in `constants.py`
2. Remove stage registration from `PipelineManager._register_default_stages()`
3. Remove from `ALL_MODULES` in `config.py`
4. Remove from `reconforgex/modules/__init__.py`
5. Remove from `_print_module_list()` in `cli.py`
6. Delete the module file

### Versioning

Follow semantic versioning. The current version is 2.0.0.

### CI/CD

GitHub Actions workflows:
- `ci.yml` — Runs tests, linting, and type checking on push/PR
- `release.yml` — Publishes to PyPI on tag push