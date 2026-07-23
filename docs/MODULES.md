# ReconForgeX — Modules

## Overview

ReconForgeX includes 13 built-in reconnaissance modules. Each module extends `BaseModule` and implements a standardized interface. This document describes every module's purpose, inputs, outputs, dependencies, configuration, statistics, and example output.

---

## Module Interface

All modules implement the following interface from `modules/base.py`:

```python
class BaseModule(ABC):
    async def run(self, target: str, **kwargs) -> List[Any]: ...
    def metadata(self) -> ModuleMetadata: ...
    def statistics(self) -> ModuleStatistics: ...
    def health(self) -> ModuleHealth: ...
    def configuration(self) -> ModuleConfiguration: ...
    def set_http_client(self, client: Any) -> None: ...
    def reset(self) -> None: ...
```

### Common Dataclasses

```python
@dataclass
class ModuleMetadata:
    name: str
    description: str
    version: str = "1.0.0"
    author: str = "ReconForgeX"
    tags: List[str]
    requires_network: bool = True
    requires_domain: bool = True
    timeout_default: int = 30

@dataclass
class ModuleStatistics:
    execution_time: float
    items_found: int
    items_processed: int
    errors: int
    retries: int
    status: ModuleStatus
    memory_usage_mb: float
    cpu_percent: float

@dataclass
class ModuleConfiguration:
    enabled: bool = True
    timeout: int = 30
    max_retries: int = 3
    concurrency: int = 10
    extra: Dict[str, Any]
```

---

## Module List

| # | Module | File | Category | Wave |
|---|--------|------|----------|------|
| 1 | HTTP Fingerprinting | `http_fingerprint.py` | HTTP Analysis | 1 |
| 2 | Header Analyzer | `header_analyzer.py` | HTTP Analysis | 1 |
| 3 | Security Header Scanner | `security_header_scanner.py` | Security Scanning | 1 |
| 4 | TLS Inspector | `tls_inspector.py` | Security Scanning | 1 |
| 5 | CSP Analyzer | `csp_analyzer.py` | Security Scanning | 1 |
| 6 | robots.txt Parser | `robots_parser.py` | Content Discovery | 1 |
| 7 | sitemap.xml Parser | `sitemap_parser.py` | Content Discovery | 1 |
| 8 | JS Collector | `js_collector.py` | JavaScript Analysis | 1 |
| 9 | Interesting Files Finder | `interesting_files.py` | Content Discovery | 1 |
| 10 | HTTP Response Analyzer | `http_response_analyzer.py` | HTTP Analysis | 1 |
| 11 | JS Endpoint Extractor | `js_endpoint_extractor.py` | JavaScript Analysis | 2 |
| 12 | JS Secret Detector | `js_secret_detector.py` | JavaScript Analysis | 2 |
| 13 | Risk Scoring Engine | `risk_scoring.py` | Security Scanning | 3 |

---

## 1. HTTP Fingerprinting

**File**: `reconforgex/modules/http_fingerprint.py`  
**Class**: `HTTPFingerprinting`

### Purpose

Identifies web servers, frameworks, and technologies by analyzing HTTP response headers, cookies, and body patterns. Built-in fingerprint database covers 30+ technologies.

### Why It Exists

Knowing what technologies a target uses is the first step in reconnaissance. It informs vulnerability assessment, technology-specific attack surface analysis, and helps prioritize further investigation.

### Inputs

- `target` (str): Domain name (e.g., `example.com`)
- HTTP client (injected via `set_http_client()`)

### Outputs

Returns a list of `FingerprintResult` dataclass instances:

```python
@dataclass
class FingerprintResult:
    url: str
    status_code: int
    server_header: str
    technologies: List[str]
    headers: Dict[str, str]
    body_snippets: List[str]
    response_time: float
```

### Dependencies

- `AsyncHTTPClient` (shared)
- `FINGERPRINT_PATTERNS` — built-in dictionary of 30+ technology signatures

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | HTTP request timeout |
| `max_retries` | 3 | Retry attempts per request |

### Statistics Produced

- `items_found`: Number of technologies detected
- `items_processed`: Number of URLs fingerprinted
- `errors`: Failed requests

### Example Output

```python
[
    FingerprintResult(
        url="https://example.com",
        status_code=200,
        server_header="ECS (dcb/7F5E)",
        technologies=["cloudflare", "aws"],
        headers={"server": "ECS (dcb/7F5E)", "cf-ray": "..."},
        body_snippets=["<title>Example Domain</title>"],
        response_time=0.234,
    )
]
```
```

### Fingerprint Database

The module includes signatures for: nginx, Apache, Cloudflare, CloudFront, AWS, Google Cloud, Azure, Fastly, Varnish, IIS, PHP, Python, Django, Flask, Node.js, Express, Next.js, Nuxt.js, Gatsby, WordPress, Drupal, Joomla, Shopify, Magento, Wix, Squarespace, Netlify, Vercel, GitHub Pages, GitLab Pages, and more.

---

## 2. Header Analyzer

**File**: `reconforgex/modules/header_analyzer.py`  
**Class**: `HeaderAnalyzer`

### Purpose

Analyzes HTTP response headers for security misconfigurations, information disclosure, and compliance with OWASP best practices. Provides a security score (0–100) per target.

### Why It Exists

HTTP headers reveal a lot about a server's security posture. Missing security headers, exposed server versions, and information leakage through headers are common findings in security assessments.

### Inputs

- `target` (str): Domain name
- HTTP client (injected)

### Outputs

Returns a list of `HeaderAnalysisResult` dataclass instances:

```python
@dataclass
class HeaderAnalysisResult:
    url: str
    status_code: int
    security_score: int  # 0-100
    findings: List[Finding]
    missing_security_headers: List[str]
    information_disclosures: List[str]

@dataclass
class Finding:
    type: str  # "missing_header", "info_disclosure", "misconfiguration"
    severity: str  # "critical", "high", "medium", "low", "info"
    header: str
    message: str
    recommendation: str
```

### Dependencies

- `AsyncHTTPClient` (shared)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | HTTP request timeout |
| `max_retries` | 3 | Retry attempts |

### Statistics Produced

- `items_found`: Number of findings
- `items_processed`: Number of URLs analyzed

### Headers Checked

**Security Headers (11)**:
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `X-XSS-Protection`
- `Referrer-Policy`
- `Permissions-Policy`
- `Access-Control-Allow-Origin`
- `Cross-Origin-Resource-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Embedder-Policy`

**Information Disclosure Headers (4)**:
- `Server`
- `X-Powered-By`
- `X-AspNet-Version`
- `X-AspNetMvc-Version`

### Example Output

```python
[
    HeaderAnalysisResult(
        url="https://example.com",
        status_code=200,
        security_score=45,
        findings=[
            Finding(
                type="missing_header",
                severity="high",
                header="Content-Security-Policy",
                message="CSP header is missing",
                recommendation="Implement a CSP header to prevent XSS attacks",
            ),
            Finding(
                type="info_disclosure",
                severity="low",
                header="Server",
                message="Server version disclosed: ECS (dcb/7F5E)",
                recommendation="Remove or obfuscate server version header",
            ),
        ],
        missing_security_headers=["Content-Security-Policy", "Permissions-Policy"],
        information_disclosures=["Server"],
    )
]
```

---

## 3. Security Header Scanner

**File**: `reconforgex/modules/security_header_scanner.py`  
**Class**: `SecurityHeaderScanner`

### Purpose

Dedicated scanner for 12 OWASP-recommended security headers with detailed compliance checking. Provides per-header compliance status and an overall compliance score.

### Why It Exists

While the Header Analyzer provides a broad overview, the Security Header Scanner performs deep compliance checking against OWASP recommendations, including value validation (e.g., checking that `Strict-Transport-Security` has a sufficient `max-age`).

### Inputs

- `target` (str): Domain name
- HTTP client (injected)

### Outputs

Returns a list of `SecurityHeaderResult` dataclass instances:

```python
@dataclass
class SecurityHeaderResult:
    url: str
    status_code: int
    compliance_score: int  # 0-100
    total_headers: int
    present_headers: int
    compliant_headers: int
    checks: List[HeaderCheck]

@dataclass
class HeaderCheck:
    header: str
    present: bool
    value: str
    compliant: bool
    severity: str
    recommendation: str
```

### Dependencies

- `AsyncHTTPClient` (shared)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | HTTP request timeout |
| `max_retries` | 3 | Retry attempts |

### Statistics Produced

- `items_found`: Number of header checks performed
- `items_processed`: Number of URLs scanned

### Headers Checked

1. `Strict-Transport-Security` — HSTS with `max-age >= 31536000`
2. `Content-Security-Policy` — Present and not overly permissive
3. `X-Content-Type-Options` — Must be `nosniff`
4. `X-Frame-Options` — Must be `DENY` or `SAMEORIGIN`
5. `X-XSS-Protection` — Must be `1; mode=block`
6. `Referrer-Policy` — Must be set to a privacy-preserving value
7. `Permissions-Policy` — Must restrict sensitive features
8. `Access-Control-Allow-Origin` — Should not be `*`
9. `Cross-Origin-Resource-Policy` — Should be set
10. `Cross-Origin-Opener-Policy` — Should be set
11. `Cross-Origin-Embedder-Policy` — Should be set
12. `Cache-Control` — Should prevent caching of sensitive data

### Example Output

```python
[
    SecurityHeaderResult(
        url="https://example.com",
        status_code=200,
        compliance_score=58,
        total_headers=12,
        present_headers=5,
        compliant_headers=3,
        checks=[
            HeaderCheck(
                header="Strict-Transport-Security",
                present=True,
                value="max-age=31536000",
                compliant=True,
                severity="high",
                recommendation="HSTS is properly configured",
            ),
            HeaderCheck(
                header="Content-Security-Policy",
                present=False,
                value="",
                compliant=False,
                severity="critical",
                recommendation="Implement CSP to prevent XSS attacks",
            ),
        ],
    )
]
```

---

## 4. TLS Inspector

**File**: `reconforgex/modules/tls_inspector.py`  
**Class**: `TLSInspector`

### Purpose

Inspects TLS/SSL certificates, protocol versions, and security configurations. Detects expired certificates, self-signed certificates, and weak TLS versions.

### Why It Exists

TLS configuration is critical for security. Expired certificates, weak protocols (TLS 1.0/1.1), and misconfigured certificate validation are common findings that can lead to MITM attacks or service disruptions.

### Inputs

- `target` (str): Domain name
- HTTP client (injected)

### Outputs

Returns a list of `TLSResult` dataclass instances:

```python
@dataclass
class TLSResult:
    url: str
    tls_version: str
    certificate_issuer: str
    certificate_subject: str
    certificate_serial: str
    valid_from: str
    valid_until: str
    days_remaining: int
    is_expired: bool
    is_self_signed: bool
    san_list: List[str]
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
```

### Dependencies

- `AsyncHTTPClient` (shared)
- Python `ssl` module (via httpx)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | Connection timeout |
| `max_retries` | 3 | Retry attempts |

### Statistics Produced

- `items_found`: Number of certificates inspected
- `items_processed`: Number of TLS connections made
- `tls_versions`: Distribution of TLS versions found

### Example Output

```python
[
    TLSResult(
        url="https://example.com",
        tls_version="TLS 1.3",
        certificate_issuer="CN=DigiCert TLS RSA SHA256 2020 CA1",
        certificate_subject="CN=example.com",
        certificate_serial="0123456789ABCDEF",
        valid_from="2024-01-01 00:00:00 UTC",
        valid_until="2025-01-01 23:59:59 UTC",
        days_remaining=163,
        is_expired=False,
        is_self_signed=False,
        san_list=["example.com", "www.example.com"],
        signature_algorithm="sha256WithRSAEncryption",
        public_key_algorithm="RSA",
        public_key_size=2048,
    )
]
```

---

## 5. CSP Analyzer

**File**: `reconforgex/modules/csp_analyzer.py`  
**Class**: `CSPAnalyzer`

### Purpose

Analyzes Content-Security-Policy headers for weaknesses, missing directives, and bypass opportunities. Identifies 10+ CSP bypass vectors.

### Why It Exists

CSP is a powerful defense against XSS, but it's notoriously easy to misconfigure. Common mistakes like using `unsafe-inline`, allowing CDN-hosted script sources, or missing critical directives can render CSP ineffective.

### Inputs

- `target` (str): Domain name
- HTTP client (injected)

### Outputs

Returns a list of `CSPAnalysisResult` dataclass instances:

```python
@dataclass
class CSPAnalysisResult:
    url: str
    has_csp: bool
    csp_header: str
    directives: Dict[str, List[str]]
    weaknesses: List[CSPWeakness]
    bypass_vectors: List[str]
    security_score: int  # 0-100

@dataclass
class CSPWeakness:
    type: str
    directive: str
    severity: str
    description: str
    recommendation: str
```

### Dependencies

- `AsyncHTTPClient` (shared)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | HTTP request timeout |
| `max_retries` | 3 | Retry attempts |

### Statistics Produced

- `items_found`: Number of CSP weaknesses found
- `items_processed`: Number of URLs analyzed

### Bypass Vectors Detected

1. `unsafe-inline` in `script-src`
2. `unsafe-eval` in `script-src`
3. CDN-based bypass (ajax.googleapis.com, cdnjs.cloudflare.com, etc.)
4. Wildcard in `script-src`
5. Missing `object-src`
6. Missing `base-uri`
7. Weak `frame-ancestors`
8. Missing `form-action`
9. Scheme bypass (`http:`, `https:`)
10. JSONP endpoints in allowed sources
11. Angular expressions in allowed sources

### Example Output

```python
[
    CSPAnalysisResult(
        url="https://example.com",
        has_csp=True,
        csp_header="default-src 'self'; script-src 'self' https://cdn.example.com",
        directives={
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"],
        },
        weaknesses=[
            CSPWeakness(
                type="cdn_bypass",
                directive="script-src",
                severity="high",
                description="CDN source allows potential script injection",
                recommendation="Remove CDN sources or use SRI hashes",
            ),
        ],
        bypass_vectors=["cdn_bypass"],
        security_score=65,
    )
]
```

---

## 6. robots.txt Parser

**File**: `reconforgex/modules/robots_parser.py`  
**Class**: `RobotsParser`

### Purpose

Downloads and parses robots.txt to discover paths, sitemaps, and interesting restricted areas. Identifies 15+ interesting path patterns.

### Why It Exists

robots.txt is designed to tell crawlers what not to index, which ironically makes it a great source of discovery for security researchers. Disallowed paths often point to admin panels, private areas, or sensitive files.

### Inputs

- `target` (str): Domain name
- HTTP client (injected)

### Outputs

Returns a list of `RobotsResult` dataclass instances:

```python
@dataclass
class RobotsResult:
    url: str
    has_robots: bool
    content: str
    disallowed_paths: List[str]
    allowed_paths: List[str]
    sitemaps: List[str]
    crawl_delay: Optional[float]
    interesting_paths: List[InterestingPath]

@dataclass
class InterestingPath:
    path: str
    pattern_type: str  # "admin", "backup", "config", ".git", etc.
    severity: str
```

### Dependencies

- `AsyncHTTPClient` (shared)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | HTTP request timeout |
| `max_retries` | 3 | Retry attempts |

### Statistics Produced

- `items_found`: Number of discovered paths
- `items_processed`: Number of robots.txt files parsed

### Interesting Path Patterns

admin, administrator, backup, backup_files, config, configuration, db, database, debug, dev, development, .git, .svn, .env, wp-admin, login, dashboard, internal, private, secret, temp, test, staging, api, v1, v2, graphql, swagger, docs

### Example Output

```python
[
    RobotsResult(
        url="https://example.com/robots.txt",
        has_robots=True,
        content="User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nSitemap: https://example.com/sitemap.xml",
        disallowed_paths=["/admin/", "/backup/"],
        allowed_paths=[],
        sitemaps=["https://example.com/sitemap.xml"],
        crawl_delay=None,
        interesting_paths=[
            InterestingPath(path="/admin/", pattern_type="admin", severity="high"),
            InterestingPath(path="/backup/", pattern_type="backup", severity="critical"),
        ],
    )
]
```

---

## 7. sitemap.xml Parser

**File**: `reconforgex/modules/sitemap_parser.py`  
**Class**: `SitemapParser`

### Purpose

Downloads and parses XML sitemaps (including sitemap indices) to discover URLs within the target domain. Recursively fetches sub-sitemaps from sitemap indices.

### Why It Exists

Sitemaps provide an official inventory of a website's URLs. They reveal pages that might not be linked from the main site, including hidden or forgotten endpoints.

### Inputs

- `target` (str): Domain name
- HTTP client (injected)

### Outputs

Returns a list of `SitemapResult` dataclass instances:

```python
@dataclass
class SitemapResult:
    url: str
    has_sitemap: bool
    urls: List[SitemapURL]
    is_sitemap_index: bool
    sub_sitemaps: List[str]

@dataclass
class SitemapURL:
    loc: str
    lastmod: Optional[str]
    changefreq: Optional[str]
    priority: Optional[float]
```

### Dependencies

- `AsyncHTTPClient` (shared)
- Python `xml.etree.ElementTree` (stdlib)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | HTTP request timeout |
| `max_retries` | 3 | Retry attempts |

### Statistics Produced

- `items_found`: Number of URLs discovered
- `items_processed`: Number of sitemaps parsed

### Example Output

```python
[
    SitemapResult(
        url="https://example.com/sitemap.xml",
        has_sitemap=True,
        urls=[
            SitemapURL(
                loc="https://example.com/",
                lastmod="2024-01-15",
                changefreq="daily",
                priority=1.0,
            ),
            SitemapURL(
                loc="https://example.com/about",
                lastmod="2024-01-10",
                changefreq="monthly",
                priority=0.8,
            ),
        ],
        is_sitemap_index=False,
        sub_sitemaps=[],
    )
]
```

---

## 8. JS Collector

**File**: `reconforgex/modules/js_collector.py`  
**Class**: `JSCollector`

### Purpose

Discovers and collects JavaScript files from web pages for further analysis. Extracts both inline and external scripts, identifies third-party scripts.

### Why It Exists

JavaScript files are a rich source of information for security researchers. They often contain API endpoints, authentication logic, secret keys, and client-side vulnerabilities. Collecting them is the first step in client-side security analysis.

### Inputs

- `target` (str): Domain name
- HTTP client (injected)

### Outputs

Returns a list of `JSCollectionResult` dataclass instances:

```python
@dataclass
class JSCollectionResult:
    url: str
    js_files: List[JSFile]
    inline_scripts: List[str]
    total_scripts: int
    third_party_scripts: List[str]

@dataclass
class JSFile:
    url: str
    content: str
    size: int
    is_third_party: bool
    source_domain: str
```

### Dependencies

- `AsyncHTTPClient` (shared)
- HTML parsing via regex (no external parser dependency)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | HTTP request timeout |
| `max_retries` | 3 | Retry attempts |

### Statistics Produced

- `items_found`: Number of JS files collected
- `items_processed`: Number of pages analyzed

### Example Output

```python
[
    JSCollectionResult(
        url="https://example.com",
        js_files=[
            JSFile(
                url="https://example.com/js/app.js",
                content="console.log('hello');\n// ...",
                size=45230,
                is_third_party=False,
                source_domain="example.com",
            ),
            JSFile(
                url="https://cdn.example.com/lib.js",
                content="/* library code */",
                size=120000,
                is_third_party=True,
                source_domain="cdn.example.com",
            ),
        ],
        inline_scripts=["<script>var x = 1;</script>"],
        total_scripts=3,
        third_party_scripts=["https://cdn.example.com/lib.js"],
    )
]
```

---

## 9. Interesting Files Finder

**File**: `reconforgex/modules/interesting_files.py`  
**Class**: `InterestingFilesFinder`

### Purpose

Discovers 60+ interesting files and paths organized into 7 categories: configuration files, source control, backups, logs, admin panels, API endpoints, and sensitive files.

### Why It Exists

Many web applications expose sensitive files through common paths. Automated discovery of these paths reveals configuration files, source code repositories, backup archives, and other sensitive information.

### Inputs

- `target` (str): Domain name
- HTTP client (injected)

### Outputs

Returns a list of `InterestingFileResult` dataclass instances:

```python
@dataclass
class InterestingFileResult:
    url: str
    path: str
    status_code: int
    content_type: str
    content_length: int
    category: str  # "config", "source_control", "backup", "log", "admin", "api", "sensitive"
    severity: str
    description: str
```

### Dependencies

- `AsyncHTTPClient` (shared)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | HTTP request timeout |
| `max_retries` | 3 | Retry attempts |
| `concurrency` | 10 | Concurrent path checks |

### Statistics Produced

- `items_found`: Number of accessible interesting files
- `items_processed`: Number of paths checked

### Path Categories

| Category | Count | Examples |
|----------|-------|---------|
| Configuration | 12 | `.env`, `config.php`, `settings.py`, `database.yml` |
| Source Control | 6 | `.git/`, `.svn/`, `.hg/`, `CVS/` |
| Backups | 8 | `backup.sql`, `dump.rdb`, `backup.zip` |
| Logs | 6 | `error.log`, `access.log`, `debug.log` |
| Admin Panels | 10 | `admin/`, `wp-admin/`, `administrator/` |
| API Endpoints | 10 | `api/`, `graphql`, `swagger.json`, `openapi.json` |
| Sensitive Files | 10 | `phpinfo.php`, `info.php`, `test.php`, `crossdomain.xml` |

### Example Output

```python
[
    InterestingFileResult(
        url="https://example.com/.env",
        path="/.env",
        status_code=200,
        content_type="application/octet-stream",
        content_length=1024,
        category="config",
        severity="critical",
        description="Environment configuration file exposed",
    ),
    InterestingFileResult(
        url="https://example.com/admin/",
        path="/admin/",
        status_code=200,
        content_type="text/html",
        content_length=5000,
        category="admin",
        severity="high",
        description="Admin panel accessible",
    ),
]
```

---

## 10. HTTP Response Analyzer

**File**: `reconforgex/modules/http_response_analyzer.py`  
**Class**: `HTTPResponseAnalyzer`

### Purpose

Analyzes HTTP responses for status codes, redirects, content types, and patterns (forms, login pages, file uploads). Provides status code distribution and response time analysis.

### Why It Exists

Understanding how a target responds to different requests reveals its attack surface. Redirect chains, form endpoints, file upload handlers, and login pages are all important reconnaissance targets.

### Inputs

- `target` (str): Domain name
- HTTP client (injected)

### Outputs

Returns a list of `ResponseAnalysisResult` dataclass instances:

```python
@dataclass
class ResponseAnalysisResult:
    url: str
    status_code: int
    content_type: str
    content_length: int
    response_time: float
    redirect_count: int
    redirect_chain: List[str]
    has_form: bool
    has_login_form: bool
    has_file_upload: bool
    has_error_page: bool
    technologies: List[str]
```

### Dependencies

- `AsyncHTTPClient` (shared)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | HTTP request timeout |
| `max_retries` | 3 | Retry attempts |

### Statistics Produced

- `items_found`: Number of patterns detected
- `items_processed`: Number of responses analyzed
- `redirects`: Total redirect count

### Example Output

```python
[
    ResponseAnalysisResult(
        url="https://example.com",
        status_code=200,
        content_type="text/html",
        content_length=1256,
        response_time=0.234,
        redirect_count=0,
        redirect_chain=[],
        has_form=False,
        has_login_form=False,
        has_file_upload=False,
        has_error_page=False,
        technologies=["cloudflare"],
    ),
    ResponseAnalysisResult(
        url="https://example.com/login",
        status_code=200,
        content_type="text/html",
        content_length=5000,
        response_time=0.456,
        redirect_count=0,
        redirect_chain=[],
        has_form=True,
        has_login_form=True,
        has_file_upload=False,
        has_error_page=False,
        technologies=[],
    ),
]
```

---

## 11. JS Endpoint Extractor

**File**: `reconforgex/modules/js_endpoint_extractor.py`  
**Class**: `JSEndpointExtractor`

### Purpose

Extracts API endpoints, routes, and URLs from JavaScript source code using 12+ pattern categories including API routes, HTTP requests, framework routes, WebSocket URLs, and gRPC services.

### Why It Exists

Modern web applications define their API routes and client-side logic in JavaScript. Extracting these endpoints reveals the application's API surface, including undocumented or hidden endpoints.

### Inputs

- `target` (str): Domain name
- `js_contents` (List[Tuple[str, str]]): List of (url, content) pairs from JS Collector
- No HTTP client needed (operates on collected data)

### Outputs

Returns a list of `JSEndpointResult` dataclass instances:

```python
@dataclass
class JSEndpointResult:
    url: str
    source_file: str
    endpoints: List[Endpoint]
    total_endpoints: int

@dataclass
class Endpoint:
    path: str
    method: Optional[str]  # GET, POST, PUT, DELETE, etc.
    pattern_type: str  # "api_route", "http_request", "framework_route", "websocket", "grpc"
    line_number: Optional[int]
    context: str
```

### Dependencies

- `JSCollector` (provides `js_contents`)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | Processing timeout |

### Statistics Produced

- `items_found`: Number of endpoints extracted
- `items_processed`: Number of JS files analyzed

### Pattern Categories

1. API routes: `/api/v1/`, `/api/v2/`, etc.
2. HTTP requests: `fetch()`, `XMLHttpRequest`, `axios.get`, `$.ajax`
3. Framework routes: Angular, React Router, Vue Router patterns
4. WebSocket URLs: `ws://`, `wss://`
5. gRPC services: `proto`, `service` definitions
6. GraphQL endpoints: `/graphql`, `gql` template literals
7. RESTful patterns: `/users/:id`, `/posts/{id}`
8. Static file paths: `/static/`, `/assets/`, `/images/`
9. Authentication endpoints: `/login`, `/logout`, `/auth`
10. Admin endpoints: `/admin`, `/dashboard`, `/manage`

### Example Output

```python
[
    JSEndpointResult(
        url="https://example.com",
        source_file="https://example.com/js/app.js",
        endpoints=[
            Endpoint(
                path="/api/v1/users",
                method="GET",
                pattern_type="api_route",
                line_number=42,
                context="fetch('/api/v1/users')",
            ),
            Endpoint(
                path="/api/v1/users",
                method="POST",
                pattern_type="api_route",
                line_number=45,
                context="axios.post('/api/v1/users', data)",
            ),
            Endpoint(
                path="/ws/notifications",
                method=None,
                pattern_type="websocket",
                line_number=100,
                context="new WebSocket('wss://example.com/ws/notifications')",
            ),
        ],
        total_endpoints=3,
    )
]
```

---

## 12. JS Secret Detector

**File**: `reconforgex/modules/js_secret_detector.py`  
**Class**: `JSSecretDetector`

### Purpose

Detects 30+ types of secrets including API keys, AWS keys, Google API keys, GitHub tokens, JWT tokens, Slack tokens, database URLs, private keys, and more. Severity-graded findings.

### Why It Exists

Hardcoded secrets in JavaScript are one of the most common and critical security findings. Client-side code is fully visible to users, making any embedded credentials immediately accessible to attackers.

### Inputs

- `target` (str): Domain name
- `js_contents` (List[Tuple[str, str]]): List of (url, content) pairs from JS Collector
- No HTTP client needed (operates on collected data)

### Outputs

Returns a list of `JSSecretResult` dataclass instances:

```python
@dataclass
class JSSecretResult:
    url: str
    source_file: str
    findings: List[SecretFinding]
    total_findings: int

@dataclass
class SecretFinding:
    type: str  # "aws_key", "google_api", "github_token", "jwt", "slack_token", etc.
    value: str  # (masked in output)
    severity: str  # "critical", "high", "medium", "low"
    line_number: Optional[int]
    context: str
    recommendation: str
```

### Dependencies

- `JSCollector` (provides `js_contents`)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | Processing timeout |

### Statistics Produced

- `items_found`: Number of secrets detected
- `items_processed`: Number of JS files analyzed

### Secret Types Detected (30+)

| Category | Types |
|----------|-------|
| Cloud | AWS Access Key, AWS Secret Key, Google API Key, Google OAuth, Azure Key, DigitalOcean Token |
| Code Repos | GitHub Token, GitLab Token, Bitbucket Token, Git credentials |
| Auth | JWT Token, OAuth Token, Bearer Token, Basic Auth |
| Communication | Slack Token, Discord Token, Telegram Token, Twilio Key |
| Database | MongoDB URI, MySQL URI, PostgreSQL URI, Redis URI, SQLite path |
| Encryption | Private Key (RSA, DSA, EC), PGP Key, SSH Key |
| Other | Firebase URL, Heroku API Key, Sentry DSN, New Relic Key, npm token, PyPI token |

### Example Output

```python
[
    JSSecretResult(
        url="https://example.com",
        source_file="https://example.com/js/config.js",
        findings=[
            SecretFinding(
                type="aws_access_key",
                value="AKIA************",
                severity="critical",
                line_number=15,
                context="AWS_ACCESS_KEY_ID: 'AKIA...'",
                recommendation="Rotate this AWS key immediately and remove it from client-side code",
            ),
            SecretFinding(
                type="jwt",
                value="eyJ***.***.***",
                severity="high",
                line_number=42,
                context="const token = 'eyJ...'",
                recommendation="JWT tokens should not be hardcoded in client-side code",
            ),
        ],
        total_findings=2,
    )
]
```

---

## 13. Risk Scoring Engine

**File**: `reconforgex/modules/risk_scoring.py`  
**Class**: `RiskScoringEngine`

### Purpose

Aggregates findings from all modules into a weighted risk score (0–100) with detailed breakdown by category.

### Why It Exists

Individual module findings are useful, but security teams need a single quantifiable measure of risk. The risk scoring engine provides this by combining findings from all analysis modules into a weighted score.

### Inputs

- `target` (str): Domain name
- `header_results` (List[Dict]): From Header Analyzer
- `tls_results` (List[Dict]): From TLS Inspector
- `csp_results` (List[Dict]): From CSP Analyzer
- `secret_results` (List[Dict]): From JS Secret Detector

### Outputs

Returns a list of `RiskScoreResult` dataclass instances:

```python
@dataclass
class RiskScoreResult:
    target: str
    overall_score: int  # 0-100 (higher = more secure)
    risk_level: str  # "critical", "high", "medium", "low", "minimal"
    category_scores: Dict[str, float]
    factors: List[RiskFactor]

@dataclass
class RiskFactor:
    name: str
    severity: str
    score_impact: float
    description: str
    recommendation: str
    source_module: str
```

### Dependencies

- Header Analyzer (provides header findings)
- Security Header Scanner (provides compliance scores)
- TLS Inspector (provides TLS results)
- CSP Analyzer (provides CSP findings)
- JS Secret Detector (provides secret findings)

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 30 | Processing timeout |

### Scoring Weights

| Category | Weight | Source |
|----------|--------|--------|
| Security Headers | 30% | Header Analyzer + Security Header Scanner |
| TLS Configuration | 25% | TLS Inspector |
| CSP Strength | 25% | CSP Analyzer |
| Secrets Exposure | 20% | JS Secret Detector |

### Risk Levels

| Score Range | Level | Color |
|-------------|-------|-------|
| 90–100 | Minimal | Green |
| 70–89 | Low | Blue |
| 50–69 | Medium | Yellow |
| 30–49 | High | Orange |
| 0–29 | Critical | Red |

### Example Output

```python
[
    RiskScoreResult(
        target="example.com",
        overall_score=62,
        risk_level="medium",
        category_scores={
            "security_headers": 45,
            "tls": 85,
            "csp": 55,
            "secrets": 70,
        },
        factors=[
            RiskFactor(
                name="Missing Content-Security-Policy",
                severity="high",
                score_impact=-15,
                description="CSP header is not set, increasing XSS risk",
                recommendation="Implement a CSP header",
                source_module="header_analyzer",
            ),
            RiskFactor(
                name="TLS 1.3 with valid certificate",
                severity="info",
                score_impact=10,
                description="TLS configuration is secure",
                recommendation="No action needed",
                source_module="tls_inspector",
            ),
        ],
    )
]