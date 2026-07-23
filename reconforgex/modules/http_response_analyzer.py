"""
HTTP Response Analyzer Module.

Analyzes HTTP responses for status codes, redirects, content types,
and response patterns. Built entirely in Python.
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

from reconforgex.modules.base import (
    BaseModule,
    ModuleConfiguration,
    ModuleHealth,
    ModuleMetadata,
    ModuleStatus,
)
from reconforgex.utils.http_client import AsyncHTTPClient, HTTPClientConfig, HTTPResponse
from reconforgex.logger import get_logger

log = get_logger()


@dataclass
class StatusCodeDistribution:
    """Distribution of HTTP status codes."""
    code: int
    count: int
    percentage: float


@dataclass
class RedirectChain:
    """A redirect chain discovered."""
    initial_url: str
    final_url: str
    redirect_count: int
    chain: List[str]


@dataclass
class ResponseAnalysis:
    """Analysis of HTTP responses for a target."""
    url: str
    status_code: int
    content_type: str
    content_length: int
    response_time: float
    is_redirect: bool
    redirect_chain: List[str]
    redirect_count: int
    has_form: bool
    has_login: bool
    has_file_upload: bool
    technologies: List[str]
    server_header: str
    powered_by: str


@dataclass
class HTTPResponseAnalysisResult:
    """Complete HTTP response analysis result."""
    base_url: str
    responses: List[ResponseAnalysis]
    status_distribution: List[StatusCodeDistribution]
    total_requests: int
    success_count: int
    redirect_count: int
    error_count: int
    avg_response_time: float


class HTTPResponseAnalyzer(BaseModule):
    """HTTP Response Analyzer Module.

    Analyzes HTTP responses for patterns, status codes, redirects,
    and content characteristics.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        super().__init__(config)
        self._client: Optional[AsyncHTTPClient] = None

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="HTTP Response Analyzer",
            description="Analyze HTTP responses for status codes, redirects, content types, and patterns",
            version="1.0.0",
            author="ReconForgeX",
            tags=["http", "responses", "analysis", "redirects", "content"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="HTTP Response Analyzer module operational",
            last_check=__import__("time").time(),
        )

    def _analyze_response(self, http_resp: HTTPResponse) -> ResponseAnalysis:
        """Analyze a single HTTP response."""
        body_lower = http_resp.body.lower()

        has_form = bool("action=" in body_lower and "method=" in body_lower)
        has_login = any(term in body_lower for term in [
            "login", "signin", "log in", "sign in", "username", "password"
        ])
        has_file_upload = any(term in body_lower for term in [
            "enctype=\"multipart/form-data\"", "file", "upload"
        ])

        technologies: List[str] = []
        server = http_resp.headers.get("server", "")
        powered_by = http_resp.headers.get("x-powered-by", "")

        if server:
            technologies.append(server)
        if powered_by:
            technologies.append(powered_by)

        return ResponseAnalysis(
            url=http_resp.url,
            status_code=http_resp.status_code,
            content_type=http_resp.content_type or "",
            content_length=len(http_resp.body.encode()),
            response_time=http_resp.elapsed,
            is_redirect=http_resp.is_redirect,
            redirect_chain=[http_resp.url],
            redirect_count=0,
            has_form=has_form,
            has_login=has_login,
            has_file_upload=has_file_upload,
            technologies=list(dict.fromkeys(technologies)),
            server_header=server,
            powered_by=powered_by,
        )

    async def run(self, target: str, **kwargs: Any) -> List[HTTPResponseAnalysisResult]:
        """Run HTTP response analysis against the target.

        Parameters
        ----------
        target:
            URL or domain to analyze.
        **kwargs:
            - urls: Optional list of full URLs
            - paths: Optional list of paths to probe

        Returns
        -------
        List[HTTPResponseAnalysisResult]
            List of HTTP response analysis results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[HTTPResponseAnalysisResult] = []

        base_urls: List[str] = kwargs.get("urls", [])
        if not base_urls:
            base_urls = [f"https://{target}", f"http://{target}"]
            base_urls = list(dict.fromkeys(base_urls))

        paths = kwargs.get("paths", ["/"])
        all_urls = []
        for base_url in base_urls:
            for path in paths:
                all_urls.append(f"{base_url.rstrip('/')}/{path.lstrip('/')}")
        all_urls = list(dict.fromkeys(all_urls))

        try:
            client = self._get_client()
            responses = await client.batch_get(all_urls)
            analyzed: List[ResponseAnalysis] = []

            for resp in responses:
                if resp.error and resp.status_code == 0:
                    continue
                analysis = self._analyze_response(resp)
                analyzed.append(analysis)

            # Calculate status distribution
            status_codes: Dict[int, int] = {}
            for a in analyzed:
                status_codes[a.status_code] = status_codes.get(a.status_code, 0) + 1

            total = len(analyzed)
            distribution = [
                StatusCodeDistribution(
                    code=code,
                    count=count,
                    percentage=round(count / total * 100, 1) if total > 0 else 0.0,
                )
                for code, count in sorted(status_codes.items())
            ]

            success = sum(1 for a in analyzed if 200 <= a.status_code < 400)
            redirects = sum(1 for a in analyzed if 300 <= a.status_code < 400)
            errors = sum(1 for a in analyzed if a.status_code >= 400)
            avg_time = sum(a.response_time for a in analyzed) / max(len(analyzed), 1)

            result = HTTPResponseAnalysisResult(
                base_url=base_urls[0],
                responses=analyzed,
                status_distribution=distribution,
                total_requests=total,
                success_count=success,
                redirect_count=redirects,
                error_count=errors,
                avg_response_time=round(avg_time, 3),
            )
            results.append(result)
            self.stats.items_found += total

        except Exception as exc:
            self._record_error(str(exc))
        finally:
            self.stats.status = ModuleStatus.COMPLETED
            self.stats.end_time = __import__("time").time()
            self.stats.items_processed = len(results)

        return results

    def _get_client(self) -> AsyncHTTPClient:
        """Get or create HTTP client. Uses shared client when available."""
        if self._shared_client is not None:
            return self._shared_client
        if self._client is None:
            http_config = HTTPClientConfig(
                timeout=self.config.extra.get("timeout", 30),
                max_retries=self.config.extra.get("max_retries", 2),
                max_concurrency=self.config.extra.get("concurrency", 25),
                follow_redirects=True,
                max_redirects=10,
            )
            self._client = AsyncHTTPClient(http_config)
        return self._client
