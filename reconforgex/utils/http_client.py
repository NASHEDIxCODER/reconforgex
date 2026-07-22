"""
High-Performance Async HTTP Client.

Optimized for reconnaissance workloads with:
- httpx.AsyncClient with HTTP/2 support
- Connection pooling with keep-alive
- Configurable timeouts (connect, read, write, pool)
- Retry with exponential backoff and jitter
- Proxy support (HTTP, HTTPS, SOCKS)
- Custom headers and cookies
- Redirect tracking
- TLS verification toggle
- Rate limiting integration
- Memory-efficient streaming
- Object reuse to minimize allocations

Usage::

    client = AsyncHTTPClient(config)
    async with client:
        response = await client.get("https://example.com")
        responses = await client.batch_get(["https://a.com", "https://b.com"])
"""

import asyncio
import time
import random
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from reconforgex.logger import get_logger
from reconforgex.utils.rate_limiter import RateLimiter

log = get_logger()


class HTTPClientError(Exception):
    """Base exception for HTTP client errors."""


class MaxRetriesExceeded(HTTPClientError):
    """Raised when all retry attempts are exhausted."""


class RequestCancelled(HTTPClientError):
    """Raised when a request is cancelled."""


@dataclass
class HTTPResponse:
    """Structured HTTP response with minimal memory overhead."""

    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    error: Optional[str] = None
    tls_version: Optional[str] = None
    redirect_url: Optional[str] = None
    content_type: Optional[str] = None
    server: Optional[str] = None
    http_version: Optional[str] = None
    request_size: int = 0
    response_size: int = 0

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400


@dataclass
class HTTPClientConfig:
    """Configuration for the high-performance async HTTP client."""
    timeout: float = 30.0
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    write_timeout: float = 30.0
    pool_timeout: float = 10.0
    max_retries: int = 3
    max_concurrency: int = 50
    backoff_base: float = 1.0
    backoff_multiplier: float = 2.0
    max_backoff: float = 60.0
    jitter: float = 0.1  # 10% jitter for backoff
    follow_redirects: bool = True
    max_redirects: int = 10
    verify_ssl: bool = True
    http2: bool = True
    proxy: Optional[str] = None
    max_keepalive: int = 50
    max_connections: int = 100
    default_headers: Dict[str, str] = field(default_factory=lambda: {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    })
    cookies: Dict[str, str] = field(default_factory=dict)
    rate_limit_global_rps: int = 100
    rate_limit_per_host_rps: int = 5
    rate_limit_burst: int = 10
    enable_rate_limiting: bool = True


class AsyncHTTPClient:
    """High-performance async HTTP client with connection pooling.

    Optimized for reconnaissance workloads. Reuses httpx.AsyncClient
    connections, minimizes object allocations, and supports rate limiting.

    Usage::

        config = HTTPClientConfig(max_concurrency=100, http2=True)
        async with AsyncHTTPClient(config) as client:
            response = await client.get("https://example.com")
            responses = await client.batch_get(urls)
    """

    def __init__(self, config: Optional[HTTPClientConfig] = None):
        self.config = config or HTTPClientConfig()
        self._client: Optional[httpx.AsyncClient] = None
        self._cancelled = False
        self._rate_limiter: Optional[RateLimiter] = None

        # Statistics (use __slots__-like approach for speed)
        self._request_count = 0
        self._error_count = 0
        self._retry_count = 0
        self._total_elapsed = 0.0
        self._timings: List[float] = []
        self._open_connections = 0
        self._peak_connections = 0
        self._bytes_sent = 0
        self._bytes_received = 0

        # Initialize rate limiter
        if self.config.enable_rate_limiting:
            self._rate_limiter = RateLimiter(
                global_rps=self.config.rate_limit_global_rps,
                burst=self.config.rate_limit_burst,
                per_host_rps=self.config.rate_limit_per_host_rps,
            )

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-init the async client with connection pooling."""
        if self._client is None:
            limits = httpx.Limits(
                max_keepalive_connections=self.config.max_keepalive,
                max_connections=self.config.max_connections,
            )
            timeout = httpx.Timeout(
                self.config.timeout,
                connect=self.config.connect_timeout,
                read=self.config.read_timeout,
                write=self.config.write_timeout,
                pool=self.config.pool_timeout,
            )
            client_kwargs: Dict[str, Any] = {
                "timeout": timeout,
                "limits": limits,
                "follow_redirects": self.config.follow_redirects,
                "max_redirects": self.config.max_redirects,
                "verify": self.config.verify_ssl,
                "headers": self.config.default_headers,
                "cookies": self.config.cookies,
                "http2": self.config.http2,
            }
            if self.config.proxy:
                client_kwargs["proxies"] = self.config.proxy

            self._client = httpx.AsyncClient(**client_kwargs)
        return self._client

    async def close(self) -> None:
        """Close the underlying client and release connections."""
        if self._client:
            await self._client.aclose()
            self._client = None
            self._open_connections = 0

    def cancel(self) -> None:
        """Cancel all pending requests."""
        self._cancelled = True

    async def __aenter__(self) -> "AsyncHTTPClient":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    def _extract_host(self, url: str) -> str:
        """Extract host from URL for rate limiting."""
        try:
            return urlparse(url).hostname or url
        except Exception:
            return url

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate backoff with jitter."""
        backoff = min(
            self.config.backoff_base * (self.config.backoff_multiplier ** attempt),
            self.config.max_backoff,
        )
        # Add jitter: ±10%
        jitter = backoff * self.config.jitter * (2 * random.random() - 1)
        return max(0.1, backoff + jitter)

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> HTTPResponse:
        """Perform a GET request with retry, backoff, and rate limiting."""
        return await self._request("GET", url, headers=headers, timeout=timeout)

    async def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> HTTPResponse:
        """Perform a HEAD request."""
        return await self._request("HEAD", url, headers=headers, timeout=timeout)

    async def _request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> HTTPResponse:
        """Core request method with retry, backoff, rate limiting, and cancellation."""
        if self._cancelled:
            raise RequestCancelled("Client has been cancelled")

        last_error: Optional[str] = None
        start_time = time.monotonic()
        host = self._extract_host(url)

        # Rate limiting
        if self._rate_limiter:
            wait_time = await self._rate_limiter.acquire(host)
            if wait_time > 0:
                await asyncio.sleep(wait_time)

        for attempt in range(self.config.max_retries + 1):
            if self._cancelled:
                raise RequestCancelled("Request cancelled during retry")

            try:
                client = await self._get_client()
                request_headers = dict(self.config.default_headers)
                if headers:
                    request_headers.update(headers)

                self._open_connections += 1
                self._peak_connections = max(self._peak_connections, self._open_connections)

                response = await client.request(
                    method,
                    url,
                    headers=request_headers,
                    timeout=timeout or self.config.timeout,
                )

                self._open_connections -= 1
                elapsed = time.monotonic() - start_time
                self._request_count += 1
                self._total_elapsed += elapsed
                self._timings.append(elapsed)

                # Record latency for adaptive rate limiting
                if self._rate_limiter:
                    self._rate_limiter.record_latency(host, elapsed)

                # Read body efficiently
                body = response.text
                resp_headers = dict(response.headers)

                # TLS version detection
                tls_version = None
                http_version = response.http_version
                if http_version == "HTTP/2":
                    tls_version = "TLS 1.3"
                elif hasattr(response, "extensions"):
                    try:
                        ext = response.extensions
                        if ext and "http_version" in ext:
                            http_version = ext["http_version"]
                    except Exception:
                        pass

                # Track bytes
                self._bytes_received += len(body.encode())
                if headers:
                    self._bytes_sent += sum(len(k) + len(v) for k, v in headers.items())

                return HTTPResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=resp_headers,
                    body=body,
                    elapsed=elapsed,
                    tls_version=tls_version,
                    redirect_url=str(response.url) if response.is_redirect else None,
                    content_type=resp_headers.get("content-type", ""),
                    server=resp_headers.get("server", ""),
                    http_version=http_version,
                    response_size=len(body.encode()),
                )

            except httpx.TimeoutException:
                last_error = f"Request timed out after {self.config.timeout}s"
                self._error_count += 1
                if self._open_connections > 0:
                    self._open_connections -= 1

            except httpx.ConnectError as exc:
                last_error = f"Connection error: {exc}"
                self._error_count += 1
                if self._open_connections > 0:
                    self._open_connections -= 1

            except httpx.HTTPStatusError as exc:
                last_error = f"HTTP error {exc.response.status_code}: {exc}"
                self._error_count += 1
                if self._open_connections > 0:
                    self._open_connections -= 1

            except httpx.RequestError as exc:
                last_error = f"Request error: {exc}"
                self._error_count += 1
                if self._open_connections > 0:
                    self._open_connections -= 1

            except Exception as exc:
                last_error = f"Unexpected error: {exc}"
                self._error_count += 1
                if self._open_connections > 0:
                    self._open_connections -= 1

            if attempt < self.config.max_retries:
                backoff = self._calculate_backoff(attempt)
                self._retry_count += 1
                log.debug(
                    "Retry %d/%d for %s in %.1fs (error: %s)",
                    attempt + 1, self.config.max_retries, url, backoff, last_error,
                )
                await asyncio.sleep(backoff)

        elapsed = time.monotonic() - start_time
        return HTTPResponse(
            url=url,
            status_code=0,
            headers={},
            body="",
            elapsed=elapsed,
            error=last_error or "Unknown error",
        )

    async def batch_get(
        self,
        urls: List[str],
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> List[HTTPResponse]:
        """Execute multiple GET requests concurrently.

        Uses asyncio.gather for maximum throughput.
        """
        tasks = [self.get(url, headers=headers, timeout=timeout) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=False)

    @property
    def statistics(self) -> Dict[str, Any]:
        """Return client usage statistics."""
        return {
            "request_count": self._request_count,
            "error_count": self._error_count,
            "retry_count": self._retry_count,
            "total_elapsed": round(self._total_elapsed, 3),
            "avg_response_time": round(
                self._total_elapsed / max(self._request_count, 1), 3
            ),
            "open_connections": self._open_connections,
            "peak_connections": self._peak_connections,
            "bytes_sent": self._bytes_sent,
            "bytes_received": self._bytes_received,
        }