"""
Async HTTP client with retry, backoff, timeout, and cancellation support.

Uses ``httpx.AsyncClient`` with semaphore-based concurrency control,
exponential backoff, and comprehensive telemetry.
"""

import asyncio
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

import httpx

from reconforgex.logger import get_logger

log = get_logger()


class HTTPClientError(Exception):
    """Base exception for HTTP client errors."""
    pass


class MaxRetriesExceeded(HTTPClientError):
    """Raised when all retry attempts are exhausted."""
    pass


class RequestCancelled(HTTPClientError):
    """Raised when a request is cancelled."""
    pass


@dataclass
class HTTPResponse:
    """Structured HTTP response."""
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
    """Configuration for the async HTTP client."""
    timeout: float = 30.0
    max_retries: int = 3
    max_concurrency: int = 50
    backoff_base: float = 1.0
    backoff_multiplier: float = 2.0
    max_backoff: float = 60.0
    follow_redirects: bool = True
    max_redirects: int = 10
    verify_ssl: bool = True
    default_headers: Dict[str, str] = field(default_factory=lambda: {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    cookies: Dict[str, str] = field(default_factory=dict)


class AsyncHTTPClient:
    """Async HTTP client with retry, backoff, and concurrency control.

    Usage::

        client = AsyncHTTPClient(config)
        response = await client.get("https://example.com")
        responses = await client.batch_get(["https://a.com", "https://b.com"])
    """

    def __init__(self, config: Optional[HTTPClientConfig] = None):
        self.config = config or HTTPClientConfig()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)
        self._client: Optional[httpx.AsyncClient] = None
        self._cancelled = False
        self._request_count = 0
        self._error_count = 0
        self._retry_count = 0
        self._total_elapsed = 0.0
        self._timings: List[float] = []

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-init the async client."""
        if self._client is None:
            limits = httpx.Limits(
                max_keepalive_connections=self.config.max_concurrency,
                max_connections=self.config.max_concurrency * 2,
            )
            timeout = httpx.Timeout(self.config.timeout)
            self._client = httpx.AsyncClient(
                timeout=timeout,
                limits=limits,
                follow_redirects=self.config.follow_redirects,
                max_redirects=self.config.max_redirects,
                verify=self.config.verify_ssl,
                headers=self.config.default_headers,
                cookies=self.config.cookies,
                http2=True,
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def cancel(self) -> None:
        """Cancel all pending requests."""
        self._cancelled = True

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> HTTPResponse:
        """Perform a GET request with retry and backoff."""
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
        """Core request method with retry, backoff, and cancellation."""
        if self._cancelled:
            raise RequestCancelled("Client has been cancelled")

        async with self._semaphore:
            last_error: Optional[str] = None
            start_time = time.monotonic()

            for attempt in range(self.config.max_retries + 1):
                if self._cancelled:
                    raise RequestCancelled("Request cancelled during retry")

                try:
                    client = await self._get_client()
                    request_headers = {**self.config.default_headers}
                    if headers:
                        request_headers.update(headers)

                    response = await client.request(
                        method,
                        url,
                        headers=request_headers,
                        timeout=timeout or self.config.timeout,
                    )

                    elapsed = time.monotonic() - start_time
                    self._request_count += 1
                    self._total_elapsed += elapsed
                    self._timings.append(elapsed)

                    body = response.text
                    resp_headers = dict(response.headers)

                    tls_version = None
                    if response.extensions.get("http_version") == "HTTP/2":
                        tls_version = "TLS 1.3"
                    elif hasattr(response, "extensions") and response.extensions.get("network_stream"):
                        try:
                            ssl_obj = response.extensions["network_stream"].get_extra_info("ssl_object")
                            if ssl_obj:
                                tls_version = ssl_obj.version()
                        except Exception:
                            pass

                    return HTTPResponse(
                        url=str(response.url),
                        status_code=response.status_code,
                        headers=resp_headers,
                        body=body,
                        elapsed=elapsed,
                        tls_version=tls_version,
                        redirect_url=str(response.url) if response.is_redirect else None,
                        content_type=resp_headers.get("content-type", ""),
                    )

                except httpx.TimeoutException:
                    last_error = f"Request timed out after {self.config.timeout}s"
                    self._error_count += 1
                except httpx.ConnectError as exc:
                    last_error = f"Connection error: {exc}"
                    self._error_count += 1
                except httpx.HTTPStatusError as exc:
                    last_error = f"HTTP error {exc.response.status_code}: {exc}"
                    self._error_count += 1
                except httpx.RequestError as exc:
                    last_error = f"Request error: {exc}"
                    self._error_count += 1
                except Exception as exc:
                    last_error = f"Unexpected error: {exc}"
                    self._error_count += 1

                if attempt < self.config.max_retries:
                    backoff = min(
                        self.config.backoff_base * (self.config.backoff_multiplier ** attempt),
                        self.config.max_backoff,
                    )
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
        """Execute multiple GET requests concurrently."""
        tasks = [self.get(url, headers=headers, timeout=timeout) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=False)

    @property
    def statistics(self) -> Dict[str, Any]:
        """Return client usage statistics."""
        return {
            "request_count": self._request_count,
            "error_count": self._error_count,
            "retry_count": self._retry_count,
            "total_elapsed": self._total_elapsed,
            "avg_response_time": self._total_elapsed / max(self._request_count, 1),
        }