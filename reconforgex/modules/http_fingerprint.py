"""
HTTP Fingerprinting Module.

Identifies web servers, frameworks, and technologies by analyzing
HTTP response headers, cookies, and other fingerprintable attributes.
Built entirely in Python - no external tool dependencies.
"""

import re
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from reconforgex.modules.base import (
    BaseModule,
    ModuleConfiguration,
    ModuleHealth,
    ModuleMetadata,
    ModuleStatistics,
    ModuleStatus,
)
from reconforgex.utils.http_client import AsyncHTTPClient, HTTPClientConfig, HTTPResponse
from reconforgex.logger import get_logger

log = get_logger()


# Known fingerprint patterns for common technologies
FINGERPRINT_PATTERNS: Dict[str, List[Dict[str, str]]] = {
    "nginx": [
        {"header": "server", "pattern": r"nginx"},
        {"header": "server", "pattern": r"openresty"},
    ],
    "apache": [
        {"header": "server", "pattern": r"apache", "flags": re.IGNORECASE},
    ],
    "cloudflare": [
        {"header": "server", "pattern": r"cloudflare", "flags": re.IGNORECASE},
        {"header": "cf-ray", "pattern": r"."},
    ],
    "cloudfront": [
        {"header": "x-amz-cf-id", "pattern": r"."},
        {"header": "x-amz-cf-pop", "pattern": r"."},
    ],
    "aws": [
        {"header": "x-amz-request-id", "pattern": r"."},
        {"header": "x-amz-id-2", "pattern": r"."},
    ],
    "google cloud": [
        {"header": "x-cloud-trace-context", "pattern": r"."},
    ],
    "azure": [
        {"header": "x-ms-request-id", "pattern": r"."},
    ],
    "fastly": [
        {"header": "x-served-by", "pattern": r".*fastly.*", "flags": re.IGNORECASE},
    ],
    "varnish": [
        {"header": "via", "pattern": r".*varnish.*", "flags": re.IGNORECASE},
        {"header": "x-varnish", "pattern": r"."},
    ],
    "iis": [
        {"header": "server", "pattern": r"microsoft-iis", "flags": re.IGNORECASE},
        {"header": "x-aspnet-version", "pattern": r"."},
        {"header": "x-powered-by", "pattern": r"ASP\.NET"},
    ],
    "php": [
        {"header": "x-powered-by", "pattern": r"php", "flags": re.IGNORECASE},
    ],
    "python": [
        {"header": "server", "pattern": r"python", "flags": re.IGNORECASE},
        {"header": "x-powered-by", "pattern": r"python", "flags": re.IGNORECASE},
    ],
    "django": [
        {"header": "server", "pattern": r"WSGIServer", "flags": re.IGNORECASE},
        {"header": "x-frame-options", "pattern": r"SAMEORIGIN"},
    ],
    "flask": [
        {"header": "server", "pattern": r"Werkzeug", "flags": re.IGNORECASE},
    ],
    "node.js": [
        {"header": "x-powered-by", "pattern": r"Express"},
        {"header": "x-powered-by", "pattern": r"node.js", "flags": re.IGNORECASE},
    ],
    "react": [
        {"cookie": "React-Dev-Tools", "pattern": r"."},
    ],
    "wordpress": [
        {"header": "x-powered-by", "pattern": r"WordPress", "flags": re.IGNORECASE},
        {"header": "link", "pattern": r"wp-json"},
    ],
    "laravel": [
        {"header": "x-powered-by", "pattern": r"Laravel", "flags": re.IGNORECASE},
    ],
    "ruby on rails": [
        {"header": "x-powered-by", "pattern": r"Phusion", "flags": re.IGNORECASE},
        {"header": "server", "pattern": r"WEBrick", "flags": re.IGNORECASE},
    ],
    "tomcat": [
        {"header": "server", "pattern": r"tomcat", "flags": re.IGNORECASE},
    ],
    "haproxy": [
        {"header": "x-served-by", "pattern": r"haproxy", "flags": re.IGNORECASE},
    ],
    "traefik": [
        {"header": "x-forwarded-proto", "pattern": r"."},
    ],
    "caddy": [
        {"header": "server", "pattern": r"caddy", "flags": re.IGNORECASE},
    ],
}

COMMON_COOKIE_PATTERNS: Dict[str, str] = {
    "PHPSESSID": "php",
    "JSESSIONID": "java/tomcat",
    "ASP.NET_SessionId": "asp.net",
    "connect.sid": "express.js",
    "laravel_session": "laravel",
    "wordpress_": "wordpress",
    "wp-settings": "wordpress",
}


@dataclass
class FingerprintResult:
    """Result of HTTP fingerprinting for a single target."""
    url: str
    status_code: int
    server: str
    technologies: List[str]
    headers: Dict[str, str]
    cookies: List[str]
    title: str
    content_type: str
    response_time: float


class HTTPFingerprinting(BaseModule):
    """HTTP Fingerprinting Module.

    Identifies web servers, frameworks, and technologies by analyzing
    HTTP response headers, cookies, and body content patterns.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        super().__init__(config)
        self._client: Optional[AsyncHTTPClient] = None

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="HTTP Fingerprinting",
            description="Identify web servers, frameworks, and technologies via HTTP response analysis",
            version="1.0.0",
            author="ReconForgeX",
            tags=["http", "fingerprint", "technology-detection", "reconnaissance"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="HTTP Fingerprinting module operational",
            last_check=__import__("time").time(),
        )

    def _extract_title(self, body: str) -> str:
        """Extract page title from HTML body."""
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:200]
        return ""

    def _match_technologies(self, headers: Dict[str, str], cookies: List[str], body: str) -> List[str]:
        """Match response data against known fingerprint patterns."""
        technologies: List[str] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for tech, patterns in FINGERPRINT_PATTERNS.items():
            matched = False
            for pattern_def in patterns:
                header_name = pattern_def.get("header", "")
                cookie_name = pattern_def.get("cookie", "")
                body_pattern = pattern_def.get("body", "")
                pattern = pattern_def.get("pattern", "")
                flags = pattern_def.get("flags", 0)

                if header_name:
                    val = headers_lower.get(header_name.lower(), "")
                    if val and re.search(pattern, val, flags):
                        matched = True
                        break
                elif cookie_name:
                    for cookie in cookies:
                        if cookie.lower().startswith(cookie_name.lower()):
                            matched = True
                            break
                    if matched:
                        break
                elif body_pattern:
                    if re.search(pattern, body, flags):
                        matched = True
                        break

            if matched:
                technologies.append(tech)

        # Check cookie-based fingerprinting
        for cookie in cookies:
            cookie_name = cookie.split("=")[0]
            for pattern, tech in COMMON_COOKIE_PATTERNS.items():
                if cookie_name.lower().startswith(pattern.lower()):
                    if tech not in technologies:
                        technologies.append(tech)

        return sorted(set(technologies))

    async def run(self, target: str, **kwargs: Any) -> List[FingerprintResult]:
        """Run HTTP fingerprinting against the target.

        Parameters
        ----------
        target:
            URL or domain to fingerprint.
        **kwargs:
            - urls: Optional list of full URLs to probe
            - headers: Optional custom headers

        Returns
        -------
        List[FingerprintResult]
            List of fingerprint results for each probed URL.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[FingerprintResult] = []

        urls: List[str] = kwargs.get("urls", [])
        if not urls:
            urls = [f"https://{target}", f"http://{target}"]
            urls = list(dict.fromkeys(urls))  # deduplicate preserve order

        try:
            client = self._get_client()
            responses = await client.batch_get(urls)

            for response in responses:
                if response.error and response.status_code == 0:
                    continue

                cookies = []
                set_cookie = response.headers.get("set-cookie", "")
                if set_cookie:
                    cookies = [c.strip() for c in set_cookie.split(";")]

                technologies = self._match_technologies(
                    response.headers, cookies, response.body
                )

                result = FingerprintResult(
                    url=response.url,
                    status_code=response.status_code,
                    server=response.headers.get("server", ""),
                    technologies=technologies,
                    headers=dict(response.headers),
                    cookies=cookies,
                    title=self._extract_title(response.body),
                    content_type=response.content_type or "",
                    response_time=response.elapsed,
                )
                results.append(result)
                self.stats.items_found += 1

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
                max_concurrency=self.config.extra.get("concurrency", 50),
                follow_redirects=True,
            )
            self._client = AsyncHTTPClient(http_config)
        return self._client
