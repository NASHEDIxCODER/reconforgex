"""
Header Analyzer Module.

Analyzes HTTP response headers for security, information disclosure,
and configuration best practices. Built entirely in Python.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from reconforgex.modules.base import (
    BaseModule,
    ModuleConfiguration,
    ModuleHealth,
    ModuleMetadata,
    ModuleStatus,
)
from reconforgex.utils.http_client import AsyncHTTPClient, HTTPClientConfig
from reconforgex.logger import get_logger

log = get_logger()


@dataclass
class HeaderFinding:
    """A single header analysis finding."""
    header: str
    value: str
    severity: str  # info, low, medium, high, critical
    category: str  # security, info_disclosure, misconfiguration, best_practice
    description: str
    recommendation: str


@dataclass
class HeaderAnalysisResult:
    """Result of header analysis for a single target."""
    url: str
    status_code: int
    headers: Dict[str, str]
    findings: List[HeaderFinding]
    security_score: float  # 0.0 - 100.0


# Security headers that should be present
REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": "high",
        "description": "HTTP Strict Transport Security (HSTS) header missing. This allows downgrade attacks.",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        "pattern": r"max-age=\d+",
    },
    "content-security-policy": {
        "severity": "high",
        "description": "Content Security Policy (CSP) header missing. This increases risk of XSS attacks.",
        "recommendation": "Implement a Content-Security-Policy header appropriate for your application.",
    },
    "x-content-type-options": {
        "severity": "medium",
        "description": "X-Content-Type-Options header missing. Browser may MIME-sniff responses.",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header.",
        "expected": "nosniff",
    },
    "x-frame-options": {
        "severity": "medium",
        "description": "X-Frame-Options header missing. Page may be embedded in iframes (clickjacking risk).",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
    },
    "x-xss-protection": {
        "severity": "medium",
        "description": "X-XSS-Protection header missing. Older browsers may not have XSS filtering enabled.",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' header.",
    },
    "referrer-policy": {
        "severity": "low",
        "description": "Referrer-Policy header missing. Referrer information may be leaked.",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
    },
    "permissions-policy": {
        "severity": "low",
        "description": "Permissions-Policy header missing. Browser features may be abused.",
        "recommendation": "Add a Permissions-Policy header to restrict feature usage.",
    },
    "cache-control": {
        "severity": "medium",
        "description": "Cache-Control header missing or insecure. Sensitive data may be cached.",
        "recommendation": "Add 'Cache-Control: no-store, no-cache, must-revalidate' for sensitive pages.",
    },
    "cross-origin-opener-policy": {
        "severity": "medium",
        "description": "Cross-Origin-Opener-Policy header missing. Window may be targeted by cross-origin popups.",
        "recommendation": "Add 'Cross-Origin-Opener-Policy: same-origin-allow-popups' or 'same-origin'.",
    },
    "cross-origin-embedder-policy": {
        "severity": "medium",
        "description": "Cross-Origin-Embedder-Policy header missing. Cross-origin resources may be loaded.",
        "recommendation": "Add 'Cross-Origin-Embedder-Policy: require-corp' for enhanced isolation.",
    },
    "cross-origin-resource-policy": {
        "severity": "low",
        "description": "Cross-Origin-Resource-Policy header missing.",
        "recommendation": "Add 'Cross-Origin-Resource-Policy: same-origin' to restrict resource loading.",
    },
}

# Headers that may disclose sensitive information
INFO_DISCLOSURE_HEADERS = {
    "server": {
        "severity": "low",
        "description": "Server header discloses web server software version.",
        "recommendation": "Remove or obscure the Server header to prevent version fingerprinting.",
    },
    "x-powered-by": {
        "severity": "low",
        "description": "X-Powered-By header discloses underlying technology.",
        "recommendation": "Remove the X-Powered-By header to prevent technology fingerprinting.",
    },
    "x-aspnet-version": {
        "severity": "medium",
        "description": "ASP.NET version exposed, aiding targeted attacks.",
        "recommendation": "Remove the X-AspNet-Version header in web.config.",
    },
    "x-aspnetmvc-version": {
        "severity": "medium",
        "description": "ASP.NET MVC version exposed, aiding targeted attacks.",
        "recommendation": "Remove the X-AspNetMvc-Version header.",
    },
}


class HeaderAnalyzer(BaseModule):
    """Header Analyzer Module.

    Analyzes HTTP response headers for security misconfigurations,
    information disclosure, and compliance with best practices.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        super().__init__(config)
        self._client: Optional[AsyncHTTPClient] = None

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="Header Analyzer",
            description="Analyze HTTP response headers for security and configuration issues",
            version="1.0.0",
            author="ReconForgeX",
            tags=["http", "headers", "security", "analysis"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="Header Analyzer module operational",
            last_check=__import__("time").time(),
        )

    def _analyze_security_headers(self, headers: Dict[str, str]) -> List[HeaderFinding]:
        """Check for missing or misconfigured security headers."""
        findings: List[HeaderFinding] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, config in REQUIRED_SECURITY_HEADERS.items():
            value = headers_lower.get(header, "")
            if not value:
                findings.append(HeaderFinding(
                    header=header,
                    value="",
                    severity=config["severity"],
                    category="security",
                    description=config["description"],
                    recommendation=config["recommendation"],
                ))
            elif "pattern" in config:
                if not re.search(config["pattern"], value, re.IGNORECASE):
                    findings.append(HeaderFinding(
                        header=header,
                        value=value,
                        severity=config["severity"],
                        category="security",
                        description=f"{header} is present but may be misconfigured: {value}",
                        recommendation=config["recommendation"],
                    ))

        return findings

    def _analyze_info_disclosure(self, headers: Dict[str, str]) -> List[HeaderFinding]:
        """Check for headers that disclose sensitive information."""
        findings: List[HeaderFinding] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, config in INFO_DISCLOSURE_HEADERS.items():
            value = headers_lower.get(header, "")
            if value:
                findings.append(HeaderFinding(
                    header=header,
                    value=value,
                    severity=config["severity"],
                    category="info_disclosure",
                    description=config["description"],
                    recommendation=config["recommendation"],
                ))

        return findings

    def _analyze_cookies(self, headers: Dict[str, str]) -> List[HeaderFinding]:
        """Analyze Set-Cookie headers for security attributes."""
        findings: List[HeaderFinding] = []
        set_cookie = headers.get("set-cookie", "")

        if not set_cookie:
            return findings

        cookies = [c.strip() for c in set_cookie.split(";")]
        for cookie in cookies:
            if "=" not in cookie:
                continue
            cookie_name = cookie.split("=")[0].strip()

            if "httponly" not in set_cookie.lower():
                findings.append(HeaderFinding(
                    header="set-cookie",
                    value=cookie_name,
                    severity="medium",
                    category="security",
                    description=f"Cookie '{cookie_name}' missing HttpOnly flag. Accessible via JavaScript.",
                    recommendation="Add 'HttpOnly' flag to cookies containing session identifiers.",
                ))

            if "secure" not in set_cookie.lower():
                findings.append(HeaderFinding(
                    header="set-cookie",
                    value=cookie_name,
                    severity="medium",
                    category="security",
                    description=f"Cookie '{cookie_name}' missing Secure flag. Sent over unencrypted connections.",
                    recommendation="Add 'Secure' flag to cookies to ensure they're only sent over HTTPS.",
                ))

            if "samesite" not in set_cookie.lower():
                findings.append(HeaderFinding(
                    header="set-cookie",
                    value=cookie_name,
                    severity="low",
                    category="security",
                    description=f"Cookie '{cookie_name}' missing SameSite attribute.",
                    recommendation="Add 'SameSite=Lax' or 'SameSite=Strict' to prevent CSRF attacks.",
                ))

        return findings

    def _calculate_security_score(self, findings: List[HeaderFinding]) -> float:
        """Calculate a security score based on findings."""
        if not findings:
            return 100.0

        score = 100.0
        severity_penalties = {
            "critical": 25.0,
            "high": 15.0,
            "medium": 8.0,
            "low": 3.0,
            "info": 1.0,
        }

        for finding in findings:
            score -= severity_penalties.get(finding.severity, 5.0)

        return max(0.0, score)

    async def run(self, target: str, **kwargs: Any) -> List[HeaderAnalysisResult]:
        """Run header analysis against the target.

        Parameters
        ----------
        target:
            URL or domain to analyze.
        **kwargs:
            - urls: Optional list of full URLs

        Returns
        -------
        List[HeaderAnalysisResult]
            List of header analysis results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[HeaderAnalysisResult] = []

        urls: List[str] = kwargs.get("urls", [])
        if not urls:
            urls = [f"https://{target}", f"http://{target}"]
            urls = list(dict.fromkeys(urls))

        try:
            client = self._get_client()
            responses = await client.batch_get(urls)

            for response in responses:
                if response.error and response.status_code == 0:
                    continue

                findings: List[HeaderFinding] = []

                # Analyze all categories
                findings.extend(self._analyze_security_headers(response.headers))
                findings.extend(self._analyze_info_disclosure(response.headers))
                findings.extend(self._analyze_cookies(response.headers))

                score = self._calculate_security_score(findings)

                result = HeaderAnalysisResult(
                    url=response.url,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    findings=findings,
                    security_score=score,
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
                follow_redirects=False,
            )
            self._client = AsyncHTTPClient(http_config)
        return self._client
