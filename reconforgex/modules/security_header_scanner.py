"""
Security Header Scanner Module.

Dedicated scanner for security-related HTTP headers with detailed
compliance checking against OWASP recommendations.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from reconforgex.logger import get_logger
from reconforgex.modules.base import (
    BaseModule,
    ModuleConfiguration,
    ModuleHealth,
    ModuleMetadata,
    ModuleStatus,
)
from reconforgex.utils.http_client import AsyncHTTPClient, HTTPClientConfig

log = get_logger()


@dataclass
class SecurityHeaderCheck:
    """Result of a single security header check."""
    header: str
    present: bool
    value: str
    expected: str
    compliant: bool
    severity: str
    description: str
    reference: str


@dataclass
class SecurityHeaderResult:
    """Security header scan result for a single target."""
    url: str
    status_code: int
    checks: List[SecurityHeaderCheck]
    compliance_score: float
    total_headers: int
    present_headers: int
    compliant_headers: int


SECURITY_HEADER_CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "expected": "max-age=31536000; includeSubDomains",
        "severity": "high",
        "description": "HSTS enforces HTTPS connections and prevents downgrade attacks",
        "reference": "https://owasp.org/www-project-secure-headers/#strict-transport-security",
    },
    {
        "header": "Content-Security-Policy",
        "expected": "Present with appropriate directives",
        "severity": "high",
        "description": "CSP mitigates XSS and data injection attacks",
        "reference": "https://owasp.org/www-project-secure-headers/#content-security-policy",
    },
    {
        "header": "X-Content-Type-Options",
        "expected": "nosniff",
        "severity": "medium",
        "description": "Prevents MIME-type sniffing",
        "reference": "https://owasp.org/www-project-secure-headers/#x-content-type-options",
    },
    {
        "header": "X-Frame-Options",
        "expected": "DENY or SAMEORIGIN",
        "severity": "medium",
        "description": "Prevents clickjacking attacks",
        "reference": "https://owasp.org/www-project-secure-headers/#x-frame-options",
    },
    {
        "header": "X-XSS-Protection",
        "expected": "1; mode=block",
        "severity": "medium",
        "description": "Enables browser XSS filter",
        "reference": "https://owasp.org/www-project-secure-headers/#x-xss-protection",
    },
    {
        "header": "Referrer-Policy",
        "expected": "strict-origin-when-cross-origin",
        "severity": "low",
        "description": "Controls referrer information sent with requests",
        "reference": "https://owasp.org/www-project-secure-headers/#referrer-policy",
    },
    {
        "header": "Permissions-Policy",
        "expected": "Restrictive policy defined",
        "severity": "low",
        "description": "Controls browser feature access",
        "reference": "https://owasp.org/www-project-secure-headers/#permissions-policy",
    },
    {
        "header": "Cache-Control",
        "expected": "no-store, no-cache, must-revalidate",
        "severity": "medium",
        "description": "Prevents caching of sensitive data",
        "reference": "https://owasp.org/www-project-secure-headers/#cache-control",
    },
    {
        "header": "Cross-Origin-Opener-Policy",
        "expected": "same-origin-allow-popups or same-origin",
        "severity": "medium",
        "description": "Isolates cross-origin windows",
        "reference": "https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy",
    },
    {
        "header": "Cross-Origin-Embedder-Policy",
        "expected": "require-corp",
        "severity": "medium",
        "description": "Prevents loading cross-origin resources without explicit permission",
        "reference": "https://owasp.org/www-project-secure-headers/#cross-origin-embedder-policy",
    },
    {
        "header": "Cross-Origin-Resource-Policy",
        "expected": "same-origin",
        "severity": "low",
        "description": "Restricts resource loading to same-origin",
        "reference": "https://owasp.org/www-project-secure-headers/#cross-origin-resource-policy",
    },
    {
        "header": "Access-Control-Allow-Origin",
        "expected": "Restrictive (not '*')",
        "severity": "medium",
        "description": "CORS header controlling cross-origin access",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
    },
]


class SecurityHeaderScanner(BaseModule):
    """Security Header Scanner Module.

    Scans HTTP response headers for security-related headers and
    checks compliance with OWASP security header recommendations.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        super().__init__(config)
        self._client: Optional[AsyncHTTPClient] = None

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="Security Header Scanner",
            description="Scan HTTP response headers for OWASP security header compliance",
            version="1.0.0",
            author="ReconForgeX",
            tags=["security", "headers", "owasp", "compliance"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="Security Header Scanner module operational",
            last_check=__import__("time").time(),
        )

    def _check_header_compliance(
        self, headers: Dict[str, str], check: Dict[str, Any]
    ) -> SecurityHeaderCheck:
        """Check a single security header for compliance."""
        header_name = check["header"]
        value = headers.get(header_name.lower(), headers.get(header_name, ""))
        present = bool(value)

        compliant = False
        if present:
            expected = check["expected"].lower()
            value_lower = value.lower()
            if "present" in expected:
                compliant = True
            elif " or " in expected:
                options = [opt.strip() for opt in expected.split(" or ")]
                compliant = any(opt in value_lower for opt in options)
            else:
                compliant = expected in value_lower

        return SecurityHeaderCheck(
            header=header_name,
            present=present,
            value=value or "",
            expected=check["expected"],
            compliant=compliant,
            severity=check["severity"],
            description=check["description"],
            reference=check["reference"],
        )

    async def run(self, target: str, **kwargs: Any) -> List[SecurityHeaderResult]:
        """Run security header scan against the target.

        Parameters
        ----------
        target:
            URL or domain to scan.
        **kwargs:
            - urls: Optional list of full URLs

        Returns
        -------
        List[SecurityHeaderResult]
            List of security header scan results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[SecurityHeaderResult] = []

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

                checks = [
                    self._check_header_compliance(response.headers, check)
                    for check in SECURITY_HEADER_CHECKS
                ]

                total = len(checks)
                present = sum(1 for c in checks if c.present)
                compliant = sum(1 for c in checks if c.compliant)
                score = (compliant / total * 100) if total > 0 else 0.0

                result = SecurityHeaderResult(
                    url=response.url,
                    status_code=response.status_code,
                    checks=checks,
                    compliance_score=round(score, 1),
                    total_headers=total,
                    present_headers=present,
                    compliant_headers=compliant,
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
