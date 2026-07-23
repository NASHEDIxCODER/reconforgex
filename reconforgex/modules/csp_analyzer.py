"""
CSP Analyzer Module.

Analyzes Content-Security-Policy headers for weaknesses, missing directives,
and bypass opportunities. Built entirely in Python.
"""

import re
from typing import Any, Dict, List, Optional, Set
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
class CSPDirective:
    """A single CSP directive and its values."""
    name: str
    values: List[str]
    is_present: bool
    is_unsafe: bool
    notes: List[str]


@dataclass
class CSPAnalysis:
    """CSP analysis result for a single target."""
    url: str
    policy: Optional[str]
    directives: List[CSPDirective]
    weaknesses: List[str]
    strengths: List[str]
    bypass_possibilities: List[str]
    score: int  # 0-100
    is_report_only: bool


# Known CSP bypass and weakness patterns
UNSAFE_DIRECTIVES = {
    "'unsafe-inline'": "Allows inline scripts/styles, increasing XSS risk",
    "'unsafe-eval'": "Allows eval(), increasing code injection risk",
    "*": "Wildcard allows any origin, defeating CSP purpose",
    "data:": "Allows data: URIs, can bypass CSP for images",
    "https:": "Allows all HTTPS origins, too permissive",
    "http:": "Allows all HTTP origins, extremely dangerous",
}

WEAK_HOST_PATTERNS = [
    (r"\.pastebin\.com", "Pastebin can host arbitrary content for bypass"),
    (r"\.github\.io", "GitHub Pages can host arbitrary content"),
    (r"\.jsdelivr\.net", "CDN with user content capabilities"),
    (r"cdn\.rawgit\.com", "Deprecated CDN that allowed arbitrary content"),
    (r"\.cloudfront\.net", "AWS CloudFront with potential user content"),
    (r"\.amazonaws\.com", "AWS S3 buckets may host user content"),
    (r"\.blob\.core\.windows\.net", "Azure Blob Storage may host user content"),
    (r"\.firebaseapp\.com", "Firebase hosting allows user content"),
    (r"\.netlify\.app", "Netlify allows user content"),
    (r"\.vercel\.app", "Vercel allows user content"),
    (r"\.pages\.dev", "Cloudflare Pages allows user content"),
]


class CSPAnalyzer(BaseModule):
    """CSP Analyzer Module.

    Analyzes Content-Security-Policy headers for security weaknesses,
    misconfigurations, and potential bypass vectors.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        super().__init__(config)
        self._client: Optional[AsyncHTTPClient] = None

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="CSP Analyzer",
            description="Analyze Content-Security-Policy headers for weaknesses and bypass vectors",
            version="1.0.0",
            author="ReconForgeX",
            tags=["csp", "content-security-policy", "security", "xss", "headers"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="CSP Analyzer module operational",
            last_check=__import__("time").time(),
        )

    def _parse_csp(self, policy: str) -> Dict[str, List[str]]:
        """Parse a CSP policy string into directives."""
        directives: Dict[str, List[str]] = {}
        # Remove header name if present
        policy = re.sub(r'^(?:content-security-policy|content-security-policy-report-only)\s*:\s*',
                        '', policy, flags=re.IGNORECASE)

        parts = policy.split(";")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directive = tokens[0].lower()
                values = tokens[1:] if len(tokens) > 1 else ["*"]
                directives[directive] = values
        return directives

    def _analyze_directive(self, name: str, values: List[str]) -> CSPDirective:
        """Analyze a single directive for security issues."""
        notes: List[str] = []
        is_unsafe = False

        for value in values:
            lower_val = value.lower()

            # Check for unsafe keywords
            if lower_val in UNSAFE_DIRECTIVES:
                notes.append(UNSAFE_DIRECTIVES[lower_val])
                is_unsafe = True

            # Check for weak hosts
            for pattern, note in WEAK_HOST_PATTERNS:
                if re.search(pattern, lower_val):
                    notes.append(f"Potentially weak host: {value} - {note}")
                    is_unsafe = True

            # Check for missing scheme
            if "." in value and "://" not in value and value not in ("'none'", "'self'"):
                notes.append(f"Missing scheme in {value} - could allow both HTTP and HTTPS")

        return CSPDirective(
            name=name,
            values=values,
            is_present=True,
            is_unsafe=is_unsafe,
            notes=notes,
        )

    def _evaluate_csp(self, directives: Dict[str, List[str]], is_report_only: bool) -> CSPAnalysis:
        """Evaluate a CSP policy for overall security posture."""
        analyzed_directives: List[CSPDirective] = []
        weaknesses: List[str] = []
        strengths: List[str] = []
        bypasses: List[str] = []

        # Analyze each directive
        for name, values in directives.items():
            directive = self._analyze_directive(name, values)
            analyzed_directives.append(directive)

        # Check for essential directives
        directive_names = {d.name for d in analyzed_directives}

        if "default-src" not in directive_names:
            weaknesses.append("No default-src directive - unspecified directives fallback to unrestricted")
        else:
            default_src = next(d for d in analyzed_directives if d.name == "default-src")
            if "'none'" in default_src.values:
                strengths.append("default-src set to 'none' - very restrictive baseline")

        if "script-src" not in directive_names:
            weaknesses.append("No script-src directive - scripts are controlled by default-src or unrestricted")
        elif "'strict-dynamic'" in str(directives.get("script-src", [])):
            strengths.append("Uses 'strict-dynamic' - modern CSP approach with nonces/hashes")
        elif "'nonce-" in str(directives.get("script-src", [])):
            strengths.append("Uses nonce-based CSP for scripts")
        elif "'unsafe-inline'" in str(directives.get("script-src", [])):
            weaknesses.append("script-src allows 'unsafe-inline' - high XSS risk")

        if "object-src" not in directive_names:
            weaknesses.append("No object-src directive - plugins may be exploitable")

        if "base-uri" not in directive_names:
            weaknesses.append("No base-uri directive - base tag injection possible")

        if "frame-ancestors" not in directive_names:
            weaknesses.append("No frame-ancestors directive - clickjacking protection relies on X-Frame-Options")

        if "report-uri" not in directive_names and "report-to" not in directive_names:
            weaknesses.append("No reporting configured - CSP violations won't be reported")
        else:
            strengths.append("CSP violation reporting configured")

        if "form-action" not in directive_names:
            weaknesses.append("No form-action directive - forms can submit to any origin")

        if is_report_only:
            weaknesses.append("CSP is in report-only mode - does not enforce policy")

        # Check for bypass possibilities
        for directive in analyzed_directives:
            if "jsonp" in str(directive.values).lower():
                bypasses.append("JSONP endpoints in script-src enable CSP bypass")
            if directive.name in ("script-src", "style-src"):
                for val in directive.values:
                    if val.startswith("https://") and val.count(".") >= 2:
                        bypasses.append(f"HTTPS host {val} could enable CDN-based bypass")

        # Calculate score
        score = 100
        score -= len(weaknesses) * 10
        if is_report_only:
            score -= 20
        for bypass in bypasses:
            score -= 5
        score = max(0, min(100, score))

        return CSPAnalysis(
            url="",
            policy="; ".join(f"{k} {' '.join(v)}" for k, v in directives.items()),
            directives=analyzed_directives,
            weaknesses=weaknesses,
            strengths=strengths,
            bypass_possibilities=bypasses,
            score=score,
            is_report_only=is_report_only,
        )

    async def run(self, target: str, **kwargs: Any) -> List[CSPAnalysis]:
        """Run CSP analysis against the target.

        Parameters
        ----------
        target:
            URL or domain to analyze.
        **kwargs:
            - urls: Optional list of full URLs

        Returns
        -------
        List[CSPAnalysis]
            List of CSP analysis results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[CSPAnalysis] = []

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

                # Look for CSP headers
                csp_header = ""
                is_report_only = False

                for header_name, header_value in response.headers.items():
                    lower_name = header_name.lower()
                    if lower_name == "content-security-policy":
                        csp_header = header_value
                        is_report_only = False
                        break
                    elif lower_name == "content-security-policy-report-only":
                        csp_header = header_value
                        is_report_only = True
                        break

                if csp_header:
                    directives = self._parse_csp(csp_header)
                    analysis = self._evaluate_csp(directives, is_report_only)
                    analysis.url = response.url
                else:
                    analysis = CSPAnalysis(
                        url=response.url,
                        policy=None,
                        directives=[],
                        weaknesses=["No Content-Security-Policy header found"],
                        strengths=[],
                        bypass_possibilities=[],
                        score=0,
                        is_report_only=False,
                    )

                results.append(analysis)
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
