"""
JS Secret Detector Module.

Detects potential secrets, API keys, tokens, and credentials in
JavaScript source code. Built entirely in Python.
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
from reconforgex.logger import get_logger

log = get_logger()


@dataclass
class SecretFinding:
    """A potential secret discovered in JavaScript."""
    type: str
    value: str
    source_url: str
    context: str
    severity: str  # critical, high, medium, low
    pattern_used: str


@dataclass
class SecretDetectionResult:
    """Secret detection result for a source."""
    source_url: str
    findings: List[SecretFinding]
    total_found: int


# Comprehensive patterns for secret detection
SECRET_PATTERNS = [
    # API Keys
    (r"(?i)(['\"]?(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)['\"]?\s*(?::|=|=>)\s*['\"]?)([a-zA-Z0-9_\-+=/]{16,64})['\"]?", "API Key", "high"),
    # AWS Keys
    (r"(?i)(AKIA[0-9A-Z]{16})", "AWS Access Key ID", "critical"),
    (r"(?i)(['\"]?(?:aws_secret|aws[_-]?secret[_-]?key|secret[_-]?access[_-]?key)['\"]?\s*(?::|=|=>)\s*['\"]?)([a-zA-Z0-9/+=]{40})['\"]?", "AWS Secret Key", "critical"),
    # Google API Keys
    (r"(?i)(AIza[0-9A-Za-z\-_]{35})", "Google API Key", "high"),
    # GitHub Tokens
    (r"(?i)(ghp_[0-9a-zA-Z]{36})", "GitHub Personal Access Token", "critical"),
    (r"(?i)(gho_[0-9a-zA-Z]{36})", "GitHub OAuth Token", "critical"),
    (r"(?i)(ghu_[0-9a-zA-Z]{36})", "GitHub User Token", "critical"),
    (r"(?i)(ghs_[0-9a-zA-Z]{36})", "GitHub Server Token", "critical"),
    # JWT Tokens
    (r"(?i)(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)", "JWT Token", "high"),
    # Slack Tokens
    (r"(?i)(xox[baprs]-[0-9a-zA-Z\-]{10,48})", "Slack Token", "critical"),
    # Facebook Tokens
    (r"(?i)(EAACEdEose0cBA[0-9a-zA-Z]+)", "Facebook Access Token", "high"),
    # Twitter Tokens
    (r"(?i)(['\"]?(?:twitter[_-]?(?:api|secret|token|key))['\"]?\s*(?::|=|=>)\s*['\"]?)([a-zA-Z0-9\-_]{20,60})['\"]?", "Twitter API Token", "high"),
    # Generic Bearer Tokens
    (r"(?i)(['\"]?authorization['\"]?\s*(?::|=|=>)\s*['\"]?bearer\s+[a-zA-Z0-9\-_\.=+/]{20,200})['\"]?", "Bearer Token", "critical"),
    # Basic Auth
    (r"(?i)(['\"]?authorization['\"]?\s*(?::|=|=>)\s*['\"]?basic\s+[a-zA-Z0-9=+/]{10,100})['\"]?", "Basic Auth Token", "critical"),
    # Database URLs
    (r"(?i)((?:postgres|mysql|mongodb|redis|amqp|mqtt)://[a-zA-Z0-9\-_.]+:[a-zA-Z0-9\-_./~%]+@[a-zA-Z0-9\-_.]+:\d+)", "Database URL", "critical"),
    # Private Keys
    (r"-----BEGIN\s?(?:RSA\s)?PRIVATE\s?KEY-----", "Private Key", "critical"),
    (r"-----BEGIN\s?EC\s?PRIVATE\s?KEY-----", "EC Private Key", "critical"),
    (r"-----BEGIN\s?DSA\s?PRIVATE\s?KEY-----", "DSA Private Key", "critical"),
    (r"-----BEGIN\s?OPENSSH\s?PRIVATE\s?KEY-----", "OpenSSH Private Key", "critical"),
    # Heroku API Keys
    (r"(?i)(heroku[a-zA-Z0-9\-_]{20,40})", "Heroku API Key", "high"),
    # Stripe Keys
    (r"(?i)(sk_live_[0-9a-zA-Z]{24})", "Stripe Live Secret Key", "critical"),
    (r"(?i)(pk_live_[0-9a-zA-Z]{24})", "Stripe Live Publishable Key", "high"),
    (r"(?i)(sk_test_[0-9a-zA-Z]{24})", "Stripe Test Secret Key", "medium"),
    # Twilio Keys
    (r"(?i)(SK[a-zA-Z0-9\-_]{32})", "Twilio API Key", "high"),
    # SendGrid Keys
    (r"(?i)(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})", "SendGrid API Key", "high"),
    # Mailgun Keys
    (r"(?i)(key-[0-9a-zA-Z]{32})", "Mailgun API Key", "high"),
    # Password fields
    (r"(?i)(['\"]?(?:password|passwd|pwd|secret)['\"]?\s*(?::|=|=>)\s*['\"]?)([^'\"\s]{8,})['\"]?", "Password/Secret", "critical"),
    # Firebase URLs
    (r"(?i)([a-zA-Z0-9\-_]+\.firebaseio\.com)", "Firebase URL", "high"),
    # S3 Buckets
    (r"(?i)([a-zA-Z0-9\-_]+\.s3\.amazonaws\.com)", "S3 Bucket URL", "medium"),
    (r"(?i)(s3://[a-zA-Z0-9\-_./]+)", "S3 Bucket Path", "medium"),
    # Custom endpoints
    (r"(?i)(['\"]?(?:internal[_-]?url|private[_-]?url|backend[_-]?url)['\"]?\s*(?::|=|=>)\s*['\"]?https?://[a-zA-Z0-9\-_.]+)['\"]?", "Internal URL", "medium"),
]


class JSSecretDetector(BaseModule):
    """JS Secret Detector Module.

    Detects potential secrets, API keys, tokens, and credentials
    in JavaScript source code.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="JS Secret Detector",
            description="Detect potential secrets, API keys, tokens, and credentials in JavaScript code",
            version="1.0.0",
            author="ReconForgeX",
            tags=["javascript", "secrets", "tokens", "api-keys", "credentials"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="JS Secret Detector module operational",
            last_check=__import__("time").time(),
        )

    def _get_context(self, text: str, pos: int, window: int = 60) -> str:
        """Get surrounding context around a match position."""
        start = max(0, pos - window)
        end = min(len(text), pos + window)
        context = text[start:end].replace("\n", " ").strip()
        if start > 0:
            context = "..." + context
        if end < len(text):
            context = context + "..."
        return context

    def _detect_secrets(self, content: str, source_url: str) -> List[SecretFinding]:
        """Detect secrets in content."""
        findings: List[SecretFinding] = []
        seen_values: Set[str] = set()

        for pattern, secret_type, severity in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                # The matched value is typically group 2 or the full match
                value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)

                # Truncate long values
                if len(value) > 100:
                    value = value[:50] + "..." + value[-20:]

                if value in seen_values:
                    continue
                seen_values.add(value)

                context = self._get_context(content, match.start())
                finding = SecretFinding(
                    type=secret_type,
                    value=value,
                    source_url=source_url,
                    context=context,
                    severity=severity,
                    pattern_used=str(pattern)[:50],
                )
                findings.append(finding)

        return findings

    async def run(self, target: str, **kwargs: Any) -> List[SecretDetectionResult]:
        """Run secret detection against JS files.

        Parameters
        ----------
        target:
            Not used directly - provide js_contents in kwargs.
        **kwargs:
            - js_contents: List of (source_url, content) tuples

        Returns
        -------
        List[SecretDetectionResult]
            List of secret detection results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[SecretDetectionResult] = []

        js_sources: List[tuple] = kwargs.get("js_contents", [])
        if not js_sources:
            js_sources = kwargs.get("js_contents", [])

        try:
            for source_url, content in js_sources:
                findings = self._detect_secrets(content, source_url)
                if findings:
                    result = SecretDetectionResult(
                        source_url=source_url,
                        findings=findings,
                        total_found=len(findings),
                    )
                    results.append(result)
                    self.stats.items_found += len(findings)

        except Exception as exc:
            self._record_error(str(exc))
        finally:
            self.stats.status = ModuleStatus.COMPLETED
            self.stats.end_time = __import__("time").time()
            self.stats.items_processed = len(results)

        return results