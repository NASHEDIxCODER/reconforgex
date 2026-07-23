"""
robots.txt Parser Module.

Downloads and parses robots.txt files to discover allowed/disallowed paths,
sitemaps, and crawl rules. Built entirely in Python.
"""

import re
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

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
class RobotsRule:
    """A single robots.txt rule."""
    user_agent: str
    disallowed: List[str]
    allowed: List[str]
    crawl_delay: Optional[float]
    sitemaps: List[str]


@dataclass
class RobotsResult:
    """robots.txt analysis result."""
    url: str
    exists: bool
    content: str
    rules: List[RobotsRule]
    sitemaps: List[str]
    disallowed_paths: List[str]
    allowed_paths: List[str]
    interesting_disallowed: List[str]  # Paths that might be interesting for recon


INTERESTING_PATH_PATTERNS = [
    r"admin", r"backup", r"config", r"database", r"db\b",
    r"debug", r"dev", r"internal", r"private",
    r"secret", r"temp", r"test", r"staging",
    r"api", r"v1", r"v2", r"graphql",
    r"swagger", r"docs", r"health",
    r".git", r".svn", r".env",
    r"wp-admin", r"wp-content", r"wp-includes",
    r"login", r"dashboard", r"panel",
]


class RobotsParser(BaseModule):
    """robots.txt Parser Module.

    Downloads and parses robots.txt to discover paths, sitemaps,
    and interesting restricted areas.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        super().__init__(config)
        self._client: Optional[AsyncHTTPClient] = None

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="robots.txt Parser",
            description="Download and parse robots.txt to discover paths, sitemaps, and restricted areas",
            version="1.0.0",
            author="ReconForgeX",
            tags=["robots", "crawl", "discovery", "paths", "sitemap"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="robots.txt Parser module operational",
            last_check=__import__("time").time(),
        )

    def _parse_robots(self, content: str) -> List[RobotsRule]:
        """Parse robots.txt content into structured rules."""
        rules: List[RobotsRule] = []
        current_agent = "*"
        current_disallowed: List[str] = []
        current_allowed: List[str] = []
        current_sitemaps: List[str] = []
        current_delay: Optional[float] = None

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.lower().startswith("user-agent"):
                # Save previous rules
                if current_disallowed or current_allowed or current_sitemaps:
                    rules.append(RobotsRule(
                        user_agent=current_agent,
                        disallowed=list(current_disallowed),
                        allowed=list(current_allowed),
                        crawl_delay=current_delay,
                        sitemaps=list(current_sitemaps),
                    ))
                # Start new agent section
                match = re.match(r"user-agent:\s*(.*)", line, re.IGNORECASE)
                current_agent = match.group(1).strip() if match else "*"
                current_disallowed = []
                current_allowed = []
                current_sitemaps = []
                current_delay = None

            elif line.lower().startswith("disallow"):
                match = re.match(r"disallow:\s*(.*)", line, re.IGNORECASE)
                if match:
                    path = match.group(1).strip()
                    if path:
                        current_disallowed.append(path)

            elif line.lower().startswith("allow"):
                match = re.match(r"allow:\s*(.*)", line, re.IGNORECASE)
                if match:
                    path = match.group(1).strip()
                    if path:
                        current_allowed.append(path)

            elif line.lower().startswith("crawl-delay"):
                match = re.match(r"crawl-delay:\s*([\d.]+)", line, re.IGNORECASE)
                if match:
                    try:
                        current_delay = float(match.group(1))
                    except ValueError:
                        pass

            elif line.lower().startswith("sitemap"):
                match = re.match(r"sitemap:\s*(.*)", line, re.IGNORECASE)
                if match:
                    url = match.group(1).strip()
                    if url:
                        current_sitemaps.append(url)

        # Save last rules
        if current_disallowed or current_allowed or current_sitemaps:
            rules.append(RobotsRule(
                user_agent=current_agent,
                disallowed=list(current_disallowed),
                allowed=list(current_allowed),
                crawl_delay=current_delay,
                sitemaps=list(current_sitemaps),
            ))

        return rules

    def _find_interesting_paths(self, paths: List[str]) -> List[str]:
        """Filter paths that match interesting recon patterns."""
        interesting = []
        for path in paths:
            for pattern in INTERESTING_PATH_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    interesting.append(path)
                    break
        return interesting

    async def run(self, target: str, **kwargs: Any) -> List[RobotsResult]:
        """Run robots.txt parsing against the target.

        Parameters
        ----------
        target:
            Domain or URL to analyze.
        **kwargs:
            - urls: Optional list of full URLs

        Returns
        -------
        List[RobotsResult]
            List of robots.txt analysis results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[RobotsResult] = []

        urls: List[str] = kwargs.get("urls", [])
        if not urls:
            urls = [
                f"https://{target}/robots.txt",
                f"http://{target}/robots.txt",
            ]
            urls = list(dict.fromkeys(urls))

        try:
            client = self._get_client()
            responses = await client.batch_get(urls)

            for response in responses:
                if response.error and response.status_code == 0:
                    continue

                if response.status_code == 404:
                    results.append(RobotsResult(
                        url=response.url,
                        exists=False,
                        content="",
                        rules=[],
                        sitemaps=[],
                        disallowed_paths=[],
                        allowed_paths=[],
                        interesting_disallowed=[],
                    ))
                    continue

                rules = self._parse_robots(response.body)

                # Collect all paths
                all_disallowed: List[str] = []
                all_allowed: List[str] = []
                all_sitemaps: List[str] = []

                for rule in rules:
                    all_disallowed.extend(rule.disallowed)
                    all_allowed.extend(rule.allowed)
                    all_sitemaps.extend(rule.sitemaps)

                # Remove duplicates while preserving order
                all_disallowed = list(dict.fromkeys(all_disallowed))
                all_allowed = list(dict.fromkeys(all_allowed))
                all_sitemaps = list(dict.fromkeys(all_sitemaps))

                interesting = self._find_interesting_paths(all_disallowed)

                result = RobotsResult(
                    url=response.url,
                    exists=True,
                    content=response.body,
                    rules=rules,
                    sitemaps=all_sitemaps,
                    disallowed_paths=all_disallowed,
                    allowed_paths=all_allowed,
                    interesting_disallowed=interesting,
                )
                results.append(result)
                self.stats.items_found += len(interesting)

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
                timeout=self.config.extra.get("timeout", 15),
                max_retries=self.config.extra.get("max_retries", 2),
                max_concurrency=self.config.extra.get("concurrency", 10),
                follow_redirects=True,
            )
            self._client = AsyncHTTPClient(http_config)
        return self._client
