"""
sitemap.xml Parser Module.

Downloads and parses XML sitemaps to discover URLs, paths, and
additional sitemap indices. Built entirely in Python.
"""

import gzip
import re
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse
from xml.etree import ElementTree

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
class SitemapURL:
    """A URL entry from a sitemap."""
    location: str
    last_modified: Optional[str]
    change_frequency: Optional[str]
    priority: Optional[float]


@dataclass
class SitemapResult:
    """sitemap.xml analysis result."""
    url: str
    exists: bool
    is_sitemap_index: bool
    urls: List[SitemapURL]
    sub_sitemaps: List[str]
    total_urls: int
    total_sitemaps: int
    paths_discovered: List[str]


class SitemapParser(BaseModule):
    """sitemap.xml Parser Module.

    Downloads and parses XML sitemaps to discover URLs and paths
    within the target domain.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        super().__init__(config)
        http_config = HTTPClientConfig(
            timeout=config.extra.get("timeout", 15) if config else 15,
            max_retries=config.extra.get("max_retries", 2) if config else 2,
            max_concurrency=config.extra.get("concurrency", 10) if config else 10,
            follow_redirects=True,
        )
        self._client = AsyncHTTPClient(http_config)

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="sitemap.xml Parser",
            description="Download and parse XML sitemaps to discover URLs and paths",
            version="1.0.0",
            author="ReconForgeX",
            tags=["sitemap", "discovery", "urls", "paths", "crawl"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="sitemap.xml Parser module operational",
            last_check=__import__("time").time(),
        )

    def _parse_sitemap(self, content: str) -> tuple:
        """Parse sitemap XML content."""
        urls: List[SitemapURL] = []
        sub_sitemaps: List[str] = []
        is_index = False

        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            return urls, sub_sitemaps, is_index

        # Strip namespace
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag[:root.tag.index("}") + 1]

        if root.tag == f"{ns}sitemapindex":
            is_index = True
            for sitemap_elem in root.findall(f"{ns}sitemap"):
                loc = sitemap_elem.findtext(f"{ns}loc", "").strip()
                if loc:
                    sub_sitemaps.append(loc)

        elif root.tag == f"{ns}urlset":
            for url_elem in root.findall(f"{ns}url"):
                loc = url_elem.findtext(f"{ns}loc", "").strip()
                if loc:
                    lastmod = url_elem.findtext(f"{ns}lastmod", "")
                    changefreq = url_elem.findtext(f"{ns}changefreq", "")
                    priority_str = url_elem.findtext(f"{ns}priority", "")
                    priority = None
                    if priority_str:
                        try:
                            priority = float(priority_str)
                        except ValueError:
                            pass
                    urls.append(SitemapURL(
                        location=loc,
                        last_modified=lastmod or None,
                        change_frequency=changefreq or None,
                        priority=priority,
                    ))

        return urls, sub_sitemaps, is_index

    def _extract_paths(self, urls: List[SitemapURL]) -> List[str]:
        """Extract unique paths from sitemap URLs."""
        paths: Set[str] = set()
        for url_entry in urls:
            parsed = urlparse(url_entry.location)
            if parsed.path:
                paths.add(parsed.path)
        return sorted(paths)

    async def run(self, target: str, **kwargs: Any) -> List[SitemapResult]:
        """Run sitemap parsing against the target.

        Parameters
        ----------
        target:
            Domain or URL to analyze.
        **kwargs:
            - urls: Optional list of sitemap URLs

        Returns
        -------
        List[SitemapResult]
            List of sitemap analysis results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[SitemapResult] = []

        sitemap_urls: List[str] = kwargs.get("urls", [])
        if not sitemap_urls:
            sitemap_urls = [
                f"https://{target}/sitemap.xml",
                f"https://{target}/sitemap_index.xml",
                f"http://{target}/sitemap.xml",
            ]
            # Also check common sitemap locations
            for common_path in [
                "/sitemap.xml", "/sitemap_index.xml", "/sitemap/",
                "/sitemap/sitemap.xml", "/sitemap1.xml", "/sitemap2.xml",
            ]:
                sitemap_urls.append(f"https://{target}{common_path}")
                sitemap_urls.append(f"http://{target}{common_path}")
            sitemap_urls = list(dict.fromkeys(sitemap_urls))

        try:
            responses = await self._client.batch_get(sitemap_urls)

            for response in responses:
                if response.error and response.status_code == 0:
                    continue

                if response.status_code == 404:
                    continue

                urls, sub_sitemaps, is_index = self._parse_sitemap(response.body)

                # If sitemap index, fetch sub-sitemaps
                if is_index and sub_sitemaps:
                    sub_responses = await self._client.batch_get(sub_sitemaps)
                    for sub_resp in sub_responses:
                        if sub_resp.status_code == 200:
                            sub_urls, _, _ = self._parse_sitemap(sub_resp.body)
                            urls.extend(sub_urls)

                paths = self._extract_paths(urls)

                result = SitemapResult(
                    url=response.url,
                    exists=True,
                    is_sitemap_index=is_index,
                    urls=urls,
                    sub_sitemaps=sub_sitemaps,
                    total_urls=len(urls),
                    total_sitemaps=len(sub_sitemaps) + 1,
                    paths_discovered=paths,
                )
                results.append(result)
                self.stats.items_found += len(urls)

        except Exception as exc:
            self._record_error(str(exc))
        finally:
            self.stats.status = ModuleStatus.COMPLETED
            self.stats.end_time = __import__("time").time()
            self.stats.items_processed = len(results)
            await self._client.close()

        return results