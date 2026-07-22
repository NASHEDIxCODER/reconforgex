"""
JavaScript Collector Module.

Discovers and collects JavaScript files from web pages by parsing
HTML for script tags. Built entirely in Python.
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
class JSFile:
    """A discovered JavaScript file."""
    url: str
    source_url: str
    inline: bool
    content: str
    size_bytes: int
    is_third_party: bool
    domain: str


@dataclass
class JSCollectionResult:
    """JavaScript collection result for a target."""
    url: str
    js_files: List[JSFile]
    inline_scripts: int
    external_scripts: int
    third_party_scripts: int
    total_size_bytes: int


class JSCollector(BaseModule):
    """JavaScript Collector Module.

    Discovers and collects JavaScript files from web pages for
    further analysis.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        super().__init__(config)
        http_config = HTTPClientConfig(
            timeout=config.extra.get("timeout", 30) if config else 30,
            max_retries=config.extra.get("max_retries", 2) if config else 2,
            max_concurrency=config.extra.get("concurrency", 25) if config else 25,
            follow_redirects=True,
        )
        self._client = AsyncHTTPClient(http_config)

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="JavaScript Collector",
            description="Discover and collect JavaScript files from web pages",
            version="1.0.0",
            author="ReconForgeX",
            tags=["javascript", "collection", "analysis", "reconnaissance"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="JS Collector module operational",
            last_check=__import__("time").time(),
        )

    def _extract_js_sources(self, html: str, base_url: str) -> tuple:
        """Extract JavaScript sources from HTML."""
        external_urls: List[str] = []
        inline_contents: List[str] = []
        domain = urlparse(base_url).netloc

        # Extract external scripts
        script_pattern = re.compile(
            r'<script[^>]*src=["\'](.*?)["\'][^>]*>',
            re.IGNORECASE | re.DOTALL,
        )
        for match in script_pattern.finditer(html):
            src = match.group(1).strip()
            if src:
                full_url = urljoin(base_url, src)
                external_urls.append(full_url)

        # Extract inline scripts
        inline_pattern = re.compile(
            r'<script[^>]*>(.*?)</script>',
            re.IGNORECASE | re.DOTALL,
        )
        for match in inline_pattern.finditer(html):
            content = match.group(1).strip()
            if content and 'src=' not in match.group(0).lower():
                inline_contents.append(content)

        return external_urls, inline_contents

    def _is_third_party(self, url: str, main_domain: str) -> bool:
        """Check if a JS URL is third-party."""
        try:
            js_domain = urlparse(url).netloc
            return js_domain != main_domain and js_domain != ""
        except Exception:
            return False

    async def run(self, target: str, **kwargs: Any) -> List[JSCollectionResult]:
        """Run JavaScript collection against the target.

        Parameters
        ----------
        target:
            URL or domain to analyze.
        **kwargs:
            - urls: Optional list of full URLs

        Returns
        -------
        List[JSCollectionResult]
            List of JS collection results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[JSCollectionResult] = []

        urls: List[str] = kwargs.get("urls", [])
        if not urls:
            urls = [f"https://{target}", f"http://{target}"]
            urls = list(dict.fromkeys(urls))

        try:
            responses = await self._client.batch_get(urls)

            for response in responses:
                if response.error and response.status_code == 0:
                    continue

                main_domain = urlparse(response.url).netloc
                external_urls, inline_contents = self._extract_js_sources(
                    response.body, response.url
                )

                # Deduplicate external URLs
                external_urls = list(dict.fromkeys(external_urls))

                # Fetch external JS files
                js_files: List[JSFile] = []

                # Add inline scripts
                for idx, content in enumerate(inline_contents):
                    js_files.append(JSFile(
                        url=f"inline:{idx}",
                        source_url=response.url,
                        inline=True,
                        content=content,
                        size_bytes=len(content.encode()),
                        is_third_party=False,
                        domain=main_domain,
                    ))

                # Fetch external JS
                if external_urls:
                    js_responses = await self._client.batch_get(external_urls)
                    for js_url, js_resp in zip(external_urls, js_responses):
                        if js_resp.status_code == 200:
                            is_third_party = self._is_third_party(js_url, main_domain)
                            js_files.append(JSFile(
                                url=js_url,
                                source_url=response.url,
                                inline=False,
                                content=js_resp.body,
                                size_bytes=len(js_resp.body.encode()),
                                is_third_party=is_third_party,
                                domain=urlparse(js_url).netloc,
                            ))

                external_count = sum(1 for j in js_files if not j.inline)
                third_party_count = sum(1 for j in js_files if j.is_third_party)
                total_size = sum(j.size_bytes for j in js_files)

                result = JSCollectionResult(
                    url=response.url,
                    js_files=js_files,
                    inline_scripts=len(inline_contents),
                    external_scripts=external_count,
                    third_party_scripts=third_party_count,
                    total_size_bytes=total_size,
                )
                results.append(result)
                self.stats.items_found += len(js_files)

        except Exception as exc:
            self._record_error(str(exc))
        finally:
            self.stats.status = ModuleStatus.COMPLETED
            self.stats.end_time = __import__("time").time()
            self.stats.items_processed = len(results)
            await self._client.close()

        return results