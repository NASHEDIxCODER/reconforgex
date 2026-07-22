"""
JS Endpoint Extractor Module.

Extracts API endpoints, routes, and paths from JavaScript source code
using pattern matching. Built entirely in Python.
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
from reconforgex.logger import get_logger

log = get_logger()


@dataclass
class Endpoint:
    """A discovered endpoint from JavaScript."""
    path: str
    source: str  # The JS file or inline script where found
    method: Optional[str]
    url_pattern: str  # The regex/string pattern that matched
    context: str  # Surrounding code for context


@dataclass
class EndpointExtractionResult:
    """Endpoint extraction result."""
    source_url: str
    endpoints: List[Endpoint]
    total_found: int


# Patterns for detecting API endpoints and routes
ENDPOINT_PATTERNS = [
    # API route patterns
    (r"['\"]/(?:api|v[1-9])/[a-zA-Z0-9/_.-]+['\"]", "api_route"),
    (r"['\"]/(?:rest|graphql|odata)/[a-zA-Z0-9/_.-]*['\"]", "api_route"),
    # Axios/fetch patterns
    (r"(?:axios|fetch|ajax|request)\s*\(?\s*['\"]/*([a-zA-Z0-9/_.?-]+)['\"]", "http_request"),
    # Angular/React route patterns
    (r"(?:path|component|route)\s*:\s*['\"]/*([a-zA-Z0-9/_.?-]+)['\"]", "framework_route"),
    (r"Router\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['\"]/*([a-zA-Z0-9/_.?-]+)['\"]", "router"),
    # Express route patterns
    (r"\.(?:get|post|put|delete|patch|all)\s*\(\s*['\"]/*([a-zA-Z0-9/_.?-]+)['\"]", "express_route"),
    # URL patterns
    (r"url\s*:\s*['\"]/*([a-zA-Z0-9/_.?-]+)['\"]", "url_config"),
    (r"endpoint\s*:\s*['\"]/*([a-zA-Z0-9/_.?-]+)['\"]", "endpoint_config"),
    # WebSocket patterns
    (r"(?:ws|wss)://[a-zA-Z0-9./_-]+", "websocket"),
    # Service worker patterns
    (r"register\s*\(\s*['\"]/*([a-zA-Z0-9/_.?-]+)['\"]", "service_worker"),
    # gRPC patterns
    (r"(?:proto|service)\s*:\s*['\"]/*([a-zA-Z0-9/_.-]+)['\"]", "grpc"),
    # File paths that may be endpoints
    (r"['\"]/*(?:download|upload|export|import|callback|redirect|webhook)/*['\"]", "file_endpoint"),
]

HTTP_METHOD_PATTERNS = {
    r"(?:function|def)\s+get": "GET",
    r"(?:function|def)\s+post": "POST",
    r"(?:function|def)\s+put": "PUT",
    r"(?:function|def)\s+delete": "DELETE",
    r"(?:function|def)\s+patch": "PATCH",
    r"(?:function|def)\s+update": "PUT",
    r"(?:function|def)\s+create": "POST",
    r"(?:function|def)\s+remove": "DELETE",
    r"(?:function|def)\s+list": "GET",
}


class JSEndpointExtractor(BaseModule):
    """JS Endpoint Extractor Module.

    Extracts API endpoints, routes, and URLs from JavaScript source
    code using regex pattern matching.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="JS Endpoint Extractor",
            description="Extract API endpoints, routes, and URLs from JavaScript source code",
            version="1.0.0",
            author="ReconForgeX",
            tags=["javascript", "endpoints", "api", "routes", "reconnaissance"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="JS Endpoint Extractor module operational",
            last_check=__import__("time").time(),
        )

    def _get_context(self, text: str, pos: int, window: int = 80) -> str:
        """Get surrounding context around a match position."""
        start = max(0, pos - window)
        end = min(len(text), pos + window)
        context = text[start:end].replace("\n", " ").strip()
        if start > 0:
            context = "..." + context
        if end < len(text):
            context = context + "..."
        return context

    def _infer_method(self, context: str) -> Optional[str]:
        """Try to infer HTTP method from surrounding code context."""
        for pattern, method in HTTP_METHOD_PATTERNS.items():
            if re.search(pattern, context, re.IGNORECASE):
                return method
        return None

    def _extract_endpoints_from_content(self, content: str, source_url: str) -> List[Endpoint]:
        """Extract endpoints from a single JS source."""
        endpoints: List[Endpoint] = []
        seen_paths: Set[str] = set()

        for pattern, category in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                path = match.group(0).strip("'\"() ")
                if path in seen_paths:
                    continue
                seen_paths.add(path)

                context = self._get_context(content, match.start())
                method = self._infer_method(context)

                endpoint = Endpoint(
                    path=path,
                    source=source_url,
                    method=method,
                    url_pattern=pattern,
                    context=context,
                )
                endpoints.append(endpoint)

        return endpoints

    def _deduplicate_endpoints(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        """Deduplicate endpoints by path."""
        seen: Set[str] = set()
        unique: List[Endpoint] = []
        for ep in endpoints:
            if ep.path not in seen:
                seen.add(ep.path)
                unique.append(ep)
        return unique

    async def run(self, target: str, **kwargs: Any) -> List[EndpointExtractionResult]:
        """Run endpoint extraction against JS files.

        Parameters
        ----------
        target:
            Not used directly - provide j_s_files in kwargs.
        **kwargs:
            - js_files: List of JSFile objects with content
            - js_contents: List of (source_url, content) tuples

        Returns
        -------
        List[EndpointExtractionResult]
            List of endpoint extraction results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[EndpointExtractionResult] = []

        js_sources: List[tuple] = kwargs.get("js_contents", [])

        try:
            for source_url, content in js_sources:
                endpoints = self._extract_endpoints_from_content(content, source_url)
                endpoints = self._deduplicate_endpoints(endpoints)

                result = EndpointExtractionResult(
                    source_url=source_url,
                    endpoints=endpoints,
                    total_found=len(endpoints),
                )
                results.append(result)
                self.stats.items_found += len(endpoints)

        except Exception as exc:
            self._record_error(str(exc))
        finally:
            self.stats.status = ModuleStatus.COMPLETED
            self.stats.end_time = __import__("time").time()
            self.stats.items_processed = len(results)

        return results