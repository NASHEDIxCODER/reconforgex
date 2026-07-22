"""
Interesting Files Finder Module.

Discovers interesting files and directories on web servers by probing
common paths. Built entirely in Python.
"""

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin

from reconforgex.modules.base import (
    BaseModule,
    ModuleConfiguration,
    ModuleHealth,
    ModuleMetadata,
    ModuleStatus,
)
from reconforgex.utils.http_client import AsyncHTTPClient, HTTPClientConfig, HTTPResponse
from reconforgex.logger import get_logger

log = get_logger()


@dataclass
class InterestingFile:
    """A discovered interesting file or path."""
    url: str
    status_code: int
    size_bytes: int
    content_type: str
    category: str
    description: str


@dataclass
class InterestingFilesResult:
    """Result of interesting files search."""
    base_url: str
    files: List[InterestingFile]
    total_found: int


# Common interesting files and paths organized by category
INTERESTING_PATHS = {
    # Configuration files
    "config": [
        ("/.env", "Environment configuration file"),
        ("/.env.example", "Environment configuration example"),
        ("/.env.local", "Local environment configuration"),
        ("/config.json", "JSON configuration file"),
        ("/config.yaml", "YAML configuration file"),
        ("/config.yml", "YAML configuration file"),
        ("/configuration.json", "Configuration file"),
        ("/settings.py", "Python settings file"),
        ("/settings.json", "JSON settings file"),
        ("/appsettings.json", ".NET application settings"),
        ("/web.config", "IIS Web configuration"),
        ("/.htaccess", "Apache access configuration"),
        ("/nginx.conf", "Nginx configuration"),
        ("/robots.txt", "Robots exclusion file"),
    ],
    # Source control
    "source_control": [
        ("/.git/HEAD", "Git repository HEAD file"),
        ("/.git/config", "Git repository configuration"),
        ("/.svn/entries", "SVN repository entries"),
        ("/.svn/wc.db", "SVN working copy database"),
        ("/CVS/Entries", "CVS repository entries"),
    ],
    # Backup files
    "backup": [
        ("/backup.zip", "Backup archive"),
        ("/backup.tar.gz", "Backup archive"),
        ("/backup.sql", "Database backup"),
        ("/db_backup.sql", "Database backup"),
        ("/dump.sql", "Database dump"),
        ("/dump.rdb", "Redis dump"),
        ("/.bak", "Backup file"),
        ("/*.bak", "Backup files"),
        ("/*.old", "Old files"),
        ("/*.swp", "Vim swap file"),
    ],
    # Log files
    "logs": [
        ("/error.log", "Error log"),
        ("/access.log", "Access log"),
        ("/debug.log", "Debug log"),
        ("/app.log", "Application log"),
        ("/log.txt", "Log file"),
        ("/logs/", "Logs directory"),
        ("/var/log/", "System logs"),
    ],
    # Admin panels
    "admin_panels": [
        ("/admin/", "Admin panel"),
        ("/administrator/", "Administrator panel"),
        ("/admin.php", "Admin PHP page"),
        ("/dashboard/", "Dashboard"),
        ("/panel/", "Management panel"),
        ("/manager/", "Manager interface"),
        ("/backend/", "Backend interface"),
        ("/cpanel/", "Control panel"),
    ],
    # API endpoints
    "api_endpoints": [
        ("/api/", "API root"),
        ("/api/v1/", "API v1"),
        ("/api/v2/", "API v2"),
        ("/api/v3/", "API v3"),
        ("/graphql", "GraphQL endpoint"),
        ("/swagger.json", "Swagger API documentation"),
        ("/swagger.yaml", "Swagger API documentation"),
        ("/api-docs", "API documentation"),
        ("/openapi.json", "OpenAPI specification"),
    ],
    # Sensitive files
    "sensitive": [
        ("/phpinfo.php", "PHP information page"),
        ("/info.php", "PHP information page"),
        ("/test.php", "Test PHP file"),
        ("/debug/", "Debug interface"),
        ("/status", "Status page"),
        ("/health", "Health check endpoint"),
        ("/metrics", "Metrics endpoint"),
        ("/actuator/health", "Spring Boot health"),
        ("/actuator/info", "Spring Boot info"),
    ],
    # Security-related
    "security": [
        ("/security.txt", "Security contact information"),
        ("/.well-known/security.txt", "Security contact information"),
        ("/keybase.txt", "Keybase verification"),
        ("/pgpkey.txt", "PGP public key"),
    ],
}


class InterestingFilesFinder(BaseModule):
    """Interesting Files Finder Module.

    Discovers interesting files, directories, and endpoints on web
    servers by probing common paths.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        super().__init__(config)
        http_config = HTTPClientConfig(
            timeout=config.extra.get("timeout", 10) if config else 10,
            max_retries=config.extra.get("max_retries", 1) if config else 1,
            max_concurrency=config.extra.get("concurrency", 50) if config else 50,
            follow_redirects=False,
        )
        self._client = AsyncHTTPClient(http_config)

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="Interesting Files Finder",
            description="Discover interesting files, directories, and endpoints on web servers",
            version="1.0.0",
            author="ReconForgeX",
            tags=["discovery", "files", "paths", "directories", "reconnaissance"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="Interesting Files Finder module operational",
            last_check=__import__("time").time(),
        )

    async def run(self, target: str, **kwargs: Any) -> List[InterestingFilesResult]:
        """Run interesting files discovery against the target.

        Parameters
        ----------
        target:
            URL or domain to analyze.
        **kwargs:
            - urls: Optional list of base URLs
            - custom_paths: Optional list of custom paths to check

        Returns
        -------
        List[InterestingFilesResult]
            List of discovery results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[InterestingFilesResult] = []

        base_urls: List[str] = kwargs.get("urls", [])
        if not base_urls:
            base_urls = [f"https://{target}", f"http://{target}"]
            base_urls = list(dict.fromkeys(base_urls))

        # Build path list
        paths_to_check: List[Tuple[str, str, str]] = []
        for category, paths in INTERESTING_PATHS.items():
            for path, description in paths:
                paths_to_check.append((path, category, description))

        custom_paths = kwargs.get("custom_paths", [])
        for path in custom_paths:
            paths_to_check.append((path, "custom", "Custom path"))

        try:
            for base_url in base_urls:
                full_urls = [urljoin(base_url, path) for path, _, _ in paths_to_check]
                responses = await self._client.batch_get(full_urls)

                found_files: List[InterestingFile] = []
                for (path, category, description), response in zip(paths_to_check, responses):
                    if response.status_code not in (0, 404) and response.status_code < 500:
                        file = InterestingFile(
                            url=response.url,
                            status_code=response.status_code,
                            size_bytes=len(response.body.encode()),
                            content_type=response.content_type or "",
                            category=category,
                            description=description,
                        )
                        found_files.append(file)

                result = InterestingFilesResult(
                    base_url=base_url,
                    files=found_files,
                    total_found=len(found_files),
                )
                results.append(result)
                self.stats.items_found += len(found_files)

        except Exception as exc:
            self._record_error(str(exc))
        finally:
            self.stats.status = ModuleStatus.COMPLETED
            self.stats.end_time = __import__("time").time()
            self.stats.items_processed = len(results)
            await self._client.close()

        return results