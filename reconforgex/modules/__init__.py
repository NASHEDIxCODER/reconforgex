"""
ReconForgeX Modules Package.

All modules expose:
    - run()        : Execute the module's core logic
    - metadata()   : Return module metadata
    - statistics() : Return execution statistics
    - health()     : Return health check status
    - configuration() : Return current configuration
"""

from reconforgex.modules.base import (
    BaseModule,
    ModuleConfiguration,
    ModuleHealth,
    ModuleMetadata,
    ModuleStatistics,
    ModuleStatus,
)
from reconforgex.modules.csp_analyzer import CSPAnalysis, CSPAnalyzer, CSPDirective
from reconforgex.modules.header_analyzer import HeaderAnalysisResult, HeaderAnalyzer, HeaderFinding
from reconforgex.modules.http_fingerprint import FingerprintResult, HTTPFingerprinting
from reconforgex.modules.http_response_analyzer import (
    HTTPResponseAnalysisResult,
    HTTPResponseAnalyzer,
    ResponseAnalysis,
)
from reconforgex.modules.interesting_files import (
    InterestingFile,
    InterestingFilesFinder,
    InterestingFilesResult,
)
from reconforgex.modules.js_collector import JSCollectionResult, JSCollector, JSFile
from reconforgex.modules.js_endpoint_extractor import (
    Endpoint,
    EndpointExtractionResult,
    JSEndpointExtractor,
)
from reconforgex.modules.js_secret_detector import (
    JSSecretDetector,
    SecretDetectionResult,
    SecretFinding,
)
from reconforgex.modules.risk_scoring import RiskFactor, RiskScoreResult, RiskScoringEngine
from reconforgex.modules.robots_parser import RobotsParser, RobotsResult, RobotsRule
from reconforgex.modules.security_header_scanner import (
    SecurityHeaderCheck,
    SecurityHeaderResult,
    SecurityHeaderScanner,
)
from reconforgex.modules.sitemap_parser import SitemapParser, SitemapResult, SitemapURL
from reconforgex.modules.tls_inspector import TLSInspector, TLSResult

__all__ = [
    # Base
    "BaseModule",
    "ModuleConfiguration",
    "ModuleHealth",
    "ModuleMetadata",
    "ModuleStatistics",
    "ModuleStatus",
    # HTTP Fingerprinting
    "HTTPFingerprinting",
    "FingerprintResult",
    # Header Analyzer
    "HeaderAnalyzer",
    "HeaderAnalysisResult",
    "HeaderFinding",
    # Security Header Scanner
    "SecurityHeaderScanner",
    "SecurityHeaderResult",
    "SecurityHeaderCheck",
    # TLS Inspector
    "TLSInspector",
    "TLSResult",
    # CSP Analyzer
    "CSPAnalyzer",
    "CSPAnalysis",
    "CSPDirective",
    # robots.txt Parser
    "RobotsParser",
    "RobotsResult",
    "RobotsRule",
    # sitemap.xml Parser
    "SitemapParser",
    "SitemapResult",
    "SitemapURL",
    # JavaScript Collector
    "JSCollector",
    "JSCollectionResult",
    "JSFile",
    # JS Endpoint Extractor
    "JSEndpointExtractor",
    "EndpointExtractionResult",
    "Endpoint",
    # JS Secret Detector
    "JSSecretDetector",
    "SecretDetectionResult",
    "SecretFinding",
    # Interesting Files Finder
    "InterestingFilesFinder",
    "InterestingFilesResult",
    "InterestingFile",
    # HTTP Response Analyzer
    "HTTPResponseAnalyzer",
    "HTTPResponseAnalysisResult",
    "ResponseAnalysis",
    # Risk Scoring Engine
    "RiskScoringEngine",
    "RiskScoreResult",
    "RiskFactor",
]
