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

from reconforgex.modules.http_fingerprint import HTTPFingerprinting, FingerprintResult
from reconforgex.modules.header_analyzer import HeaderAnalyzer, HeaderAnalysisResult, HeaderFinding
from reconforgex.modules.security_header_scanner import SecurityHeaderScanner, SecurityHeaderResult, SecurityHeaderCheck
from reconforgex.modules.tls_inspector import TLSInspector, TLSResult
from reconforgex.modules.csp_analyzer import CSPAnalyzer, CSPAnalysis, CSPDirective
from reconforgex.modules.robots_parser import RobotsParser, RobotsResult, RobotsRule
from reconforgex.modules.sitemap_parser import SitemapParser, SitemapResult, SitemapURL
from reconforgex.modules.js_collector import JSCollector, JSCollectionResult, JSFile
from reconforgex.modules.js_endpoint_extractor import JSEndpointExtractor, EndpointExtractionResult, Endpoint
from reconforgex.modules.js_secret_detector import JSSecretDetector, SecretDetectionResult, SecretFinding
from reconforgex.modules.interesting_files import InterestingFilesFinder, InterestingFilesResult, InterestingFile
from reconforgex.modules.http_response_analyzer import HTTPResponseAnalyzer, HTTPResponseAnalysisResult, ResponseAnalysis
from reconforgex.modules.risk_scoring import RiskScoringEngine, RiskScoreResult, RiskFactor

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