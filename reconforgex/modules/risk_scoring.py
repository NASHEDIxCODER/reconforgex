"""
Risk Scoring Engine Module.

Calculates security risk scores based on findings from all other modules.
Provides an overall risk assessment with detailed breakdown. Built entirely
in Python.
"""

from typing import Any, Dict, List, Optional
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
class RiskFactor:
    """A single risk factor contributing to the overall score."""
    category: str
    name: str
    severity: str  # critical, high, medium, low, info
    score: float  # negative impact on overall score
    description: str
    recommendation: str
    evidence: str


@dataclass
class RiskScoreResult:
    """Complete risk scoring result."""
    overall_score: float  # 0.0 (critical) to 100.0 (secure)
    risk_level: str  # critical, high, medium, low, secure
    factors: List[RiskFactor]
    category_scores: Dict[str, float]
    summary: str


# Risk thresholds
RISK_THRESHOLDS = [
    (90, "Secure", "🟢"),
    (70, "Low Risk", "🔵"),
    (50, "Medium Risk", "🟡"),
    (30, "High Risk", "🟠"),
    (0, "Critical Risk", "🔴"),
]

SEVERITY_SCORES = {
    "critical": 25.0,
    "high": 15.0,
    "medium": 8.0,
    "low": 3.0,
    "info": 1.0,
}


class RiskScoringEngine(BaseModule):
    """Risk Scoring Engine Module.

    Calculates security risk scores based on findings from all modules.
    Aggregates results across security headers, TLS, CSP, JS secrets,
    and other analysis modules.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="Risk Scoring Engine",
            description="Calculate security risk scores based on findings from all analysis modules",
            version="1.0.0",
            author="ReconForgeX",
            tags=["risk", "scoring", "security", "assessment", "reporting"],
            requires_network=False,
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="Risk Scoring Engine module operational",
            last_check=__import__("time").time(),
        )

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        for threshold, level, _ in RISK_THRESHOLDS:
            if score >= threshold:
                return level
        return "Critical Risk"

    def _score_security_headers(
        self, header_results: List[Any]
    ) -> tuple:
        """Score security header findings."""
        factors: List[RiskFactor] = []
        total_score = 100.0

        for result in header_results:
            if hasattr(result, "findings"):
                for finding in result.findings:
                    penalty = SEVERITY_SCORES.get(finding.severity, 5.0)
                    total_score -= penalty
                    factors.append(RiskFactor(
                        category="security_headers",
                        name=f"Missing/Weak: {finding.header}",
                        severity=finding.severity,
                        score=penalty,
                        description=finding.description,
                        recommendation=finding.recommendation,
                        evidence=finding.value or "Header not present",
                    ))
            elif hasattr(result, "compliance_score"):
                total_score -= (100 - result.compliance_score) * 0.3

        return factors, max(0.0, total_score)

    def _score_tls_findings(
        self, tls_results: List[Any]
    ) -> tuple:
        """Score TLS/SSL findings."""
        factors: List[RiskFactor] = []
        total_score = 100.0

        for result in tls_results:
            if result.error:
                total_score -= 15.0
                factors.append(RiskFactor(
                    category="tls",
                    name=f"TLS Error: {result.host}:{result.port}",
                    severity="high",
                    score=15.0,
                    description=f"TLS connection error: {result.error}",
                    recommendation="Ensure TLS is properly configured on the server",
                    evidence=result.error,
                ))
                continue

            if result.is_expired:
                total_score -= 25.0
                factors.append(RiskFactor(
                    category="tls",
                    name=f"Expired certificate: {result.host}",
                    severity="critical",
                    score=25.0,
                    description=f"SSL certificate expired {abs(result.days_remaining)} days ago",
                    recommendation="Renew the SSL certificate immediately",
                    evidence=f"Expired: {result.valid_until}",
                ))

            if result.is_self_signed:
                total_score -= 10.0
                factors.append(RiskFactor(
                    category="tls",
                    name="Self-signed certificate",
                    severity="medium",
                    score=10.0,
                    description="Self-signed certificates are not trusted by browsers",
                    recommendation="Use a certificate from a trusted CA (Let's Encrypt, etc.)",
                    evidence="Self-signed: True",
                ))

            if result.days_remaining < 30 and result.days_remaining > 0:
                total_score -= 8.0
                factors.append(RiskFactor(
                    category="tls",
                    name=f"Certificate expiring soon: {result.days_remaining} days",
                    severity="medium",
                    score=8.0,
                    description=f"SSL certificate expires in {result.days_remaining} days",
                    recommendation="Renew the certificate before expiration",
                    evidence=f"Days remaining: {result.days_remaining}",
                ))

        return factors, max(0.0, total_score)

    def _score_csp_findings(
        self, csp_results: List[Any]
    ) -> tuple:
        """Score CSP findings."""
        factors: List[RiskFactor] = []
        total_score = 100.0

        for result in csp_results:
            if result.score < 50:
                total_score -= 15.0
                factors.append(RiskFactor(
                    category="csp",
                    name="Weak Content Security Policy",
                    severity="high",
                    score=15.0,
                    description="CSP has significant weaknesses that reduce its effectiveness",
                    recommendation="Review CSP directives and follow OWASP CSP guidelines",
                    evidence=f"CSP Score: {result.score}/100",
                ))

            for weakness in result.weaknesses:
                penalty = 5.0
                total_score -= penalty
                factors.append(RiskFactor(
                    category="csp",
                    name=f"CSP Weakness: {weakness}",
                    severity="medium",
                    score=penalty,
                    description=weakness,
                    recommendation="Address each CSP weakness according to OWASP guidelines",
                    evidence=f"Policy: {result.policy}",
                ))

        return factors, max(0.0, total_score)

    def _score_secrets(
        self, secret_results: List[Any]
    ) -> tuple:
        """Score secret detection findings."""
        factors: List[RiskFactor] = []
        total_score = 100.0

        for result in secret_results:
            for finding in result.findings:
                penalty = SEVERITY_SCORES.get(finding.severity, 5.0)
                total_score -= penalty
                factors.append(RiskFactor(
                    category="secrets",
                    name=f"Exposed: {finding.type}",
                    severity=finding.severity,
                    score=penalty,
                    description=f"Potential {finding.type} found in JavaScript",
                    recommendation="Remove hardcoded credentials and use environment variables or secrets management",
                    evidence=f"Source: {finding.source_url}",
                ))

        return factors, max(0.0, total_score)

    async def run(self, target: str, **kwargs: Any) -> List[RiskScoreResult]:
        """Calculate risk score based on all findings.

        Parameters
        ----------
        target:
            Target identifier (domain or URL).
        **kwargs:
            - header_results: Results from HeaderAnalyzer/SecurityHeaderScanner
            - tls_results: Results from TLSInspector
            - csp_results: Results from CSPAnalyzer
            - secret_results: Results from JSSecretDetector
            - other_findings: Additional findings to factor in

        Returns
        -------
        List[RiskScoreResult]
            List containing the overall risk assessment.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = __import__("time").time()
        results: List[RiskScoreResult] = []

        try:
            all_factors: List[RiskFactor] = []
            category_scores: Dict[str, float] = {}

            # Score each category
            header_results = kwargs.get("header_results", [])
            header_factors, header_score = self._score_security_headers(header_results)
            all_factors.extend(header_factors)
            category_scores["security_headers"] = round(header_score, 1)

            tls_results = kwargs.get("tls_results", [])
            tls_factors, tls_score = self._score_tls_findings(tls_results)
            all_factors.extend(tls_factors)
            category_scores["tls"] = round(tls_score, 1)

            csp_results = kwargs.get("csp_results", [])
            csp_factors, csp_score = self._score_csp_findings(csp_results)
            all_factors.extend(csp_factors)
            category_scores["csp"] = round(csp_score, 1)

            secret_results = kwargs.get("secret_results", [])
            secret_factors, secret_score = self._score_secrets(secret_results)
            all_factors.extend(secret_factors)
            category_scores["secrets"] = round(secret_score, 1)

            # Calculate overall score (weighted average)
            weights = {
                "security_headers": 0.3,
                "tls": 0.25,
                "csp": 0.25,
                "secrets": 0.2,
            }

            overall_score = 100.0
            for category, weight in weights.items():
                if category in category_scores:
                    overall_score -= (100 - category_scores[category]) * weight

            overall_score = max(0.0, min(100.0, overall_score))
            risk_level = self._determine_risk_level(overall_score)

            # Build summary
            critical_count = sum(1 for f in all_factors if f.severity == "critical")
            high_count = sum(1 for f in all_factors if f.severity == "high")
            medium_count = sum(1 for f in all_factors if f.severity == "medium")

            summary = (
                f"Overall Risk Level: {risk_level} (Score: {overall_score:.1f}/100)\n"
                f"Critical Findings: {critical_count} | High: {high_count} | Medium: {medium_count}\n"
                f"Categories: Security Headers ({category_scores.get('security_headers', 'N/A')}/100), "
                f"TLS ({category_scores.get('tls', 'N/A')}/100), "
                f"CSP ({category_scores.get('csp', 'N/A')}/100), "
                f"Secrets ({category_scores.get('secrets', 'N/A')}/100)"
            )

            result = RiskScoreResult(
                overall_score=round(overall_score, 1),
                risk_level=risk_level,
                factors=all_factors,
                category_scores=category_scores,
                summary=summary,
            )
            results.append(result)
            self.stats.items_found = len(all_factors)

        except Exception as exc:
            self._record_error(str(exc))
        finally:
            self.stats.status = ModuleStatus.COMPLETED
            self.stats.end_time = __import__("time").time()
            self.stats.items_processed = 1

        return results