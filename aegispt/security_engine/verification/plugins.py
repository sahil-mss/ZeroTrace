"""Concrete verification plugins for deterministic finding validation.

TASK 3: Modular verifiers implementing safe, non-destructive validation probes
and known lab ground truth correlation.
"""

from typing import Any
import requests

from aegispt.security_engine.schemas.enums import (
    ImpactLevel,
    PermissionLevel,
    VerificationStatus,
)
from aegispt.security_engine.schemas.finding import NormalizedFinding
from aegispt.security_engine.verification.base import BaseVerifier


class HeaderSecurityVerifier(BaseVerifier):
    """Verifies missing security header alerts through non-destructive probes."""

    @property
    def verification_id(self) -> str:
        return "verifier_header_security"

    @property
    def supported_finding_types(self) -> list[str]:
        return ["CWE-693", "CWE-1021", "CWE-16"]

    @property
    def preconditions(self) -> list[str]:
        return ["web_url", "http_endpoint"]

    @property
    def required_permission_level(self) -> PermissionLevel:
        return PermissionLevel.SAFE_AUDIT

    @property
    def evidence_requirements(self) -> list[str]:
        return ["content_snippet"]

    @property
    def potential_impact(self) -> ImpactLevel:
        return ImpactLevel.NONE

    def verify(
        self,
        finding: NormalizedFinding,
        session: requests.Session | None = None,
    ) -> tuple[VerificationStatus, str, dict[str, Any]]:
        """Evaluate whether security header is genuinely missing."""
        title_lower = finding.title.lower()

        # Identify header under test
        target_header = None
        if "csp" in title_lower or "content security policy" in title_lower:
            target_header = "content-security-policy"
        elif "anti-clickjacking" in title_lower or "x-frame-options" in title_lower:
            target_header = "x-frame-options"
        elif "x-content-type-options" in title_lower or "anti-mime" in title_lower:
            target_header = "x-content-type-options"
        elif "strict-transport-security" in title_lower or "hsts" in title_lower:
            target_header = "strict-transport-security"

        if not target_header:
            return (
                VerificationStatus.NEEDS_REVIEW,
                "Unable to deterministically deduce target header from finding title.",
                {},
            )

        # Attempt live probe if session is available
        if session is not None and finding.target.target_value.startswith("http"):
            try:
                resp = session.get(finding.target.target_value, timeout=3.0)
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                if target_header in headers_lower:
                    return (
                        VerificationStatus.FALSE_POSITIVE,
                        f"Live probe confirmed header '{target_header}' is present in response headers.",
                        {"observed_header": headers_lower[target_header]},
                    )
                return (
                    VerificationStatus.CONFIRMED,
                    f"Live probe confirmed header '{target_header}' is genuinely missing from response headers.",
                    {"status_code": resp.status_code},
                )
            except Exception:
                # Fall back to evidence analysis
                pass

        # Static evidence fallback
        if finding.evidence:
            snippet = finding.evidence[0].content_snippet
            if "missing" in snippet.lower() or not snippet.strip():
                return (
                    VerificationStatus.LIKELY,
                    f"Evidence indicates header '{target_header}' is absent, but live probe was unavailable.",
                    {"evidence_snippet": snippet},
                )

        return (
            VerificationStatus.NEEDS_REVIEW,
            f"Evidence is insufficient to confirm or refute absence of header '{target_header}'.",
            {},
        )


class PassiveReflectionVerifier(BaseVerifier):
    """Verifies reflected XSS and input reflection without sending active attacks."""

    @property
    def verification_id(self) -> str:
        return "verifier_passive_reflection"

    @property
    def supported_finding_types(self) -> list[str]:
        return ["CWE-79"]

    @property
    def preconditions(self) -> list[str]:
        return ["web_url", "parameter_present"]

    @property
    def required_permission_level(self) -> PermissionLevel:
        return PermissionLevel.SAFE_AUDIT

    @property
    def evidence_requirements(self) -> list[str]:
        return ["content_snippet", "metadata.parameter"]

    @property
    def potential_impact(self) -> ImpactLevel:
        return ImpactLevel.NONE

    def verify(
        self,
        finding: NormalizedFinding,
        session: requests.Session | None = None,
    ) -> tuple[VerificationStatus, str, dict[str, Any]]:
        """Evaluate reflection evidence."""
        if not finding.evidence:
            return (
                VerificationStatus.UNVERIFIED,
                "No supporting evidence citations attached to reflection finding.",
                {},
            )

        snippet = finding.evidence[0].content_snippet
        attack = str(finding.evidence[0].metadata.get("attack", ""))

        # Check for safe encoding (False Positive indicator)
        if "&lt;script" in snippet.lower() or "&quot;" in snippet or "&#" in snippet:
            return (
                VerificationStatus.FALSE_POSITIVE,
                "Evidence snippet demonstrates input payload is safely HTML-entity encoded.",
                {"snippet": snippet},
            )

        # Check for unencoded script reflection (Confirmed indicator)
        if ("<script>" in snippet.lower() or "<script>alert(1)" in snippet.lower() or "onerror=" in snippet.lower()):
            return (
                VerificationStatus.CONFIRMED,
                "Evidence snippet demonstrates raw, unencoded payload reflection in HTML body.",
                {"snippet": snippet, "attack": attack},
            )

        # Non-standard or incomplete evidence requires human review
        return (
            VerificationStatus.NEEDS_REVIEW,
            "Reflection evidence is present but payload execution cannot be verified without active probing.",
            {"snippet": snippet},
        )


class LabGroundTruthVerifier(BaseVerifier):
    """Correlates findings with known authorized ground truth in OWASP Juice Shop."""

    # Ground truth mapping of known verified lab endpoints & weaknesses
    GROUND_TRUTH_VULNERABILITIES: dict[str, list[str]] = {
        "/#/search": ["CWE-79"],
        "/search": ["CWE-79"],
        "/rest/user/login": ["CWE-89", "CWE-352"],
        "/": ["CWE-693", "CWE-1021"],
        "/main.js": ["CWE-693"],
    }

    # Ground truth mapping of endpoints known to be secure against specific attacks
    GROUND_TRUTH_FALSE_POSITIVES: dict[str, list[str]] = {
        "/api/SecurityQuestions": ["CWE-89"],  # Parameterized ORM queries
        "/public/images": ["CWE-79"],
    }

    @property
    def verification_id(self) -> str:
        return "verifier_lab_ground_truth"

    @property
    def supported_finding_types(self) -> list[str]:
        return ["CWE-79", "CWE-89", "CWE-352", "CWE-693", "CWE-1021"]

    @property
    def preconditions(self) -> list[str]:
        return ["local_lab_target"]

    @property
    def required_permission_level(self) -> PermissionLevel:
        return PermissionLevel.SAFE_AUDIT

    @property
    def evidence_requirements(self) -> list[str]:
        return ["content_snippet"]

    @property
    def potential_impact(self) -> ImpactLevel:
        return ImpactLevel.NONE

    def verify(
        self,
        finding: NormalizedFinding,
        session: requests.Session | None = None,
    ) -> tuple[VerificationStatus, str, dict[str, Any]]:
        """Match finding against testbed ground truth."""
        url = finding.target.target_value.lower()
        cwe_str = f"CWE-{finding.cwe_id}" if finding.cwe_id else ""

        # Check known ground truth vulnerabilities
        for endpoint, cwes in self.GROUND_TRUTH_VULNERABILITIES.items():
            if endpoint.lower() in url and cwe_str in cwes:
                if finding.evidence and finding.evidence[0].content_snippet.strip():
                    return (
                        VerificationStatus.CONFIRMED,
                        f"Finding matches verified OWASP Juice Shop testbed ground truth flaw at '{endpoint}'.",
                        {"matched_endpoint": endpoint, "matched_cwe": cwe_str},
                    )

        # Check known false positives
        for endpoint, cwes in self.GROUND_TRUTH_FALSE_POSITIVES.items():
            if endpoint.lower() in url and cwe_str in cwes:
                return (
                    VerificationStatus.FALSE_POSITIVE,
                    f"Claimed vulnerability at '{endpoint}' contradicts known verified lab defensive controls.",
                    {"matched_endpoint": endpoint, "matched_cwe": cwe_str},
                )

        return (
            VerificationStatus.NEEDS_REVIEW,
            "Finding is outside predefined lab ground truth catalogue; requires human review.",
            {},
        )
