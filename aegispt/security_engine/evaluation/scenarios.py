"""Documented Ground Truth Benchmark Scenarios for OWASP Juice Shop.

TASK 1 & 2: Authoritative ground truth specifications derived independently
from documented lab architecture, NOT inferred from scanner telemetry.
"""

from aegispt.security_engine.evaluation.models import BenchmarkScenario
from aegispt.security_engine.schemas.enums import VerificationStatus

# Documented scenario catalogue for OWASP Juice Shop v17.1.1
JUICE_SHOP_BENCHMARK_SCENARIOS: list[BenchmarkScenario] = [
    # -------------------------------------------------------------
    # POSITIVE SAMPLES: Known Vulnerabilities (ground_truth=True)
    # -------------------------------------------------------------
    BenchmarkScenario(
        scenario_id="SCN-JUICE-XSS-01",
        description="Reflected XSS via unsanitized search parameter in Angular single-page interface.",
        lab_application="OWASP Juice Shop",
        target_endpoint="/#/search?q=",
        vulnerability_category="CWE-79",
        ground_truth=True,
        expected_scanner_behavior="DETECT_ALERT",
        expected_verification_status=VerificationStatus.CONFIRMED,
        evidence_requirements=["raw_unencoded_reflection", "parameter_q"],
    ),
    BenchmarkScenario(
        scenario_id="SCN-JUICE-SQLI-01",
        description="Classic SQL Injection in user authentication endpoint query string.",
        lab_application="OWASP Juice Shop",
        target_endpoint="/rest/user/login",
        vulnerability_category="CWE-89",
        ground_truth=True,
        expected_scanner_behavior="DETECT_ALERT",
        expected_verification_status=VerificationStatus.CONFIRMED,
        evidence_requirements=["sql_syntax_error_or_auth_bypass", "parameter_email"],
    ),
    BenchmarkScenario(
        scenario_id="SCN-JUICE-CSP-01",
        description="Absence of Content-Security-Policy (CSP) HTTP response header on web root.",
        lab_application="OWASP Juice Shop",
        target_endpoint="/",
        vulnerability_category="CWE-693",
        ground_truth=True,
        expected_scanner_behavior="DETECT_ALERT",
        expected_verification_status=VerificationStatus.CONFIRMED,
        evidence_requirements=["missing_content_security_policy_header"],
    ),
    BenchmarkScenario(
        scenario_id="SCN-JUICE-CSRF-01",
        description="Missing Anti-CSRF protection token on sensitive user profile forms.",
        lab_application="OWASP Juice Shop",
        target_endpoint="/rest/user/change-password",
        vulnerability_category="CWE-352",
        ground_truth=True,
        expected_scanner_behavior="DETECT_ALERT",
        expected_verification_status=VerificationStatus.CONFIRMED,
        evidence_requirements=["unprotected_state_changing_endpoint"],
    ),
    # -------------------------------------------------------------
    # NEGATIVE SAMPLES: Known Defensive Controls (ground_truth=False)
    # -------------------------------------------------------------
    BenchmarkScenario(
        scenario_id="SCN-JUICE-DEF-SQLI-01",
        description="Parameterized Sequelize ORM queries preventing SQL injection on Security Questions.",
        lab_application="OWASP Juice Shop",
        target_endpoint="/api/SecurityQuestions",
        vulnerability_category="CWE-89",
        ground_truth=False,
        expected_scanner_behavior="NO_ALERT",
        expected_verification_status=VerificationStatus.FALSE_POSITIVE,
        evidence_requirements=["parameterized_query_safeguard"],
    ),
    BenchmarkScenario(
        scenario_id="SCN-JUICE-DEF-XSS-01",
        description="Static non-executable asset delivery preventing script reflection in image endpoints.",
        lab_application="OWASP Juice Shop",
        target_endpoint="/public/images",
        vulnerability_category="CWE-79",
        ground_truth=False,
        expected_scanner_behavior="NO_ALERT",
        expected_verification_status=VerificationStatus.FALSE_POSITIVE,
        evidence_requirements=["static_binary_content_type"],
    ),
    BenchmarkScenario(
        scenario_id="SCN-JUICE-DEF-PASS-01",
        description="Secure password storage using modern hashing rather than cleartext storage.",
        lab_application="OWASP Juice Shop",
        target_endpoint="/api/Users",
        vulnerability_category="CWE-256",
        ground_truth=False,
        expected_scanner_behavior="NO_ALERT",
        expected_verification_status=VerificationStatus.FALSE_POSITIVE,
        evidence_requirements=["hashed_credential_storage"],
    ),
]
