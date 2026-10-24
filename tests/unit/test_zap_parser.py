"""Unit tests for ZAPAlertParser using static JSON fixtures."""

from pathlib import Path
import pytest

from aegispt.security_engine.integrations.zap.parser import (
    ZAPAlertParser,
    ZAPParserError,
)
from aegispt.security_engine.schemas import Severity

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "zap"


class TestZAPAlertParser:
    """Verifies alert parsing, field extraction, severity mappings, and error handling."""

    def test_parse_flat_alerts_and_severities(self) -> None:
        """Verify extraction of High, Medium, Low, and Informational alerts from flat list."""
        fixture_path = FIXTURES_DIR / "sample_alerts_flat.json"
        findings = ZAPAlertParser.parse_file(fixture_path)

        assert len(findings) == 4

        # 1. High: Reflected XSS
        xss = next(f for f in findings if "Cross Site Scripting" in f.title)
        assert xss.severity == Severity.HIGH
        assert xss.cwe_id == 79
        assert xss.target.target_value.startswith("http://127.0.0.1:3000/")
        assert len(xss.evidence) == 1
        assert "<script>alert(1)</script>" in xss.evidence[0].content_snippet
        assert xss.verified is False  # Strict specification requirement

        # 2. Medium: Anti-CSRF
        csrf = next(f for f in findings if "Anti-CSRF" in f.title)
        assert csrf.severity == Severity.MEDIUM
        assert csrf.cwe_id == 352
        assert csrf.verified is False

        # 3. Low: CSP Header Missing
        csp = next(f for f in findings if "Content Security Policy" in f.title)
        assert csp.severity == Severity.LOW
        assert csp.cwe_id == 693
        assert csp.verified is False

        # 4. Info: Cacheable Content
        cache = next(f for f in findings if "Cacheable Content" in f.title)
        assert cache.severity == Severity.INFO
        assert cache.cwe_id == 524
        assert cache.verified is False

    def test_parse_automation_framework_nested_report(self) -> None:
        """Verify parsing of nested Automation Framework report (site -> alerts -> instances)."""
        fixture_path = FIXTURES_DIR / "sample_automation_report.json"
        findings = ZAPAlertParser.parse_file(fixture_path)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "X-Content-Type-Options Header Missing"
        assert finding.severity == Severity.LOW
        assert finding.cwe_id == 693
        assert finding.target.target_value == "http://127.0.0.1:3000/main.js"
        assert finding.verified is False

    def test_parse_missing_fields_gracefully(self) -> None:
        """Alerts with omitted optional fields (no evidence, no CWE, no solution) parse cleanly."""
        fixture_path = FIXTURES_DIR / "sample_missing_fields.json"
        findings = ZAPAlertParser.parse_file(fixture_path)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "Missing Headers Alert"
        assert finding.severity == Severity.LOW
        assert finding.cwe_id is None
        assert finding.remediation is None
        assert finding.target.target_value == "http://127.0.0.1:3000/api"
        assert len(finding.evidence) == 1
        assert finding.verified is False

    def test_parse_malformed_json_strict_raises_error(self) -> None:
        """Malformed JSON raises ZAPParserError when strict=True."""
        fixture_path = FIXTURES_DIR / "sample_malformed.json"
        with pytest.raises(ZAPParserError) as exc_info:
            ZAPAlertParser.parse_file(fixture_path, strict=True)
        assert "Malformed ZAP JSON document" in str(exc_info.value)

    def test_parse_malformed_json_non_strict_returns_empty(self) -> None:
        """Malformed JSON returns empty list when strict=False."""
        fixture_path = FIXTURES_DIR / "sample_malformed.json"
        findings = ZAPAlertParser.parse_file(fixture_path, strict=False)
        assert findings == []

    def test_empty_string_handling(self) -> None:
        """Empty string handled cleanly."""
        with pytest.raises(ZAPParserError):
            ZAPAlertParser.parse_string("", strict=True)

        assert ZAPAlertParser.parse_string("", strict=False) == []
