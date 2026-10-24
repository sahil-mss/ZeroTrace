import pytest
from datetime import datetime, timezone
from backend.adapter import UpstreamNormalizer
from schemas.contracts import Assessment, Asset, Finding, Evidence
from schemas.enums import AssessmentStatus, AssetType, FindingSeverity, ConfidenceLevel, VerificationStatus
from modules.ai.service import AIAnalysisService
from modules.reporting.generator import ReportGenerator
from modules.reporting.exporter import ReportExporter


def test_upstream_normalizer_with_person1_schemas():
    """
    Validates that UpstreamNormalizer accurately maps Person 1 OSINT/database schemas
    into Person 3 shared contracts, preserving timestamps, provenance, and anti-upgrade invariants.
    """
    # 1. Representative Person 1 Assessment Record
    raw_p1_assessment = {
        "assessment_id": "assess_p1_test01",
        "title": "OWASP Juice Shop Penetration Test",
        "description": "Authorized black-box assessment",
        "organization_name": "Security Labs Corp",
        "authorized_by": "Lead Auditor",
        "scope": {
            "target_domains": ["127.0.0.1"],
            "target_urls": ["http://127.0.0.1:3000"],
            "target_ips": ["127.0.0.1"],
            "allowed_ports": [3000, 8080],
        },
        "status": "ACTIVE",
        "created_at": "2026-10-24T18:30:00Z",
        "completed_at": None,
    }

    norm_assessment = UpstreamNormalizer.normalize_assessment(raw_p1_assessment)
    assert norm_assessment.id == "assess_p1_test01"
    assert norm_assessment.name == "OWASP Juice Shop Penetration Test"
    assert norm_assessment.target == "http://127.0.0.1:3000"
    assert norm_assessment.status == AssessmentStatus.IN_PROGRESS

    # 2. Representative Person 1 Discovered Asset
    raw_p1_asset = {
        "asset_id": "asset_juice_01",
        "assessment_id": "assess_p1_test01",
        "asset_type": "WEB_APPLICATION",
        "value": "http://127.0.0.1:3000",
        "scope_status": "IN_SCOPE",
        "confidence": 1.0,
        "source_evidence_ids": ["evi_p1_01"],
        "metadata": {
            "server_banner": "Express.js",
            "open_ports": [3000],
        },
        "first_observed": "2026-10-24T18:31:00Z",
    }

    norm_asset = UpstreamNormalizer.normalize_asset(raw_p1_asset, norm_assessment.id)
    assert norm_asset.id == "asset_juice_01"
    assert norm_asset.hostname_or_address == "http://127.0.0.1:3000"
    assert norm_asset.asset_type == AssetType.WEB_APP
    assert len(norm_asset.discovered_services) == 1
    assert norm_asset.discovered_services[0].port == 3000

    # 3. Representative Person 1 Evidence Record with Cryptographic Hash
    raw_p1_evidence = {
        "evidence_id": "evi_p1_01",
        "assessment_id": "assess_p1_test01",
        "asset_id": "asset_juice_01",
        "source_type": "HTTP_FINGERPRINT",
        "tool_name": "http_adapter",
        "data": {
            "url": "http://127.0.0.1:3000/rest/products/search?q='",
            "status_code": 200,
            "error_snippet": "SQLITE_ERROR: syntax error near UNION SELECT",
        },
        "hash_sha256": "4b92b6a93e36e65bf33c46a6f1d011bf1cfefd2112a441ddbe789f2a4de3a525",
        "collected_at": "2026-10-24T18:35:00Z",
    }

    norm_evidence = UpstreamNormalizer.normalize_evidence(raw_p1_evidence, norm_assessment.id)
    assert norm_evidence.id == "evi_p1_01"
    assert norm_evidence.source == "http_adapter"
    assert "SQLITE_ERROR" in (norm_evidence.raw_data or "")

    # 4. Representative Person 1 / Person 2 Finding Record
    raw_p1_finding = {
        "finding_id": "find_sqli_01",
        "assessment_id": "assess_p1_test01",
        "asset_id": "asset_juice_01",
        "title": "SQL Injection in Search Endpoint",
        "description": "Error-based SQL injection confirmed on 'q' parameter.",
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "verification_status": "CONFIRMED",
        "evidence_ids": ["evi_p1_01"],
        "remediation": "Apply parameterized SQL queries.",
        "tool_name": "zap_fuzzer",
        "first_seen": "2026-10-24T18:35:10Z",
    }

    norm_finding = UpstreamNormalizer.normalize_finding(raw_p1_finding, norm_assessment.id)
    assert norm_finding.id == "find_sqli_01"
    assert norm_finding.severity == FindingSeverity.CRITICAL
    assert norm_finding.confidence == ConfidenceLevel.HIGH
    assert norm_finding.verification_status == VerificationStatus.CONFIRMED
    assert norm_finding.evidence_references == ["evi_p1_01"]


def test_anti_upgrade_rule_on_missing_evidence():
    """
    Enforces the zero-trust rule: an upstream finding claiming CONFIRMED
    without evidence is clamped to UNVERIFIED and confidence lowered.
    """
    raw_unbacked_finding = {
        "finding_id": "find_unbacked_01",
        "assessment_id": "assess_p1_test01",
        "asset_id": "asset_juice_01",
        "title": "Unbacked Finding",
        "description": "Scanner claims vulnerability without capturing payload evidence.",
        "severity": "HIGH",
        "confidence": 0.9,
        "verification_status": "CONFIRMED",
        "evidence_ids": [],  # Empty!
        "remediation": "Review code.",
        "tool_name": "speculative_scanner",
    }

    norm = UpstreamNormalizer.normalize_finding(raw_unbacked_finding)
    # Verification status must be safely demoted, never upgraded or permitted as CONFIRMED
    assert norm.verification_status == VerificationStatus.UNVERIFIED
    assert norm.confidence == ConfidenceLevel.LOW


def test_full_pipeline_from_raw_upstream_to_ai_and_report_export(tmp_path):
    """
    Executes one complete end-to-end path:
    Upstream OSINT/Scanner output -> Normalizer -> AI Analysis Service -> Report Generator -> Exporter
    """
    # 1. Raw inputs from Person 1 OSINT & Person 2 Scanners
    raw_assessment = {
        "assessment_id": "assess_e2e_001",
        "title": "E2E Integration Verification Test",
        "target": "http://127.0.0.1:3000",
        "status": "ACTIVE",
        "scope": {"target_urls": ["http://127.0.0.1:3000"]},
    }
    raw_asset = {
        "asset_id": "asset_e2e_01",
        "assessment_id": "assess_e2e_001",
        "asset_type": "WEB_APPLICATION",
        "value": "http://127.0.0.1:3000",
        "source": "nmap",
        "metadata": {"open_ports": [3000]},
    }
    raw_evidence = {
        "evidence_id": "evi_e2e_01",
        "assessment_id": "assess_e2e_001",
        "source_type": "SCANNER_ZAP",
        "tool_name": "zap_fuzzer",
        "data": {"payload": "UNION SELECT 1,2,3--", "response_code": 200},
        "hash_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    }
    raw_finding = {
        "finding_id": "find_e2e_01",
        "assessment_id": "assess_e2e_001",
        "asset_id": "asset_e2e_01",
        "title": "SQL Injection in User Search",
        "description": "Product search query parameter is vulnerable to SQL injection.",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "verification_status": "CONFIRMED",
        "evidence_ids": ["evi_e2e_01"],
        "remediation": "Use prepared statements.",
        "tool_name": "zap_fuzzer",
    }

    # 2. Normalize via adapter
    assessment = UpstreamNormalizer.normalize_assessment(raw_assessment)
    asset = UpstreamNormalizer.normalize_asset(raw_asset, assessment.id)
    evidence = UpstreamNormalizer.normalize_evidence(raw_evidence, assessment.id)
    finding = UpstreamNormalizer.normalize_finding(raw_finding, assessment.id)

    # 3. Feed into AI Analysis Service
    ai_service = AIAnalysisService()
    ai_analysis = ai_service.analyze_finding(finding, [evidence])

    assert ai_analysis.summary is not None
    assert ai_analysis.severity == FindingSeverity.CRITICAL
    assert "evi_e2e_01" in ai_analysis.cited_evidence_ids
    assert ai_analysis.is_rule_based_fallback is True

    # 4. Feed into Report Generator
    report_gen = ReportGenerator()
    report = report_gen.generate(
        assessment=assessment,
        assets=[asset],
        findings=[finding],
        evidence=[evidence],
        ai_analyses={finding.id: ai_analysis},
    )

    assert report.assessment_id == "assess_e2e_001"
    assert report.executive_summary is not None
    assert len(report.findings) == 1
    assert report.severity_breakdown["critical"] == 1

    # 5. Export Report to Markdown, JSON, and HTML
    import os
    out_dir = str(tmp_path)
    md_str = ReportExporter.to_markdown(report)
    json_str = ReportExporter.to_json(report)
    html_str = ReportExporter.to_html(report)

    assert "E2E Integration Verification Test" in md_str
    assert "SQL Injection in User Search" in md_str
    assert "evi_e2e_01" in md_str
    assert "critical" in json_str
    assert "<html" in html_str

    md_path = ReportExporter.save_to_file(report, f"{out_dir}/report.md")
    json_path = ReportExporter.save_to_file(report, f"{out_dir}/report.json")
    html_path = ReportExporter.save_to_file(report, f"{out_dir}/report.html")

    assert os.path.exists(md_path)
    assert os.path.exists(json_path)
    assert os.path.exists(html_path)
