import json
from datetime import UTC, datetime

import pytest

from modules.ai.analyst import FindingAnalyst
from modules.ai.planner import SafeTestPlanner
from modules.reporting.exporter import ReportExporter
from modules.reporting.generator import ReportGenerator
from schemas.contracts import Assessment, Asset, Evidence, Finding
from schemas.enums import (
    AssessmentStatus,
    AssetType,
    ConfidenceLevel,
    FindingSeverity,
    VerificationStatus,
)


@pytest.fixture
def sample_data():
    now = datetime.now(UTC)
    assessment = Assessment(
        id="asm_test_01",
        name="Lab Juice Shop Audit",
        target="http://127.0.0.1:3000",
        status=AssessmentStatus.IN_PROGRESS,
        created_at=now,
    )

    asset = Asset(
        id="ast_web_01",
        assessment_id="asm_test_01",
        hostname_or_address="127.0.0.1:3000",
        asset_type=AssetType.WEB_APP,
        source="nmap",
    )

    evidence = Evidence(
        id="ev_sqli_01",
        source="owasp_zap",
        description="Union query returned administrative email in response body",
        observed_at=now,
        asset_id="ast_web_01",
        raw_data='HTTP 200 OK\n[{"id":1,"email":"admin@test.local"}]',
    )

    finding = Finding(
        id="fnd_sqli_01",
        assessment_id="asm_test_01",
        asset_id="ast_web_01",
        title="Union SQL Injection in Search API",
        description="Search parameter is unescaped, allowing arbitrary database extraction.",
        severity=FindingSeverity.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        verification_status=VerificationStatus.CONFIRMED,
        evidence_references=["ev_sqli_01"],
        source_tool="owasp_zap",
        cwe="CWE-89",
    )

    return assessment, [asset], [finding], [evidence]


def test_ai_finding_analyst(sample_data):
    assessment, assets, findings, evidence = sample_data
    analyst = FindingAnalyst()

    analysis = analyst.analyze_finding(findings[0], evidence)
    assert analysis.severity_assessment == FindingSeverity.CRITICAL
    assert "ev_sqli_01" in analysis.cited_evidence_ids
    assert len(analysis.recommended_remediation) > 0
    # Must pass citation guard against real evidence IDs
    analysis.validate_citations({"ev_sqli_01"})


def test_ai_planner(sample_data):
    assessment, assets, findings, evidence = sample_data
    planner = SafeTestPlanner()

    recommendations = planner.plan_next_steps(
        assessment=assessment,
        assets=assets,
        existing_findings=findings,
        previously_run_profiles=[],
    )

    assert len(recommendations) > 0
    assert recommendations[0].recommended_profile == "passive_web_crawl"
    assert recommendations[0].target_asset_id == assets[0].id


def test_report_generator_and_export(sample_data, tmp_path):
    assessment, assets, findings, evidence = sample_data
    analyst = FindingAnalyst()
    analysis = analyst.analyze_finding(findings[0], evidence)

    generator = ReportGenerator()
    report = generator.generate(
        assessment=assessment,
        assets=assets,
        findings=findings,
        evidence=evidence,
        ai_analyses={findings[0].id: analysis},
    )

    assert report.total_findings == 1
    assert report.verified_findings_count == 1
    assert report.severity_breakdown["critical"] == 1
    assert "Critical" in report.executive_summary

    # Exporter tests
    md = ReportExporter.to_markdown(report)
    assert "# Security Assessment Report" in md
    assert "Union SQL Injection in Search API" in md

    json_str = ReportExporter.to_json(report)
    parsed = json.loads(json_str)
    assert parsed["assessment_id"] == "asm_test_01"

    html = ReportExporter.to_html(report)
    assert "<!DOCTYPE html>" in html

    # File saving
    md_file = ReportExporter.save_to_file(report, tmp_path / "report.md")
    assert md_file.exists()
    assert md_file.stat().st_size > 0
