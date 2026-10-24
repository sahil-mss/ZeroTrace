import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aegis_common.enums import (
    AssessmentStatus,
    AssetType,
    AuditOutcome,
    DataClassification,
    EvidenceSourceType,
    JobStatus,
    Severity,
    TargetType,
    VerificationStatus,
)
from aegis_common.models import (
    Assessment,
    Asset,
    AuditEvent,
    Evidence,
    Finding,
    Job,
    ScopeRule,
)
from aegis_common.schemas_generator import generate_json_schemas

# ==============================================================================
# 1. Assessment Model Tests
# ==============================================================================


def test_assessment_valid_creation():
    rule = ScopeRule(
        target_type=TargetType.DOMAIN,
        target_value="lab.example.test",
        include_subdomains=False,
    )
    assessment = Assessment(
        name="Security Audit Q4",
        organization_name="Acme Labs",
        authorized_by="Alice CISO",
        authorization_reference="AUTH-2026-001",
        authorization_acknowledged=True,
        scope_rules=[rule],
    )

    # Must default to PENDING_APPROVAL - not approved merely because it was created
    assert assessment.lifecycle_status == AssessmentStatus.PENDING_APPROVAL
    assert assessment.authorization_acknowledged is True
    assert assessment.created_at.tzinfo == UTC
    assert len(assessment.scope_rules) == 1
    assert assessment.schema_version == "1.0"


def test_assessment_missing_required_fields():
    with pytest.raises(ValidationError) as exc:
        Assessment(
            name="Missing Org Assessment",
            # organization_name missing
            authorized_by="Bob",
        )
    assert "organization_name" in str(exc.value)


def test_assessment_unsupported_extra_fields():
    with pytest.raises(ValidationError):
        Assessment(
            name="Valid Name",
            organization_name="Acme",
            authorized_by="Alice",
            unexpected_backdoor_field="malicious_payload",
        )


def test_assessment_invalid_enum_status():
    with pytest.raises(ValidationError):
        Assessment(
            name="Valid Name",
            organization_name="Acme",
            authorized_by="Alice",
            lifecycle_status="SUPER_ADMIN_APPROVED",  # Invalid enum
        )


# ==============================================================================
# 2. ScopeRule Contract Tests
# ==============================================================================


def test_scope_rule_valid_boundaries():
    # Domain rule: subdomains must NOT be automatically authorized
    d_rule = ScopeRule(
        target_type=TargetType.DOMAIN,
        target_value="lab.example.test",
    )
    assert d_rule.include_subdomains is False  # Default to narrowest permission
    assert d_rule.target_value == "lab.example.test"

    # Valid IP address
    ip_rule = ScopeRule(
        target_type=TargetType.IP_ADDRESS,
        target_value="192.168.1.50",
        approved_ports=[80, 443],
    )
    assert ip_rule.approved_ports == [80, 443]

    # Valid CIDR
    cidr_rule = ScopeRule(
        target_type=TargetType.CIDR,
        target_value="10.0.0.0/24",
    )
    assert cidr_rule.target_type == TargetType.CIDR

    # Valid URL
    url_rule = ScopeRule(
        target_type=TargetType.URL,
        target_value="https://juice-shop.local:3000/rest",
        permitted_path_prefixes=["/rest"],
    )
    assert url_rule.target_value == "https://juice-shop.local:3000/rest"


def test_scope_rule_malformed_targets():
    # Invalid IP
    with pytest.raises(ValidationError) as exc:
        ScopeRule(target_type=TargetType.IP_ADDRESS, target_value="999.999.999.999")
    assert "Invalid IP address format" in str(exc.value)

    # Invalid CIDR
    with pytest.raises(ValidationError) as exc:
        ScopeRule(target_type=TargetType.CIDR, target_value="192.168.1.1/35")
    assert "Invalid CIDR range format" in str(exc.value)

    # Invalid URL scheme
    with pytest.raises(ValidationError) as exc:
        ScopeRule(target_type=TargetType.URL, target_value="ftp://example.com")
    assert "http or https scheme" in str(exc.value)

    # Domain with URL scheme
    with pytest.raises(ValidationError) as exc:
        ScopeRule(target_type=TargetType.DOMAIN, target_value="http://not-a-pure-domain.com")
    assert "must not contain URL schemes" in str(exc.value)

    # Empty target
    with pytest.raises(ValidationError):
        ScopeRule(target_type=TargetType.DOMAIN, target_value="   ")

    # Invalid port range
    with pytest.raises(ValidationError) as exc:
        ScopeRule(target_type=TargetType.DOMAIN, target_value="test.com", approved_ports=[0, 80])
    assert "outside valid range 1-65535" in str(exc.value)

    with pytest.raises(ValidationError) as exc:
        ScopeRule(target_type=TargetType.DOMAIN, target_value="test.com", approved_ports=[70000])
    assert "outside valid range 1-65535" in str(exc.value)


# ==============================================================================
# 3. Asset Model Tests
# ==============================================================================


def test_asset_confidence_and_inferred_flags():
    # Directly observed asset
    asset1 = Asset(
        assessment_id="assess_01",
        asset_type=AssetType.WEB_APPLICATION,
        normalized_value="http://127.0.0.1:3000",
        confidence=1.0,
        is_inferred=False,
    )
    assert asset1.directly_observed is True
    assert asset1.confidence == 1.0

    # Inferred asset
    asset2 = Asset(
        assessment_id="assess_01",
        asset_type=AssetType.SUBDOMAIN,
        normalized_value="auth.example.test",
        confidence=0.75,
        is_inferred=True,
    )
    assert asset2.directly_observed is False
    assert asset2.confidence == 0.75


def test_asset_invalid_confidence_range():
    with pytest.raises(ValidationError) as exc:
        Asset(
            assessment_id="assess_01",
            asset_type=AssetType.DOMAIN,
            normalized_value="test.com",
            confidence=1.5,  # Exceeds 1.0
        )
    assert "less than or equal to 1" in str(exc.value)

    with pytest.raises(ValidationError) as exc:
        Asset(
            assessment_id="assess_01",
            asset_type=AssetType.DOMAIN,
            normalized_value="test.com",
            confidence=-0.1,  # Below 0.0
        )
    assert "greater than or equal to 0" in str(exc.value)


def test_asset_timezone_handling():
    naive_time = datetime(2026, 10, 24, 12, 0, 0)
    asset = Asset(
        assessment_id="assess_01",
        asset_type=AssetType.IP_ADDRESS,
        normalized_value="10.0.0.1",
        first_seen=naive_time,
    )
    assert asset.first_seen.tzinfo == UTC


# ==============================================================================
# 4. Evidence Model Tests
# ==============================================================================


def test_evidence_sanitization_and_hash():
    valid_hash = "a" * 64
    raw_sensitive_data = {
        "headers": {"Host": "lab.example.test"},
        "token": "secret_bearer_token_xyz",
        "nested": {
            "api_key": "sensitive_api_key_123",
            "safe_val": "public_data",
        },
    }

    evidence = Evidence(
        assessment_id="assess_01",
        source_name="NmapScanner",
        source_type=EvidenceSourceType.SCANNER_NMAP,
        content_hash=valid_hash,
        data=raw_sensitive_data,
        data_classification=DataClassification.CONFIDENTIAL,
    )

    # Ensure sensitive credentials were automatically redacted
    assert evidence.data["token"] == "[REDACTED]"
    assert evidence.data["nested"]["api_key"] == "[REDACTED]"
    assert evidence.data["nested"]["safe_val"] == "public_data"
    assert evidence.content_hash == valid_hash


def test_evidence_invalid_hash_length():
    with pytest.raises(ValidationError) as exc:
        Evidence(
            assessment_id="assess_01",
            source_name="Tool",
            source_type=EvidenceSourceType.DNS_LOOKUP,
            content_hash="too_short",  # Not 64 chars
        )
    assert "content_hash" in str(exc.value)


# ==============================================================================
# 5. Finding Model Tests
# ==============================================================================


def test_finding_valid_and_non_confirmed_default():
    finding = Finding(
        assessment_id="assess_01",
        asset_id="asset_01",
        title="Missing Content-Security-Policy",
        description="The web server does not return a CSP header.",
        cwe="CWE-1021",
        cve="CVE-2023-12345",
        severity=Severity.LOW,
        confidence=0.9,
        evidence_ids=["evi_001"],
        remediation="Configure a Content-Security-Policy header.",
        source_tool="ZAP",
    )

    # Must never default to CONFIRMED
    assert finding.verification_status == VerificationStatus.UNVERIFIED
    assert finding.cwe == "CWE-1021"
    assert finding.cve == "CVE-2023-12345"


def test_finding_empty_evidence_ids_rejected():
    with pytest.raises(ValidationError) as exc:
        Finding(
            assessment_id="assess_01",
            asset_id="asset_01",
            title="SQL Injection",
            description="Vulnerable parameter id.",
            severity=Severity.HIGH,
            evidence_ids=[],  # Empty evidence IDs forbidden
            remediation="Use parameterized queries.",
            source_tool="SQLMap",
        )
    assert "evidence_ids" in str(exc.value)


def test_finding_malformed_cve_and_cwe():
    with pytest.raises(ValidationError) as exc:
        Finding(
            assessment_id="assess_01",
            asset_id="asset_01",
            title="Vulnerability",
            description="Description.",
            severity=Severity.MEDIUM,
            evidence_ids=["evi_01"],
            cve="NOT-A-CVE",
            remediation="Fix it.",
            source_tool="Tool",
        )
    assert "Malformed CVE identifier" in str(exc.value)

    with pytest.raises(ValidationError) as exc:
        Finding(
            assessment_id="assess_01",
            asset_id="asset_01",
            title="Vulnerability",
            description="Description.",
            severity=Severity.MEDIUM,
            evidence_ids=["evi_01"],
            cwe="INVALID_CWE",
            remediation="Fix it.",
            source_tool="Tool",
        )
    assert "Malformed CWE identifier" in str(exc.value)


# ==============================================================================
# 6. Job Model Tests
# ==============================================================================


def test_job_resource_budget_and_timeouts():
    job = Job(
        assessment_id="assess_01",
        task_type="OSINT_DNS",
        requested_targets=["lab.example.test"],
        timeout_seconds=300,
    )

    assert job.status == JobStatus.CREATED
    assert job.target_input == "lab.example.test"
    assert job.resource_budget.timeout_seconds == 300
    assert job.cancellation_requested is False


def test_job_unsupported_extra_fields():
    with pytest.raises(ValidationError):
        Job(
            assessment_id="assess_01",
            task_type="PORT_SCAN",
            arbitrary_extra_field="rejected",
        )


# ==============================================================================
# 7. AuditEvent Model Tests
# ==============================================================================


def test_audit_event_sanitization_and_outcome():
    event = AuditEvent(
        assessment_id="assess_01",
        event_type="AUTH_LOGIN",
        actor="operator_1",
        outcome=AuditOutcome.SUCCESS,
        sanitized_metadata={"password": "raw_password_123", "ip": "127.0.0.1"},
    )

    assert event.outcome == AuditOutcome.SUCCESS
    assert event.sanitized_metadata["password"] == "[REDACTED]"
    assert event.sanitized_metadata["ip"] == "127.0.0.1"
    assert event.timestamp.tzinfo == UTC


# ==============================================================================
# 8. Schema Generator Repeatability Test
# ==============================================================================


def test_repeatable_json_schema_generation(tmp_path):
    generated = generate_json_schemas(output_dir=str(tmp_path))
    assert len(generated) == 7

    for _filename, filepath in generated.items():
        assert filepath.exists()
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        assert "$schema" in data
        assert "title" in data
        assert "properties" in data
