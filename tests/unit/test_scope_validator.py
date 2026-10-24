from datetime import UTC, datetime, timedelta

import pytest

from aegis_common.enums import (
    AssessmentStatus,
    ScopeStatus,
    TargetType,
    TestPermissionLevel,
)
from aegis_common.models import Assessment, ScopePolicy, ScopeRule
from backend.app.services.scope_validator import (
    ScopeReasonCode,
    ScopeValidationError,
    ScopeValidator,
    normalize_target,
    validate_redirect,
    validate_resolved_ip,
    validate_target,
)


def test_canonicalize_various_targets():
    """Verify target canonicalization across domains, URLs, ports, and whitespace."""
    # Domain with trailing dot and mixed case
    c1 = ScopeValidator.canonicalize("  Lab.Example.Test. ")
    assert c1["hostname"] == "lab.example.test"
    assert c1["port"] is None

    # URL with port and path
    c2 = ScopeValidator.canonicalize("http://127.0.0.1:3000/api/v1?test=1")
    assert c2["hostname"] == "127.0.0.1"
    assert c2["port"] == 3000
    assert c2["scheme"] == "http"

    # Host with port
    c3 = ScopeValidator.canonicalize("internal.lab:8443")
    assert c3["hostname"] == "internal.lab"
    assert c3["port"] == 8443

    # Malformed empty target
    with pytest.raises(ScopeValidationError):
        ScopeValidator.canonicalize("")


def test_scope_validation_in_scope_and_out_of_scope():
    """Verify legacy ScopePolicy evaluation for domains, CIDR, and ports."""
    scope = ScopePolicy(
        target_domains=["lab.example.test", "*.sub.example.test"],
        target_ips=["127.0.0.1"],
        target_cidrs=["192.168.50.0/24"],
        target_urls=["http://localhost:3000"],
        excluded_targets=["forbidden.sub.example.test", "192.168.50.99"],
        allowed_ports=[80, 443, 3000, 8080],
    )

    # 1. Exact domain in scope
    ok, reason, status = ScopeValidator.is_in_scope("lab.example.test", scope)
    assert ok is True
    assert status == ScopeStatus.IN_SCOPE

    # 2. Wildcard match
    ok, reason, status = ScopeValidator.is_in_scope("api.sub.example.test", scope)
    assert ok is True
    assert status == ScopeStatus.IN_SCOPE

    # 3. Disallowed external domain (Must be rejected!)
    ok, reason, status = ScopeValidator.is_in_scope("external-target.com", scope)
    assert ok is False
    assert status == ScopeStatus.OUT_OF_SCOPE

    # 4. Explicitly excluded target (Hard deny even if under wildcard)
    ok, reason, status = ScopeValidator.is_in_scope("forbidden.sub.example.test", scope)
    assert ok is False
    assert "matches excluded target" in reason

    # 5. CIDR match
    ok, reason, status = ScopeValidator.is_in_scope("192.168.50.15", scope)
    assert ok is True
    assert status == ScopeStatus.IN_SCOPE

    # 6. Excluded IP in CIDR
    ok, reason, status = ScopeValidator.is_in_scope("192.168.50.99", scope)
    assert ok is False
    assert "matches excluded target" in reason

    # 7. Disallowed port
    ok, reason, status = ScopeValidator.is_in_scope("lab.example.test:22", scope)
    assert ok is False
    assert "Port 22 is not in allowed_ports list" in reason


def test_permission_level_enforcement():
    """Verify tool action permission hierarchies are strictly enforced."""
    ok, reason = ScopeValidator.check_permission(
        requested_level=TestPermissionLevel.INTRUSIVE_TEST,
        allowed_level=TestPermissionLevel.PASSIVE_ONLY,
    )
    assert ok is False
    assert "exceeds assessment permission" in reason

    ok, reason = ScopeValidator.check_permission(
        requested_level=TestPermissionLevel.PASSIVE_ONLY,
        allowed_level=TestPermissionLevel.CONTROLLED_VULN_SCAN,
    )
    assert ok is True


# =========================================================================
# SESSION 4: DETERMINISTIC SCOPE VALIDATOR EXTENSIVE TEST CASES
# =========================================================================


def test_exact_approved_domain():
    """Exact approved domain matches; subdomains rejected by default."""
    rule = ScopeRule(
        target_type=TargetType.DOMAIN,
        target_value="example.test",
        include_subdomains=False,  # Default
    )
    assessment = Assessment(
        assessment_id="assess_exact_dom",
        name="Exact Domain Test",
        organization_name="TestOrg",
        authorized_by="LeadTester",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[rule],
    )

    # 1. Exact match -> ALLOWED
    res = validate_target("example.test", assessment)
    assert res.allowed is True
    assert res.reason_code == ScopeReasonCode.ALLOWED
    assert res.effective_host == "example.test"

    # 2. Subdomain without include_subdomains -> DENIED
    res_sub = validate_target("sub.example.test", assessment)
    assert res_sub.allowed is False
    assert res_sub.reason_code == ScopeReasonCode.SUBDOMAIN_NOT_PERMITTED


def test_subdomain_permissions_explicit_vs_default():
    """Subdomains allowed only when include_subdomains=True is explicitly enabled."""
    rules = [
        ScopeRule(
            target_type=TargetType.DOMAIN,
            target_value="corp.internal",
            include_subdomains=True,
        ),
        ScopeRule(
            target_type=TargetType.DOMAIN,
            target_value="app.internal",
            include_subdomains=False,
        ),
    ]
    assessment = Assessment(
        assessment_id="assess_sub_test",
        name="Subdomain Test",
        organization_name="TestOrg",
        authorized_by="LeadTester",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=rules,
    )

    # Allowed multi-level subdomains for corp.internal
    res1 = validate_target("api.corp.internal", assessment)
    assert res1.allowed is True
    assert res1.reason_code == ScopeReasonCode.ALLOWED

    res2 = validate_target("v1.dev.corp.internal", assessment)
    assert res2.allowed is True

    # Disallowed subdomain for app.internal
    res3 = validate_target("api.app.internal", assessment)
    assert res3.allowed is False
    assert res3.reason_code == ScopeReasonCode.SUBDOMAIN_NOT_PERMITTED


def test_lookalike_domains_rejected():
    """Substring and lookalike domains must never match approved domain."""
    rule = ScopeRule(
        target_type=TargetType.DOMAIN,
        target_value="target.test",
        include_subdomains=True,
    )
    assessment = Assessment(
        assessment_id="assess_lookalike",
        name="Lookalike Test",
        organization_name="TestOrg",
        authorized_by="LeadTester",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[rule],
    )

    # Substring matches must be strictly rejected
    bad_targets = [
        "another-target.test",
        "evil-target.test",
        "nottarget.test",
        "target.test.attacker.com",
        "target.testing",
    ]
    for bad in bad_targets:
        res = validate_target(bad, assessment)
        assert res.allowed is False, f"Target '{bad}' must be rejected!"
        assert res.reason_code == ScopeReasonCode.TARGET_NOT_IN_SCOPE


def test_allowed_and_disallowed_ip_addresses():
    """Explicitly approved IP allowed; non-matching IP denied."""
    rule = ScopeRule(
        target_type=TargetType.IP_ADDRESS,
        target_value="192.168.1.50",
    )
    assessment = Assessment(
        assessment_id="assess_ip_test",
        name="IP Test",
        organization_name="TestOrg",
        authorized_by="LeadTester",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[rule],
    )

    # Exact IP -> ALLOWED
    res_good = validate_target("192.168.1.50", assessment)
    assert res_good.allowed is True
    assert res_good.reason_code == ScopeReasonCode.ALLOWED

    # Different IP -> DENIED
    res_bad = validate_target("192.168.1.51", assessment)
    assert res_bad.allowed is False
    assert res_bad.reason_code == ScopeReasonCode.TARGET_NOT_IN_SCOPE


def test_explicitly_permitted_cidr_and_outside_ip():
    """IP within CIDR allowed; IP outside CIDR denied; domains do not match CIDR."""
    rules = [
        ScopeRule(
            target_type=TargetType.CIDR,
            target_value="10.20.0.0/16",
        ),
        ScopeRule(
            target_type=TargetType.CIDR,
            target_value="10.20.99.0/24",
            is_excluded=True,
        ),
    ]
    assessment = Assessment(
        assessment_id="assess_cidr_test",
        name="CIDR Test",
        organization_name="TestOrg",
        authorized_by="LeadTester",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=rules,
    )

    # Inside allowed CIDR
    res1 = validate_target("10.20.5.12", assessment)
    assert res1.allowed is True
    assert res1.reason_code == ScopeReasonCode.ALLOWED

    # Outside allowed CIDR
    res2 = validate_target("10.21.5.12", assessment)
    assert res2.allowed is False
    assert res2.reason_code == ScopeReasonCode.TARGET_NOT_IN_SCOPE

    # Inside excluded CIDR -> Hard deny
    res3 = validate_target("10.20.99.5", assessment)
    assert res3.allowed is False
    assert res3.reason_code == ScopeReasonCode.EXCLUDED_TARGET


def test_port_boundaries():
    """Effective port must satisfy approved_ports on matching rule."""
    rule = ScopeRule(
        target_type=TargetType.DOMAIN,
        target_value="api.internal",
        approved_ports=[8080, 8443],
    )
    assessment = Assessment(
        assessment_id="assess_port_test",
        name="Port Test",
        organization_name="TestOrg",
        authorized_by="LeadTester",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[rule],
    )

    # Approved ports
    res1 = validate_target("api.internal:8080", assessment)
    assert res1.allowed is True

    res2 = validate_target("api.internal:8443", assessment)
    assert res2.allowed is True

    # Disallowed port
    res3 = validate_target("api.internal:22", assessment)
    assert res3.allowed is False
    assert res3.reason_code == ScopeReasonCode.PORT_NOT_PERMITTED


def test_http_https_default_ports():
    """HTTP defaults to port 80; HTTPS defaults to port 443; effective ports are significant."""
    # Scope only approves port 443 (HTTPS)
    rule = ScopeRule(
        target_type=TargetType.DOMAIN,
        target_value="secure.internal",
        approved_ports=[443],
    )
    assessment = Assessment(
        assessment_id="assess_default_ports",
        name="Default Ports Test",
        organization_name="TestOrg",
        authorized_by="LeadTester",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[rule],
    )

    # HTTPS URL with implicit port 443 -> ALLOWED
    res_https = validate_target("https://secure.internal/login", assessment)
    assert res_https.allowed is True
    assert res_https.effective_port == 443

    # HTTP URL with implicit port 80 -> DENIED (port 80 not in [443])
    res_http = validate_target("http://secure.internal/login", assessment)
    assert res_http.allowed is False
    assert res_http.reason_code == ScopeReasonCode.PORT_NOT_PERMITTED


def test_url_path_prefixes():
    """Path prefixes are enforced; relative traversal normalized before prefix testing."""
    rule = ScopeRule(
        target_type=TargetType.DOMAIN,
        target_value="web.internal",
        permitted_path_prefixes=["/api/v1", "/public"],
    )
    assessment = Assessment(
        assessment_id="assess_path_test",
        name="Path Prefix Test",
        organization_name="TestOrg",
        authorized_by="LeadTester",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[rule],
    )

    # Permitted prefixes
    res1 = validate_target("https://web.internal/api/v1/users", assessment)
    assert res1.allowed is True

    res2 = validate_target("https://web.internal/public/styles.css", assessment)
    assert res2.allowed is True

    # Disallowed prefix
    res3 = validate_target("https://web.internal/admin", assessment)
    assert res3.allowed is False
    assert res3.reason_code == ScopeReasonCode.PATH_NOT_PERMITTED

    # Path traversal attack normalized and blocked
    res4 = validate_target("https://web.internal/api/v1/../../admin/secret", assessment)
    assert res4.allowed is False
    assert res4.effective_path == "/admin/secret"
    assert res4.reason_code == ScopeReasonCode.PATH_NOT_PERMITTED


def test_malformed_urls_and_embedded_credentials():
    """Rejects embedded credentials, unsupported schemes, and malformed inputs."""
    assessment = Assessment(
        assessment_id="assess_malform_test",
        name="Malformed Test",
        organization_name="TestOrg",
        authorized_by="LeadTester",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[ScopeRule(target_type=TargetType.DOMAIN, target_value="target.internal")],
    )

    # Embedded credentials rejected
    res_cred = validate_target("http://admin:secret@target.internal/api", assessment)
    assert res_cred.allowed is False
    assert res_cred.reason_code == ScopeReasonCode.MALFORMED_TARGET
    assert "credentials" in res_cred.explanation.lower()

    # Unsupported scheme rejected
    res_ftp = validate_target("ftp://target.internal/files", assessment)
    assert res_ftp.allowed is False
    assert res_ftp.reason_code == ScopeReasonCode.MALFORMED_TARGET

    # Empty or unparseable target
    res_empty = validate_target("", assessment)
    assert res_empty.allowed is False
    assert res_empty.reason_code == ScopeReasonCode.MALFORMED_TARGET


def test_out_of_scope_redirect():
    """validate_redirect checks source and destination independently; no inherited authorization."""
    assessment = Assessment(
        assessment_id="assess_redirect_test",
        name="Redirect Test",
        organization_name="TestOrg",
        authorized_by="LeadTester",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[
            ScopeRule(target_type=TargetType.DOMAIN, target_value="login.internal"),
            ScopeRule(target_type=TargetType.DOMAIN, target_value="dashboard.internal"),
        ],
    )

    # 1. In-scope to in-scope redirect -> ALLOWED
    res_ok = validate_redirect(
        source_url="https://login.internal/auth",
        destination_url="https://dashboard.internal/home",
        assessment_scope=assessment,
    )
    assert res_ok.allowed is True
    assert res_ok.reason_code == ScopeReasonCode.REDIRECT_ALLOWED

    # 2. In-scope to out-of-scope redirect -> DENIED
    res_ext = validate_redirect(
        source_url="https://login.internal/auth",
        destination_url="https://external-phishing.test/harvest",
        assessment_scope=assessment,
    )
    assert res_ext.allowed is False
    assert res_ext.reason_code == ScopeReasonCode.REDIRECT_DESTINATION_OUT_OF_SCOPE

    # 3. Disallowed source redirect -> DENIED
    res_bad_src = validate_redirect(
        source_url="https://attacker.com/init",
        destination_url="https://dashboard.internal/home",
        assessment_scope=assessment,
    )
    assert res_bad_src.allowed is False
    assert res_bad_src.reason_code == ScopeReasonCode.REDIRECT_SOURCE_DISALLOWED


def test_expired_or_unapproved_assessment():
    """Unapproved or expired assessments fail closed."""
    rule = ScopeRule(target_type=TargetType.DOMAIN, target_value="safe.internal")

    # 1. Assessment in PENDING_APPROVAL status -> DENIED
    pending_assessment = Assessment(
        assessment_id="assess_pending",
        name="Pending Assessment",
        organization_name="TestOrg",
        authorized_by="Alice",
        lifecycle_status=AssessmentStatus.PENDING_APPROVAL,
        scope_rules=[rule],
    )
    res_pending = validate_target("safe.internal", pending_assessment)
    assert res_pending.allowed is False
    assert res_pending.reason_code == ScopeReasonCode.ASSESSMENT_UNAPPROVED

    # 2. Assessment cancelled -> DENIED
    cancelled_assessment = Assessment(
        assessment_id="assess_cancelled",
        name="Cancelled Assessment",
        organization_name="TestOrg",
        authorized_by="Alice",
        lifecycle_status=AssessmentStatus.CANCELLED,
        scope_rules=[rule],
    )
    res_cancel = validate_target("safe.internal", cancelled_assessment)
    assert res_cancel.allowed is False
    assert res_cancel.reason_code == ScopeReasonCode.ASSESSMENT_UNAPPROVED

    # 3. Assessment expired -> DENIED
    past_time = datetime.now(UTC) - timedelta(hours=2)
    expired_assessment = Assessment(
        assessment_id="assess_expired",
        name="Expired Assessment",
        organization_name="TestOrg",
        authorized_by="Alice",
        lifecycle_status=AssessmentStatus.APPROVED,
        expires_at=past_time,
        scope_rules=[rule],
    )
    res_exp = validate_target("safe.internal", expired_assessment)
    assert res_exp.allowed is False
    assert res_exp.reason_code == ScopeReasonCode.ASSESSMENT_EXPIRED


def test_validate_resolved_ip():
    """Pre-execution validation of resolved IP addresses prevents rebinding and out-of-scope routing."""
    rules = [
        ScopeRule(target_type=TargetType.IP_ADDRESS, target_value="10.0.0.1"),
        ScopeRule(target_type=TargetType.CIDR, target_value="192.168.100.0/24"),
        ScopeRule(target_type=TargetType.IP_ADDRESS, target_value="192.168.100.99", is_excluded=True),
    ]
    assessment = Assessment(
        assessment_id="assess_resolved_ip",
        name="Resolved IP Test",
        organization_name="TestOrg",
        authorized_by="Alice",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=rules,
    )

    # Authorized exact IP
    res1 = validate_resolved_ip("10.0.0.1", assessment)
    assert res1.allowed is True
    assert res1.reason_code == ScopeReasonCode.ALLOWED

    # Authorized within CIDR
    res2 = validate_resolved_ip("192.168.100.25", assessment)
    assert res2.allowed is True
    assert res2.reason_code == ScopeReasonCode.ALLOWED

    # Excluded IP within CIDR
    res3 = validate_resolved_ip("192.168.100.99", assessment)
    assert res3.allowed is False
    assert res3.reason_code == ScopeReasonCode.EXCLUDED_TARGET

    # Completely out-of-scope IP
    res4 = validate_resolved_ip("8.8.8.8", assessment)
    assert res4.allowed is False
    assert res4.reason_code == ScopeReasonCode.IP_NOT_IN_SCOPE


def test_ipv6_input_and_brackets():
    """IPv6 addresses (bracketed with port and unbracketed) are handled safely."""
    rules = [
        ScopeRule(target_type=TargetType.IP_ADDRESS, target_value="2001:db8::1", approved_ports=[8080]),
        ScopeRule(target_type=TargetType.CIDR, target_value="2001:db8:acad::/48"),
    ]
    assessment = Assessment(
        assessment_id="assess_ipv6",
        name="IPv6 Test",
        organization_name="TestOrg",
        authorized_by="Alice",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=rules,
    )

    # Bracketed IPv6 with port
    res_port = validate_target("[2001:db8::1]:8080", assessment)
    assert res_port.allowed is True
    assert res_port.effective_port == 8080

    # IPv6 within CIDR
    res_cidr = validate_target("2001:db8:acad::1", assessment)
    assert res_cidr.allowed is True

    # IPv6 outside CIDR
    res_out = validate_target("2001:db9::1", assessment)
    assert res_out.allowed is False
    assert res_out.reason_code == ScopeReasonCode.TARGET_NOT_IN_SCOPE


def test_hostname_canonicalization_edge_cases():
    """Normalizes trailing dots, mixed case, and IDN punycode."""
    target_idn = "  MüNchEn.De. "
    norm = normalize_target(target_idn)
    assert norm.hostname == "xn--mnchen-3ya.de"
    assert norm.canonical == "xn--mnchen-3ya.de"

    # URL with uppercase scheme and path
    target_url = "HTTP://Example.Test./API/V1?test=1"
    norm_url = normalize_target(target_url)
    assert norm_url.scheme == "http"
    assert norm_url.hostname == "example.test"
    assert norm_url.effective_port == 80
    assert norm_url.path == "/API/V1"
