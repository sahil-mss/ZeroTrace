import pytest

from backend.policy.scope_validator import ScopeValidationError, ScopeValidator
from schemas.enums import ScopeStatus, TestPermissionLevel
from schemas.models import ScopePolicy


def test_canonicalize_various_targets():
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
    # Assessment allows only PASSIVE_ONLY
    ok, reason = ScopeValidator.check_permission(
        requested_level=TestPermissionLevel.INTRUSIVE_TEST,
        allowed_level=TestPermissionLevel.PASSIVE_ONLY,
    )
    assert ok is False
    assert "exceeds assessment permission" in reason

    # Assessment allows CONTROLLED_VULN_SCAN, requesting PASSIVE is fine
    ok, reason = ScopeValidator.check_permission(
        requested_level=TestPermissionLevel.PASSIVE_ONLY,
        allowed_level=TestPermissionLevel.CONTROLLED_VULN_SCAN,
    )
    assert ok is True
