"""Unit tests for AegisPT security engine schemas."""

from datetime import datetime
import pytest
from pydantic import ValidationError

from aegispt.security_engine.schemas import (
    AssetType,
    ImpactLevel,
    NormalizedFinding,
    OutputFormat,
    PermissionLevel,
    ResourceBudget,
    ScanProfile,
    ScanRequest,
    ScanStatus,
    ScanTarget,
    Severity,
)


class TestTargetSchema:
    """Verifies ScanTarget data model and validation logic."""

    def test_valid_localhost_ip_target(self) -> None:
        """Valid IPv4 loopback target with ports."""
        target = ScanTarget(
            asset_type=AssetType.IP_ADDRESS,
            target_value="127.0.0.1",
            ports=[80, 443, 8080],
        )
        assert target.target_value == "127.0.0.1"
        assert target.ports == [80, 443, 8080]
        assert target.is_local_or_private() is True
        assert target.is_in_scope is True

    def test_valid_docker_private_subnet_target(self) -> None:
        """Valid RFC 1918 / Docker lab IP target."""
        target = ScanTarget(
            asset_type=AssetType.IP_ADDRESS,
            target_value="172.18.0.5",
        )
        assert target.is_local_or_private() is True

    def test_public_ip_identified_as_non_local(self) -> None:
        """Public IP should be detected as non-local to prevent accidental internet scans."""
        target = ScanTarget(
            asset_type=AssetType.IP_ADDRESS,
            target_value="8.8.8.8",
        )
        assert target.is_local_or_private() is False

    def test_blank_target_value_rejected(self) -> None:
        """Empty or whitespace-only target values must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            ScanTarget(asset_type=AssetType.IP_ADDRESS, target_value="   ")
        assert "Target value must not be empty" in str(exc_info.value)

    def test_port_out_of_range_rejected(self) -> None:
        """Ports outside 1-65535 must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            ScanTarget(
                asset_type=AssetType.IP_ADDRESS,
                target_value="127.0.0.1",
                ports=[80, 70000],
            )
        assert "Port 70000 is out of bounds" in str(exc_info.value)

    def test_missing_required_fields_raises_error(self) -> None:
        """Missing asset_type or target_value must raise ValidationError."""
        with pytest.raises(ValidationError):
            ScanTarget.model_validate({})


class TestProfileSchema:
    """Verifies ScanProfile configuration and boundary constraints."""

    def test_valid_profile_creation(self) -> None:
        """Ensure properly specified profile initializes correctly."""
        profile = ScanProfile(
            profile_id="custom_lab_test",
            name="Custom Lab Profile",
            description="Testing profile for unit test suite",
            supported_asset_types=[AssetType.IP_ADDRESS],
            required_permission_level=PermissionLevel.SAFE_AUDIT,
            resource_budget=ResourceBudget(max_cpu_percent=30, max_memory_mb=256),
            timeout_seconds=60,
            max_concurrency=2,
            expected_output_format=OutputFormat.JSON,
            potential_impact=ImpactLevel.NONE,
            requires_human_approval=False,
        )
        assert profile.profile_id == "custom_lab_test"
        assert profile.timeout_seconds == 60

    def test_invalid_profile_id_characters_rejected(self) -> None:
        """Profile IDs with special shell characters must be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ScanProfile(
                profile_id="bad; rm -rf /",
                name="Malicious ID",
                description="Should fail",
                supported_asset_types=[AssetType.IP_ADDRESS],
                expected_output_format=OutputFormat.JSON,
            )
        assert "must contain only alphanumeric characters" in str(exc_info.value)

    def test_timeout_bounds_enforced(self) -> None:
        """Timeout cannot be 0 or negative."""
        with pytest.raises(ValidationError):
            ScanProfile(
                profile_id="bad_timeout",
                name="Negative timeout",
                description="Invalid",
                supported_asset_types=[AssetType.IP_ADDRESS],
                timeout_seconds=0,
                expected_output_format=OutputFormat.JSON,
            )


class TestFindingSchema:
    """Verifies NormalizedFinding schema and severity enumeration."""

    def test_normalized_finding_serialization(self) -> None:
        """Ensure finding serializes and retains all fields and evidence."""
        target = ScanTarget(asset_type=AssetType.IP_ADDRESS, target_value="127.0.0.1")
        finding = NormalizedFinding(
            scanner_id="test_scanner",
            title="Insecure HTTP Protocol",
            description="Cleartext HTTP in use on port 80",
            severity=Severity.MEDIUM,
            target=target,
            cwe_id=319,
        )
        dump = finding.model_dump()
        assert dump["severity"] == "MEDIUM"
        assert dump["cwe_id"] == 319
        assert dump["target"]["target_value"] == "127.0.0.1"


class TestScanRequestSchema:
    """Verifies ScanRequest creation and serialization."""

    def test_scan_request_valid(self) -> None:
        """Ensure complete scan request constructs properly."""
        target = ScanTarget(asset_type=AssetType.IP_ADDRESS, target_value="127.0.0.1")
        profile = ScanProfile(
            profile_id="quick_check",
            name="Quick Check",
            description="Test profile",
            supported_asset_types=[AssetType.IP_ADDRESS],
            expected_output_format=OutputFormat.JSON,
        )
        request = ScanRequest(
            scanner_id="mock_scanner",
            target=target,
            profile=profile,
        )
        assert request.scanner_id == "mock_scanner"
        assert request.target.target_value == "127.0.0.1"
