"""Unit tests for MockScanner adapter and BaseScanner lifecycle."""

import pytest

from aegispt.security_engine.core.exceptions import (
    ProfileValidationError,
    TargetValidationError,
)
from aegispt.security_engine.integrations.mock import MockScanner
from aegispt.security_engine.schemas import (
    AssetType,
    MOCK_BASELINE_PROFILE,
    MOCK_INTRUSIVE_PROFILE,
    MOCK_TIMEOUT_SIMULATION_PROFILE,
    ScanProfile,
    ScanRequest,
    ScanStatus,
    ScanTarget,
    Severity,
)


@pytest.fixture
def scanner() -> MockScanner:
    """Fixture providing a fresh MockScanner instance."""
    return MockScanner()


@pytest.fixture
def valid_target() -> ScanTarget:
    """Fixture providing an authorized local target."""
    return ScanTarget(
        asset_type=AssetType.IP_ADDRESS,
        target_value="127.0.0.1",
        ports=[8080],
        is_in_scope=True,
    )


class TestMockScannerMetadata:
    """Verifies metadata reporting for MockScanner."""

    def test_metadata_fields(self, scanner: MockScanner) -> None:
        """Ensure static metadata correctly describes scanner capabilities."""
        meta = scanner.get_metadata()
        assert meta.scanner_id == "mock_scanner"
        assert meta.version == "1.0.0"
        assert "mock_baseline" in meta.supported_profiles
        assert AssetType.IP_ADDRESS in meta.supported_asset_types


class TestMockScannerValidation:
    """Verifies target and profile validation contracts."""

    def test_valid_target_accepted(self, scanner: MockScanner, valid_target: ScanTarget) -> None:
        """Valid local target should pass validation."""
        assert scanner.validate_target(valid_target) is True

    def test_out_of_scope_target_rejected(self, scanner: MockScanner) -> None:
        """Target flagged as out of scope must raise TargetValidationError."""
        target = ScanTarget(
            asset_type=AssetType.IP_ADDRESS,
            target_value="127.0.0.1",
            is_in_scope=False,
        )
        with pytest.raises(TargetValidationError) as exc:
            scanner.validate_target(target)
        assert "explicitly flagged as out of scope" in str(exc.value)

    def test_non_local_target_rejected(self, scanner: MockScanner) -> None:
        """Public internet IP must be rejected by the safety guardrail."""
        target = ScanTarget(
            asset_type=AssetType.IP_ADDRESS,
            target_value="93.184.216.34",
            is_in_scope=True,
        )
        with pytest.raises(TargetValidationError) as exc:
            scanner.validate_target(target)
        assert "not within authorized local/lab boundaries" in str(exc.value)

    def test_invalid_profile_rejected(self, scanner: MockScanner, valid_target: ScanTarget) -> None:
        """Unsupported profile ID must raise ProfileValidationError."""
        fake_profile = ScanProfile(
            profile_id="unsupported_exploit_profile",
            name="Exploit Profile",
            description="Non-existent profile",
            supported_asset_types=[AssetType.IP_ADDRESS],
            expected_output_format=MOCK_BASELINE_PROFILE.expected_output_format,
        )
        with pytest.raises(ProfileValidationError) as exc:
            scanner.validate_profile(fake_profile)
        assert "not supported by" in str(exc.value)


class TestMockScannerExecution:
    """Verifies scan execution, result construction, and failure handling."""

    def test_successful_scan_execution(
        self, scanner: MockScanner, valid_target: ScanTarget
    ) -> None:
        """Valid scan request should complete with SUCCESS status and findings."""
        request = ScanRequest(
            scanner_id=scanner.SCANNER_ID,
            target=valid_target,
            profile=MOCK_BASELINE_PROFILE,
        )
        result = scanner.execute(request)

        assert result.status == ScanStatus.SUCCESS
        assert result.scanner_id == scanner.SCANNER_ID
        assert result.target.target_value == "127.0.0.1"
        assert result.duration_seconds >= 0.0

        # Verify raw evidence reference
        assert result.raw_evidence is not None
        assert len(result.raw_evidence.sha256_hash) == 64
        assert result.raw_evidence.byte_size > 0

        # Verify normalized finding
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.severity == Severity.LOW
        assert finding.cwe_id == 200
        assert len(finding.evidence) == 1
        assert finding.evidence[0].sha256_hash == result.raw_evidence.sha256_hash

    def test_simulated_timeout_behavior(
        self, scanner: MockScanner, valid_target: ScanTarget
    ) -> None:
        """Scan configured for timeout simulation must return TIMEOUT status."""
        request = ScanRequest(
            scanner_id=scanner.SCANNER_ID,
            target=valid_target,
            profile=MOCK_TIMEOUT_SIMULATION_PROFILE,
        )
        result = scanner.execute(request)

        assert result.status == ScanStatus.TIMEOUT
        assert result.error is not None
        assert result.error.error_code == "TIMEOUT_EXCEEDED"
        assert len(result.findings) == 0

    def test_simulated_error_behavior(
        self, scanner: MockScanner, valid_target: ScanTarget
    ) -> None:
        """Scan configured for error simulation must return FAILED status."""
        request = ScanRequest(
            scanner_id=scanner.SCANNER_ID,
            target=valid_target,
            profile=MOCK_BASELINE_PROFILE,
            options={"simulate_error": True},
        )
        result = scanner.execute(request)

        assert result.status == ScanStatus.FAILED
        assert result.error is not None
        assert result.error.error_code == "SIMULATED_FAILURE"
        assert result.error.exit_code == 1

    def test_intrusive_profile_requires_approval(
        self, scanner: MockScanner, valid_target: ScanTarget
    ) -> None:
        """Intrusive profile executed without approval flag must return NEEDS_APPROVAL."""
        request = ScanRequest(
            scanner_id=scanner.SCANNER_ID,
            target=valid_target,
            profile=MOCK_INTRUSIVE_PROFILE,
            options={},  # No approval granted
        )
        result = scanner.execute(request)

        assert result.status == ScanStatus.NEEDS_APPROVAL
        assert result.error is not None
        assert result.error.error_code == "APPROVAL_REQUIRED"

    def test_intrusive_profile_with_approval_succeeds(
        self, scanner: MockScanner, valid_target: ScanTarget
    ) -> None:
        """Intrusive profile executed with explicit operator approval proceeds to completion."""
        request = ScanRequest(
            scanner_id=scanner.SCANNER_ID,
            target=valid_target,
            profile=MOCK_INTRUSIVE_PROFILE,
            options={"human_approval_granted": True},
        )
        result = scanner.execute(request)

        assert result.status == ScanStatus.SUCCESS
        assert len(result.findings) > 0

    def test_invalid_target_in_execute_returns_failed_result(
        self, scanner: MockScanner
    ) -> None:
        """Calling execute with an out-of-bounds target traps error and returns FAILED result."""
        public_target = ScanTarget(
            asset_type=AssetType.IP_ADDRESS,
            target_value="8.8.4.4",
        )
        request = ScanRequest(
            scanner_id=scanner.SCANNER_ID,
            target=public_target,
            profile=MOCK_BASELINE_PROFILE,
        )
        result = scanner.execute(request)

        assert result.status == ScanStatus.FAILED
        assert result.error is not None
        assert result.error.error_code == "TARGET_VALIDATION_FAILED"
