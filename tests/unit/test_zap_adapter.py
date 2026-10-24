"""Unit tests for ZAPScanner adapter and ZAPConfig."""

from pathlib import Path
from unittest.mock import MagicMock
import pytest
import requests

from aegispt.security_engine.core.exceptions import (
    ProfileValidationError,
    TargetValidationError,
)
from aegispt.security_engine.integrations.zap.config import ZAPConfig
from aegispt.security_engine.integrations.zap.scanner import ZAPScanner
from aegispt.security_engine.schemas import (
    AssetType,
    ScanProfile,
    ScanRequest,
    ScanStatus,
    ScanTarget,
    ZAP_ACTIVE_BASELINE_PROFILE,
    ZAP_PASSIVE_BASELINE_PROFILE,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "zap"


@pytest.fixture
def zap_config(tmp_path: Path) -> ZAPConfig:
    """Fixture providing isolated ZAPConfig."""
    return ZAPConfig(
        zap_host="127.0.0.1",
        zap_port=8080,
        target_url="http://127.0.0.1:3000",
        artifacts_dir=tmp_path / "artifacts",
    )


@pytest.fixture
def scanner(zap_config: ZAPConfig) -> ZAPScanner:
    """Fixture providing ZAPScanner with mock session."""
    return ZAPScanner(config=zap_config)


@pytest.fixture
def valid_target() -> ScanTarget:
    """Fixture providing a valid local web target."""
    return ScanTarget(
        asset_type=AssetType.WEB_URL,
        target_value="http://127.0.0.1:3000",
        is_in_scope=True,
    )


class TestZAPTargetAndProfileValidation:
    """Verifies target gating, shell character rejection, and profile checks."""

    def test_valid_target_passes(self, scanner: ZAPScanner, valid_target: ScanTarget) -> None:
        """Valid local target URL is accepted."""
        assert scanner.validate_target(valid_target) is True

    def test_scope_rejection_public_domain(self, scanner: ZAPScanner) -> None:
        """Public internet domain is rejected by safety guardrail."""
        target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="https://example.com",
            is_in_scope=True,
        )
        with pytest.raises(TargetValidationError) as exc:
            scanner.validate_target(target)
        assert "not within authorized local/lab boundaries" in str(exc.value)

    def test_scope_rejection_public_ip(self, scanner: ZAPScanner) -> None:
        """Public internet IP is rejected by safety guardrail."""
        target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://93.184.216.34:3000",
            is_in_scope=True,
        )
        with pytest.raises(TargetValidationError) as exc:
            scanner.validate_target(target)
        assert "not within authorized local/lab boundaries" in str(exc.value)

    def test_rejection_of_shell_injection_characters(self, scanner: ZAPScanner) -> None:
        """Target containing shell metacharacters is rejected."""
        target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://127.0.0.1:3000; rm -rf /",
            is_in_scope=True,
        )
        with pytest.raises(TargetValidationError) as exc:
            scanner.validate_target(target)
        assert "contains forbidden shell characters" in str(exc.value)

    def test_unsupported_profile_rejected(self, scanner: ZAPScanner) -> None:
        """Unsupported profile ID raises ProfileValidationError."""
        bad_profile = ScanProfile(
            profile_id="unsupported_zap_exploit",
            name="Exploit Profile",
            description="Unknown",
            supported_asset_types=[AssetType.WEB_URL],
            expected_output_format=ZAP_PASSIVE_BASELINE_PROFILE.expected_output_format,
        )
        with pytest.raises(ProfileValidationError) as exc:
            scanner.validate_profile(bad_profile)
        assert "not supported by" in str(exc.value)


class TestZAPScannerExecutionLifecycle:
    """Verifies passive scan, active approval gating, evidence hashing, and error trapping."""

    def test_passive_scan_success_with_findings(
        self, scanner: ZAPScanner, valid_target: ScanTarget
    ) -> None:
        """Passive scan runs and normalizes ZAP alerts with verified=False."""
        sample_json = (FIXTURES_DIR / "sample_alerts_flat.json").read_text(encoding="utf-8")

        req = ScanRequest(
            scanner_id="owasp_zap",
            target=valid_target,
            profile=ZAP_PASSIVE_BASELINE_PROFILE,
            options={"simulated_alerts_json": sample_json},
        )
        result = scanner.execute(req)

        assert result.status == ScanStatus.SUCCESS
        assert result.raw_evidence is not None
        assert len(result.raw_evidence.sha256_hash) == 64
        assert result.raw_evidence.byte_size > 0

        # Verify parsed findings
        assert len(result.findings) == 4
        # Verify strict unverified policy
        assert all(f.verified is False for f in result.findings)

    def test_active_scan_requires_approval_by_default(
        self, scanner: ZAPScanner, valid_target: ScanTarget
    ) -> None:
        """Active scanning profile executed without operator approval returns NEEDS_APPROVAL."""
        req = ScanRequest(
            scanner_id="owasp_zap",
            target=valid_target,
            profile=ZAP_ACTIVE_BASELINE_PROFILE,
            options={},  # No approval granted
        )
        result = scanner.execute(req)

        assert result.status == ScanStatus.NEEDS_APPROVAL
        assert result.error is not None
        assert result.error.error_code == "APPROVAL_REQUIRED"

    def test_active_scan_with_approval_succeeds(
        self, scanner: ZAPScanner, valid_target: ScanTarget
    ) -> None:
        """Active scanning profile with explicit operator approval proceeds to completion."""
        sample_json = (FIXTURES_DIR / "sample_alerts_flat.json").read_text(encoding="utf-8")

        req = ScanRequest(
            scanner_id="owasp_zap",
            target=valid_target,
            profile=ZAP_ACTIVE_BASELINE_PROFILE,
            options={
                "human_approval_granted": True,
                "simulated_alerts_json": sample_json,
            },
        )
        result = scanner.execute(req)

        assert result.status == ScanStatus.SUCCESS
        assert len(result.findings) > 0

    def test_simulated_timeout_behavior(
        self, scanner: ZAPScanner, valid_target: ScanTarget
    ) -> None:
        """Scan configured for timeout simulation returns TIMEOUT status."""
        req = ScanRequest(
            scanner_id="owasp_zap",
            target=valid_target,
            profile=ZAP_PASSIVE_BASELINE_PROFILE,
            options={"simulate_timeout": True},
        )
        result = scanner.execute(req)

        assert result.status == ScanStatus.TIMEOUT
        assert result.error is not None
        assert result.error.error_code == "TIMEOUT_EXCEEDED"

    def test_cancellation_mechanism(
        self, scanner: ZAPScanner, valid_target: ScanTarget
    ) -> None:
        """Simulated cancellation returns CANCELLED status."""
        req = ScanRequest(
            scanner_id="owasp_zap",
            target=valid_target,
            profile=ZAP_PASSIVE_BASELINE_PROFILE,
            options={"simulate_cancellation": True},
        )
        result = scanner.execute(req)

        assert result.status == ScanStatus.CANCELLED

    def test_zap_daemon_connection_error_handled_gracefully(
        self, scanner: ZAPScanner, valid_target: ScanTarget
    ) -> None:
        """When ZAP daemon is offline, connection failure is trapped cleanly."""
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.ConnectionError("Connection refused")
        scanner._session = mock_session

        req = ScanRequest(
            scanner_id="owasp_zap",
            target=valid_target,
            profile=ZAP_PASSIVE_BASELINE_PROFILE,
            options={},  # No simulated JSON, triggers live API probe
        )
        result = scanner.execute(req)

        assert result.status == ScanStatus.FAILED
        assert result.error is not None
        assert result.error.error_code == "ZAP_UNAVAILABLE"


class TestZAPConfig:
    """Verifies ZAPConfig validation and environment variable secret loading."""

    def test_api_key_loaded_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API key is loaded from environment variable rather than hardcoded."""
        monkeypatch.setenv("AEGISPT_ZAP_API_KEY", "secret-test-api-key-12345")
        cfg = ZAPConfig()
        assert cfg.api_key == "secret-test-api-key-12345"

    def test_public_zap_host_rejected(self) -> None:
        """Configuring a public internet ZAP host fails local scope check."""
        cfg = ZAPConfig(zap_host="8.8.8.8")
        with pytest.raises(ValueError) as exc:
            cfg.validate_local_scope()
        assert "resolves to a public IP" in str(exc.value)
