"""Unit tests for LabManager and LabConfig."""

from pathlib import Path
from unittest.mock import MagicMock
import pytest
from pydantic import ValidationError
import requests

from aegispt.security_engine.evaluation.lab_manager import (
    LabConfig,
    LabManager,
)


class TestLabConfigValidation:
    """Verifies LabConfig schema validation and security guardrails."""

    def test_default_config_valid(self) -> None:
        """Default configuration should be valid and target localhost:3000."""
        config = LabConfig()
        assert config.target_url == "http://127.0.0.1:3000"
        assert config.port == 3000
        assert config.enforce_local_only is True
        # Scope validation should succeed
        config.validate_local_scope()

    def test_valid_docker_lab_private_ip(self) -> None:
        """Private RFC 1918 subnets (Docker bridges) should be accepted."""
        config = LabConfig(target_url="http://172.18.0.2:3000")
        config.validate_local_scope()

    def test_public_domain_rejected_by_local_guardrail(self) -> None:
        """Public internet domain must raise ValueError when local-only is enforced."""
        config = LabConfig(target_url="http://example.com:3000")
        with pytest.raises(ValueError) as exc:
            config.validate_local_scope()
        assert "Security Guardrail" in str(exc.value)

    def test_public_ip_rejected_by_local_guardrail(self) -> None:
        """Public internet IP must raise ValueError when local-only is enforced."""
        config = LabConfig(target_url="http://8.8.8.8:3000")
        with pytest.raises(ValueError) as exc:
            config.validate_local_scope()
        assert "resolves to a public internet IP" in str(exc.value)

    def test_invalid_url_scheme_rejected(self) -> None:
        """Non-http/https URL schemes must raise ValidationError."""
        with pytest.raises(ValidationError) as exc:
            LabConfig(target_url="ftp://127.0.0.1:3000")
        assert "Target URL scheme must be 'http' or 'https'" in str(exc.value)

    def test_invalid_port_range_rejected(self) -> None:
        """Port numbers outside 1-65535 must raise ValidationError."""
        with pytest.raises(ValidationError):
            LabConfig(port=70000)

    def test_negative_timeout_rejected(self) -> None:
        """Timeout must be positive."""
        with pytest.raises(ValidationError):
            LabConfig(timeout_seconds=-1.0)


class TestLabManagerReadiness:
    """Verifies LabManager probe handling, version extraction, and error trapping."""

    def test_lab_readiness_when_running(self) -> None:
        """When target is operational, report must be is_ready=True and record version."""
        mock_session = MagicMock()

        # Health endpoint response
        health_resp = MagicMock()
        health_resp.status_code = 200

        # Version endpoint response
        version_resp = MagicMock()
        version_resp.status_code = 200
        version_resp.json.return_value = {"version": "17.1.1"}

        mock_session.get.side_effect = [health_resp, version_resp]

        manager = LabManager(session=mock_session)
        status = manager.get_readiness_report()

        assert status.is_reachable is True
        assert status.is_ready is True
        assert status.application_version == "17.1.1"
        assert status.status_code == 200
        assert "Lab is READY" in status.message

    def test_lab_readiness_when_unavailable(self) -> None:
        """When service connection is refused, report is_ready=False and is_reachable=False."""
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.ConnectionError("Connection refused")

        manager = LabManager(session=mock_session)
        status = manager.get_readiness_report()

        assert status.is_reachable is False
        assert status.is_ready is False
        assert status.application_version is None
        assert "Lab is NOT ready" in status.message
        assert "Connection refused" in status.message

    def test_timeout_behavior(self) -> None:
        """When probe times out, report must gracefully capture timeout."""
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.Timeout("Read timed out")

        manager = LabManager(session=mock_session)
        status = manager.get_readiness_report()

        assert status.is_reachable is False
        assert status.is_ready is False
        assert "Connection timed out" in status.message

    def test_instantiation_rejects_external_target_url(self) -> None:
        """Instantiating LabManager with an external URL fails immediately."""
        config = LabConfig(target_url="http://93.184.216.34:3000")
        with pytest.raises(ValueError) as exc:
            LabManager(config=config)
        assert "resolves to a public internet IP" in str(exc.value)

    def test_load_from_config_file(self, tmp_path: Path) -> None:
        """Verify loading from a JSON configuration file."""
        config_file = tmp_path / "test_lab_config.json"
        config_file.write_text(
            '{"lab_name": "Test Lab", "target_url": "http://127.0.0.1:3000", "port": 3000}',
            encoding="utf-8",
        )
        manager = LabManager.from_file(config_file)
        assert manager.config.lab_name == "Test Lab"
        assert manager.config.port == 3000

    def test_load_from_nonexistent_file_raises_error(self) -> None:
        """Loading from a non-existent path raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            LabManager.from_file("nonexistent_config_file.json")

    def test_wait_for_ready_polling_success(self) -> None:
        """Polling should succeed when service becomes ready."""
        mock_session = MagicMock()

        # First call: connection error; second call: health OK; third call: version OK
        health_resp = MagicMock()
        health_resp.status_code = 200
        version_resp = MagicMock()
        version_resp.status_code = 200
        version_resp.json.return_value = {"version": "17.1.1"}

        mock_session.get.side_effect = [
            requests.ConnectionError("Starting up..."),
            health_resp,
            version_resp,
        ]

        manager = LabManager(session=mock_session)
        status = manager.wait_for_ready(max_wait_seconds=5.0, poll_interval_seconds=0.01)

        assert status.is_ready is True
        assert status.application_version == "17.1.1"

    def test_wait_for_ready_timeout(self) -> None:
        """Polling times out when service never responds."""
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.ConnectionError("Still offline")

        manager = LabManager(session=mock_session)
        status = manager.wait_for_ready(max_wait_seconds=0.05, poll_interval_seconds=0.01)

        assert status.is_ready is False
        assert "timed out after" in status.message
