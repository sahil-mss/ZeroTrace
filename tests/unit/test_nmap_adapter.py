"""Unit tests for NmapScanner adapter lifecycle and subprocess execution."""

from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch
import pytest

from aegispt.security_engine.core.exceptions import (
    ProfileValidationError,
    TargetValidationError,
)
from aegispt.security_engine.integrations.nmap.scanner import NmapScanner
from aegispt.security_engine.schemas import (
    AssetType,
    NMAP_CUSTOM_PORTS_PROFILE,
    NMAP_FAST_DISCOVERY_PROFILE,
    NMAP_SERVICE_VERSION_PROFILE,
    ScanProfile,
    ScanRequest,
    ScanStatus,
    ScanTarget,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "nmap"


@pytest.fixture
def scanner(tmp_path: Path) -> NmapScanner:
    """Fixture providing an NmapScanner configured with a temporary artifacts directory."""
    return NmapScanner(nmap_binary="nmap", artifacts_dir=tmp_path / "artifacts")


@pytest.fixture
def valid_target() -> ScanTarget:
    """Fixture providing a valid localhost target."""
    return ScanTarget(
        asset_type=AssetType.IP_ADDRESS,
        target_value="127.0.0.1",
        ports=[3000],
        is_in_scope=True,
    )


class TestNmapTargetAndProfileValidation:
    """Verifies target gating, shell character rejection, and profile checks."""

    def test_valid_target_passes(self, scanner: NmapScanner, valid_target: ScanTarget) -> None:
        """Valid local target is accepted."""
        assert scanner.validate_target(valid_target) is True

    def test_scope_rejection_public_ip(self, scanner: NmapScanner) -> None:
        """Public internet destination must be rejected by safety guardrail."""
        target = ScanTarget(
            asset_type=AssetType.IP_ADDRESS,
            target_value="8.8.8.8",
            is_in_scope=True,
        )
        with pytest.raises(TargetValidationError) as exc:
            scanner.validate_target(target)
        assert "not within authorized local/lab boundaries" in str(exc.value)

    def test_scope_rejection_out_of_scope_flag(self, scanner: NmapScanner) -> None:
        """Target flagged is_in_scope=False is rejected."""
        target = ScanTarget(
            asset_type=AssetType.IP_ADDRESS,
            target_value="127.0.0.1",
            is_in_scope=False,
        )
        with pytest.raises(TargetValidationError) as exc:
            scanner.validate_target(target)
        assert "explicitly flagged as out of scope" in str(exc.value)

    def test_rejection_of_shell_injection_characters(self, scanner: NmapScanner) -> None:
        """Target strings containing shell meta-characters are rejected."""
        # Note: ScanTarget allows general strings; NmapScanner adds strict shell character checks
        target = ScanTarget(
            asset_type=AssetType.HOSTNAME,
            target_value="127.0.0.1; rm -rf /",
            is_in_scope=True,
        )
        with pytest.raises(TargetValidationError) as exc:
            scanner.validate_target(target)
        assert "contains forbidden shell characters" in str(exc.value)

    def test_unsupported_profile_rejected(self, scanner: NmapScanner) -> None:
        """Unsupported profile ID raises ProfileValidationError."""
        bad_profile = ScanProfile(
            profile_id="unsupported_profile",
            name="Bad Profile",
            description="Unknown",
            supported_asset_types=[AssetType.IP_ADDRESS],
            expected_output_format=NMAP_FAST_DISCOVERY_PROFILE.expected_output_format,
        )
        with pytest.raises(ProfileValidationError) as exc:
            scanner.validate_profile(bad_profile)
        assert "not supported by" in str(exc.value)


class TestNmapCommandConstruction:
    """Verifies safe argument vector generation without shell=True."""

    def test_fast_discovery_args(self, scanner: NmapScanner, valid_target: ScanTarget) -> None:
        """Verify command vector for fast discovery profile."""
        output_file = Path("artifacts/test.xml")
        req = ScanRequest(
            scanner_id="nmap",
            target=valid_target,
            profile=NMAP_FAST_DISCOVERY_PROFILE,
        )
        args = scanner.build_command_args(req, output_file)

        assert args[0] == "nmap"
        assert args[1] == "-oX"
        assert args[2] == str(output_file)
        assert "-F" in args
        assert "-T4" in args
        assert "-Pn" in args
        assert args[-1] == "127.0.0.1"

    def test_custom_ports_args(self, scanner: NmapScanner, valid_target: ScanTarget) -> None:
        """Verify -p argument formatting for custom ports."""
        output_file = Path("artifacts/test.xml")
        valid_target.ports = [80, 443, 3000]
        req = ScanRequest(
            scanner_id="nmap",
            target=valid_target,
            profile=NMAP_CUSTOM_PORTS_PROFILE,
        )
        args = scanner.build_command_args(req, output_file)

        assert "-p" in args
        port_index = args.index("-p")
        assert args[port_index + 1] == "80,443,3000"


class TestNmapExecutionLifecycle:
    """Verifies missing binary handling, timeout handling, non-zero exit codes, and mock execution."""

    def test_missing_nmap_executable_handled_gracefully(
        self, scanner: NmapScanner, valid_target: ScanTarget
    ) -> None:
        """When nmap binary is not found in PATH, returns FAILED with NMAP_NOT_INSTALLED."""
        req = ScanRequest(
            scanner_id="nmap",
            target=valid_target,
            profile=NMAP_FAST_DISCOVERY_PROFILE,
        )
        with patch("shutil.which", return_value=None):
            result = scanner.execute(req)

        assert result.status == ScanStatus.FAILED
        assert result.error is not None
        assert result.error.error_code == "NMAP_NOT_INSTALLED"
        assert "not found in system PATH" in result.error.message

    def test_timeout_handling(
        self, scanner: NmapScanner, valid_target: ScanTarget
    ) -> None:
        """When nmap exceeds timeout limit, returns TIMEOUT status with TIMEOUT_EXCEEDED."""
        req = ScanRequest(
            scanner_id="nmap",
            target=valid_target,
            profile=NMAP_FAST_DISCOVERY_PROFILE,
            timeout_seconds=1,
        )
        with patch("shutil.which", return_value="C:\\Fake\\nmap.exe"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=1)):
                result = scanner.execute(req)

        assert result.status == ScanStatus.TIMEOUT
        assert result.error is not None
        assert result.error.error_code == "TIMEOUT_EXCEEDED"

    def test_non_zero_exit_code_handled(
        self, scanner: NmapScanner, valid_target: ScanTarget
    ) -> None:
        """When nmap process exits with error code, captures stderr and returns FAILED."""
        req = ScanRequest(
            scanner_id="nmap",
            target=valid_target,
            profile=NMAP_FAST_DISCOVERY_PROFILE,
        )
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "QUITTING! Failed to resolve given hostname/IP: 127.0.0.1"

        with patch("shutil.which", return_value="C:\\Fake\\nmap.exe"):
            with patch("subprocess.run", return_value=mock_proc):
                result = scanner.execute(req)

        assert result.status == ScanStatus.FAILED
        assert result.error is not None
        assert result.error.error_code == "NMAP_EXECUTION_FAILED"
        assert result.error.exit_code == 1

    def test_successful_mocked_execution_and_normalization(
        self, scanner: NmapScanner, valid_target: ScanTarget
    ) -> None:
        """Simulate successful nmap execution using static fixture output.

        Verifies:
        - ScanStatus.SUCCESS
        - Raw evidence stored with SHA-256 hash
        - Factual service observations parsed
        - Zero vulnerability findings generated for open ports
        """
        req = ScanRequest(
            scanner_id="nmap",
            target=valid_target,
            profile=NMAP_SERVICE_VERSION_PROFILE,
        )

        sample_xml = (FIXTURES_DIR / "sample_open_ports.xml").read_text(encoding="utf-8")

        def mock_subprocess_run(cmd, **kwargs):
            # Write the sample fixture into the target output XML path
            output_path = Path(cmd[2])
            output_path.write_text(sample_xml, encoding="utf-8")
            res = MagicMock()
            res.returncode = 0
            res.stdout = "Nmap done: 1 IP address (1 host up) scanned in 0.5 seconds"
            res.stderr = ""
            return res

        with patch("shutil.which", return_value="C:\\Fake\\nmap.exe"):
            with patch("subprocess.run", side_effect=mock_subprocess_run):
                result = scanner.execute(req)

        assert result.status == ScanStatus.SUCCESS
        assert result.raw_evidence is not None
        assert len(result.raw_evidence.sha256_hash) == 64
        assert result.raw_evidence.byte_size > 0

        # Verify service observations extracted
        assert len(result.observations) == 2
        port_3000 = next(o for o in result.observations if o.port == 3000)
        assert port_3000.state == "open"
        assert port_3000.service_version == "17.1.1"

        # STRICT SPEC: "Do not generate vulnerability findings merely because a port is open."
        assert len(result.findings) == 0
