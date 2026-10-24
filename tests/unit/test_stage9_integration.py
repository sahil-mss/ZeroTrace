"""Integration tests for Stage 9: Backend and AI Planner Integration.

Verifies:
- Task 1: Scanner service execution with structured scan requests.
- Task 2: Policy check and scope enforcement blocking unauthorized/public targets.
- Task 3: AI Planner recommendation validation, gatekeeping, and rejection rules.
- Task 4: Job lifecycle state machine transitions across all states.
- Task 5: Result handling with metadata, duration, normalized findings, and verification.
- Task 6: Error handling for timeouts, failures, and cancellations.
"""

import unittest

from aegispt.security_engine.core.ai_planner_interface import (
    AIPlanRecommendation,
    AIRecommendationValidator,
)
from aegispt.security_engine.core.exceptions import (
    AIRecommendationValidationError,
    JobLifecycleError,
    ScopeViolationError,
)
from aegispt.security_engine.core.scope import LocalScopeValidator
from aegispt.security_engine.schemas.enums import (
    AssetType,
    JobStatus,
    PermissionLevel,
    VerificationStatus,
)
from aegispt.security_engine.schemas.job import ScanJobRequest
from aegispt.security_engine.schemas.profile import ResourceBudget
from aegispt.security_engine.schemas.target import ScanTarget
from aegispt.security_engine.service import ScannerService, create_default_scanner_registry


class TestScannerServiceExecution(unittest.TestCase):
    """Verifies standard lifecycle execution of valid scan requests through ScannerService."""

    def setUp(self) -> None:
        self.service = ScannerService()
        self.valid_target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://127.0.0.1:3000",
            is_in_scope=True,
        )

    def test_successful_scan_job_lifecycle(self) -> None:
        """Ensure a valid job transitions through all expected states to COMPLETED."""
        req = ScanJobRequest(
            assessment_id="test-assess-001",
            asset_id="asset-web-01",
            target=self.valid_target,
            scanner_id="mock_scanner",
            profile_id="mock_baseline",
            permission_level=PermissionLevel.SAFE_AUDIT,
            resource_budget=ResourceBudget(max_cpu_percent=20, max_memory_mb=128, max_rate_limit=50),
        )

        resp = self.service.run_job(req)

        self.assertEqual(resp.status, JobStatus.COMPLETED)
        self.assertEqual(resp.job_id, req.job_id)
        self.assertIsNotNone(resp.scanner_metadata)
        self.assertEqual(resp.scanner_metadata.scanner_id, "mock_scanner")
        self.assertGreater(resp.duration_seconds, 0.0)
        self.assertGreater(len(resp.findings), 0)
        self.assertGreater(len(resp.evidence_references), 0)
        self.assertIsNone(resp.error)

        # Verify job history state progression
        job = self.service.get_job(req.job_id)
        self.assertIsNotNone(job)
        state_flow = [t.to_status for t in job.transitions]
        expected_flow = [
            JobStatus.CREATED,
            JobStatus.POLICY_CHECK,
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.REVIEW,
            JobStatus.COMPLETED,
        ]
        self.assertEqual(state_flow, expected_flow)

        # Verify verification summary populated
        self.assertEqual(len(resp.verification_summary), len(resp.findings))
        for fid, status in resp.verification_summary.items():
            self.assertIn(status, [
                VerificationStatus.CONFIRMED,
                VerificationStatus.LIKELY,
                VerificationStatus.NEEDS_REVIEW,
                VerificationStatus.UNVERIFIED,
            ])


class TestPolicyCheckAndScopeEnforcement(unittest.TestCase):
    """Verifies that unauthorized, out-of-scope, or intrusive targets are blocked at POLICY_CHECK."""

    def setUp(self) -> None:
        self.service = ScannerService()

    def test_out_of_scope_flag_rejected(self) -> None:
        """Target with is_in_scope=False must fail at POLICY_CHECK."""
        target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://127.0.0.1:3000",
            is_in_scope=False,
        )
        req = ScanJobRequest(
            assessment_id="test-assess-002",
            asset_id="asset-web-02",
            target=target,
            scanner_id="mock_scanner",
            profile_id="mock_baseline",
        )

        resp = self.service.run_job(req)

        self.assertEqual(resp.status, JobStatus.FAILED)
        self.assertIsNotNone(resp.error)
        self.assertEqual(resp.error.error_code, "SCOPE_VIOLATION")
        self.assertIn("out of scope", resp.error.message.lower())

        job = self.service.get_job(req.job_id)
        self.assertEqual(job.status, JobStatus.FAILED)
        state_flow = [t.to_status for t in job.transitions]
        self.assertEqual(state_flow, [JobStatus.CREATED, JobStatus.POLICY_CHECK, JobStatus.FAILED])

    def test_public_domain_rejected_at_policy_check(self) -> None:
        """External domain (e.g. google.com) must be rejected by local scope validator."""
        target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="https://google.com",
            is_in_scope=True,
        )
        req = ScanJobRequest(
            assessment_id="test-assess-003",
            asset_id="asset-web-03",
            target=target,
            scanner_id="mock_scanner",
            profile_id="mock_baseline",
        )

        resp = self.service.run_job(req)
        self.assertEqual(resp.status, JobStatus.FAILED)
        self.assertEqual(resp.error.error_code, "SCOPE_VIOLATION")

    def test_intrusive_profile_requires_operator_approval(self) -> None:
        """Intrusive profile without operator sign-off transitions to NEEDS_APPROVAL."""
        target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://127.0.0.1:3000",
            is_in_scope=True,
        )
        req = ScanJobRequest(
            assessment_id="test-assess-004",
            asset_id="asset-web-04",
            target=target,
            scanner_id="mock_scanner",
            profile_id="mock_intrusive_approval",
            approved_by_operator=False,
        )

        resp = self.service.run_job(req)

        self.assertEqual(resp.status, JobStatus.NEEDS_APPROVAL)
        job = self.service.get_job(req.job_id)
        self.assertEqual(job.status, JobStatus.NEEDS_APPROVAL)
        state_flow = [t.to_status for t in job.transitions]
        self.assertEqual(state_flow, [JobStatus.CREATED, JobStatus.POLICY_CHECK, JobStatus.NEEDS_APPROVAL])

    def test_intrusive_profile_with_operator_approval_succeeds(self) -> None:
        """Intrusive profile with explicit operator sign-off proceeds to completion."""
        target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://127.0.0.1:3000",
            is_in_scope=True,
        )
        req = ScanJobRequest(
            assessment_id="test-assess-005",
            asset_id="asset-web-05",
            target=target,
            scanner_id="mock_scanner",
            profile_id="mock_intrusive_approval",
            approved_by_operator=True,
        )

        resp = self.service.run_job(req)
        self.assertEqual(resp.status, JobStatus.COMPLETED)


class TestProfileAndScannerValidation(unittest.TestCase):
    """Verifies rejection of unknown scanners or profiles."""

    def setUp(self) -> None:
        self.service = ScannerService()
        self.target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://127.0.0.1:3000",
            is_in_scope=True,
        )

    def test_unregistered_scanner_fails(self) -> None:
        """Request for nonexistent scanner transitions to FAILED with SCANNER_NOT_FOUND."""
        req = ScanJobRequest(
            assessment_id="test-assess-006",
            asset_id="asset-web-06",
            target=self.target,
            scanner_id="nonexistent_scanner",
            profile_id="mock_baseline",
        )

        resp = self.service.run_job(req)
        self.assertEqual(resp.status, JobStatus.FAILED)
        self.assertEqual(resp.error.error_code, "SCANNER_NOT_FOUND")

    def test_unapproved_profile_fails(self) -> None:
        """Request with unauthorized profile ID transitions to FAILED with INVALID_SCAN_PROFILE."""
        req = ScanJobRequest(
            assessment_id="test-assess-007",
            asset_id="asset-web-07",
            target=self.target,
            scanner_id="mock_scanner",
            profile_id="unauthorized_profile_id",
        )

        resp = self.service.run_job(req)
        self.assertEqual(resp.status, JobStatus.FAILED)
        self.assertEqual(resp.error.error_code, "INVALID_SCAN_PROFILE")


class TestScannerFailureAndTimeout(unittest.TestCase):
    """Verifies that failure or timeout conditions transition the job to FAILED."""

    def setUp(self) -> None:
        self.service = ScannerService()
        self.target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://127.0.0.1:3000",
            is_in_scope=True,
        )

    def test_scanner_runtime_error_transitions_to_failed(self) -> None:
        """Triggering simulated error in mock scanner causes FAILED status."""
        req = ScanJobRequest(
            assessment_id="test-assess-008",
            asset_id="asset-web-08",
            target=self.target,
            scanner_id="mock_scanner",
            profile_id="mock_baseline",
            options={"simulate_error": True},
        )

        resp = self.service.run_job(req)
        self.assertEqual(resp.status, JobStatus.FAILED)
        self.assertIsNotNone(resp.error)
        self.assertIn(resp.error.error_code, ["SIMULATED_FAILURE", "MOCK_SIMULATED_FAILURE"])

    def test_scanner_timeout_transitions_to_failed(self) -> None:
        """Executing timeout simulation profile triggers FAILED with timeout error code."""
        req = ScanJobRequest(
            assessment_id="test-assess-009",
            asset_id="asset-web-09",
            target=self.target,
            scanner_id="mock_scanner",
            profile_id="mock_timeout_sim",
        )

        resp = self.service.run_job(req)
        self.assertEqual(resp.status, JobStatus.FAILED)
        self.assertIsNotNone(resp.error)
        self.assertIn(resp.error.error_code, ["TIMEOUT", "TIMEOUT_EXCEEDED"])


class TestJobCancellation(unittest.TestCase):
    """Verifies job cancellation behavior and edge cases."""

    def setUp(self) -> None:
        self.service = ScannerService()
        self.target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://127.0.0.1:3000",
            is_in_scope=True,
        )

    def test_cancel_created_job(self) -> None:
        """Cancelling a job before execution transitions to CANCELLED."""
        req = ScanJobRequest(
            assessment_id="test-assess-010",
            asset_id="asset-web-10",
            target=self.target,
            scanner_id="mock_scanner",
            profile_id="mock_baseline",
        )
        job = self.service.create_job(req)
        self.assertEqual(job.status, JobStatus.CREATED)

        resp = self.service.cancel_job(job.job_id, reason="Operator abort")
        self.assertEqual(resp.status, JobStatus.CANCELLED)
        self.assertEqual(job.status, JobStatus.CANCELLED)

    def test_cancel_completed_job_raises_error(self) -> None:
        """Attempting to cancel an already completed job raises JobLifecycleError."""
        req = ScanJobRequest(
            assessment_id="test-assess-011",
            asset_id="asset-web-11",
            target=self.target,
            scanner_id="mock_scanner",
            profile_id="mock_baseline",
        )
        resp = self.service.run_job(req)
        self.assertEqual(resp.status, JobStatus.COMPLETED)

        with self.assertRaises(JobLifecycleError):
            self.service.cancel_job(req.job_id)

    def test_cancel_nonexistent_job_raises_error(self) -> None:
        """Cancelling unknown job raises JobLifecycleError."""
        with self.assertRaises(JobLifecycleError):
            self.service.cancel_job("invalid-nonexistent-id")


class TestAIPlannerInterface(unittest.TestCase):
    """Verifies that Person 3's AI Planner recommendations are strictly validated and gatekept."""

    def setUp(self) -> None:
        self.validator = AIRecommendationValidator()
        self.target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://127.0.0.1:3000",
            is_in_scope=True,
        )

    def test_valid_ai_recommendation_accepted(self) -> None:
        """A safe, compatible AI recommendation successfully validates into a ScanJobRequest."""
        rec = AIPlanRecommendation(
            assessment_id="assess-ai-01",
            asset_id="asset-web-01",
            scanner_id="mock_scanner",
            profile_id="mock_baseline",
            target=self.target,
            test_category="baseline_audit",
            requested_permission_level=PermissionLevel.SAFE_AUDIT,
            resource_budget=ResourceBudget(max_cpu_percent=30, max_memory_mb=256, max_rate_limit=100),
            evidence_ids=["evidence-port-discovery-01"],
            rationale="Discovered open HTTP port, recommending baseline web audit.",
        )

        job_req = self.validator.validate_recommendation(rec)

        self.assertIsInstance(job_req, ScanJobRequest)
        self.assertEqual(job_req.assessment_id, "assess-ai-01")
        self.assertEqual(job_req.scanner_id, "mock_scanner")
        self.assertEqual(job_req.profile_id, "mock_baseline")
        self.assertEqual(job_req.options["evidence_ids"], ["evidence-port-discovery-01"])

    def test_unknown_scanner_recommendation_rejected(self) -> None:
        """AI recommending an unregistered or arbitrary scanner is rejected."""
        rec = AIPlanRecommendation(
            assessment_id="assess-ai-02",
            asset_id="asset-web-02",
            scanner_id="custom_ai_exploit_runner",
            profile_id="mock_baseline",
            target=self.target,
        )

        with self.assertRaises(AIRecommendationValidationError) as ctx:
            self.validator.validate_recommendation(rec)
        self.assertIn("Unknown or unregistered scanner", str(ctx.exception))

    def test_unapproved_profile_recommendation_rejected(self) -> None:
        """AI recommending an arbitrary unapproved profile string is rejected."""
        rec = AIPlanRecommendation(
            assessment_id="assess-ai-03",
            asset_id="asset-web-03",
            scanner_id="mock_scanner",
            profile_id="mock_arbitrary_unapproved_scan",
            target=self.target,
        )

        with self.assertRaises(AIRecommendationValidationError) as ctx:
            self.validator.validate_recommendation(rec)
        self.assertIn("Unknown or unapproved scan profile", str(ctx.exception))

    def test_incompatible_scanner_profile_pairing_rejected(self) -> None:
        """AI pairing Nmap profile with ZAP scanner is rejected."""
        rec = AIPlanRecommendation(
            assessment_id="assess-ai-04",
            asset_id="asset-web-04",
            scanner_id="owasp_zap",
            profile_id="nmap_fast_discovery",
            target=self.target,
        )

        with self.assertRaises(AIRecommendationValidationError) as ctx:
            self.validator.validate_recommendation(rec)
        self.assertIn("not compatible with scanner", str(ctx.exception))

    def test_out_of_scope_target_recommendation_rejected(self) -> None:
        """AI recommending a scan against an out-of-scope or public target is rejected."""
        public_target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="https://unauthorized-bank.com",
            is_in_scope=True,
        )
        rec = AIPlanRecommendation(
            assessment_id="assess-ai-05",
            asset_id="asset-web-05",
            scanner_id="mock_scanner",
            profile_id="mock_baseline",
            target=public_target,
        )

        with self.assertRaises(AIRecommendationValidationError) as ctx:
            self.validator.validate_recommendation(rec)
        self.assertIn("violates assessment scope", str(ctx.exception))

    def test_insufficient_permission_level_rejected(self) -> None:
        """AI requesting READ_ONLY for an ACTIVE_PROBE profile is rejected."""
        rec = AIPlanRecommendation(
            assessment_id="assess-ai-06",
            asset_id="asset-web-06",
            scanner_id="owasp_zap",
            profile_id="zap_active_baseline",
            target=self.target,
            requested_permission_level=PermissionLevel.READ_ONLY,  # Active requires ACTIVE_PROBE
        )

        with self.assertRaises(AIRecommendationValidationError) as ctx:
            self.validator.validate_recommendation(rec)
        self.assertIn("insufficient", str(ctx.exception).lower())

    def test_excessive_resource_budget_rejected(self) -> None:
        """AI proposing a resource budget that exceeds the platform ceiling is rejected."""
        rec = AIPlanRecommendation(
            assessment_id="assess-ai-07",
            asset_id="asset-web-07",
            scanner_id="mock_scanner",
            profile_id="mock_baseline",
            target=self.target,
            resource_budget=ResourceBudget(max_cpu_percent=99, max_memory_mb=4096, max_rate_limit=5000),
        )

        with self.assertRaises(AIRecommendationValidationError) as ctx:
            self.validator.validate_recommendation(rec)
        self.assertIn("exceeds platform limits", str(ctx.exception))

    def test_invalid_evidence_id_rejected(self) -> None:
        """AI providing invalid or path traversal evidence IDs is rejected."""
        rec = AIPlanRecommendation(
            assessment_id="assess-ai-08",
            asset_id="asset-web-08",
            scanner_id="mock_scanner",
            profile_id="mock_baseline",
            target=self.target,
            evidence_ids=["../../etc/shadow"],
        )

        with self.assertRaises(AIRecommendationValidationError) as ctx:
            self.validator.validate_recommendation(rec)
        self.assertIn("malformed or unsafe evidence id", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
