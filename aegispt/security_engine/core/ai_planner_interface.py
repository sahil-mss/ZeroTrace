"""AI Planner Interface and Recommendation Validation.

TASK 3: Establishes a strict boundary between Person 3's AI planning module
and Person 2's security testing engine. Person 2 retains authoritative control
over execution, rejecting unsafe or out-of-policy AI recommendations.

Guarantees:
- AI recommendations are never executed blindly.
- Registered scanner adapters and approved scan profiles are strictly enforced.
- Scope rules and resource limits cannot be overridden by AI prompts.
- All rejection decisions provide structured, auditable feedback.
"""

from typing import Any
import uuid

from pydantic import BaseModel, Field

from aegispt.security_engine.core.exceptions import (
    AIRecommendationValidationError,
    ScopeViolationError,
)
from aegispt.security_engine.core.scope import BaseScopeValidator, LocalScopeValidator
from aegispt.security_engine.schemas.enums import AssetType, PermissionLevel
from aegispt.security_engine.schemas.job import ScanJobRequest
from aegispt.security_engine.schemas.profile import APPROVED_SCAN_PROFILES, ResourceBudget, ScanProfile
from aegispt.security_engine.schemas.target import ScanTarget


class AIPlanRecommendation(BaseModel):
    """Scan recommendation payload produced by Person 3's AI planner."""

    recommendation_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique recommendation tracking ID.",
    )
    assessment_id: str = Field(
        ...,
        min_length=1,
        description="Target assessment or engagement ID.",
    )
    asset_id: str = Field(
        ...,
        min_length=1,
        description="Authoritative asset ID to test.",
    )
    scanner_id: str = Field(
        ...,
        min_length=1,
        description="Requested scanner tool (e.g. 'nmap', 'owasp_zap', 'mock_scanner').",
    )
    profile_id: str = Field(
        ...,
        min_length=1,
        description="Predefined scan profile ID.",
    )
    target: ScanTarget = Field(
        ...,
        description="Target asset specification proposed by the AI.",
    )
    test_category: str = Field(
        default="general_security_audit",
        description="Vulnerability category or test purpose (e.g. 'port_discovery', 'injection_audit').",
    )
    requested_permission_level: PermissionLevel = Field(
        default=PermissionLevel.SAFE_AUDIT,
        description="Permission level claimed or requested by the AI planner.",
    )
    resource_budget: ResourceBudget = Field(
        default_factory=ResourceBudget,
        description="Proposed resource limits.",
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Prior evidence IDs supporting this recommendation (e.g. discovered port artifact).",
    )
    rationale: str | None = Field(
        default=None,
        description="AI justification for running this particular scan.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Supplementary AI reasoning metadata.",
    )


class AIRecommendationValidator:
    """Authoritative gatekeeper validating AI Planner recommendations against engine policies."""

    def __init__(
        self,
        registered_scanner_ids: set[str] | None = None,
        approved_profiles: dict[str, ScanProfile] | None = None,
        scope_validator: BaseScopeValidator | None = None,
        max_budget: ResourceBudget | None = None,
        max_permitted_level: PermissionLevel = PermissionLevel.INTRUSIVE,
    ) -> None:
        """Initialize the validator.

        Args:
            registered_scanner_ids: Whitelist of active scanner IDs.
            approved_profiles: Map of approved ScanProfile objects.
            scope_validator: Scope policy enforcer (defaults to LocalScopeValidator).
            max_budget: Platform-wide resource ceiling.
            max_permitted_level: Highest permission level authorized for the engagement.
        """
        self.registered_scanner_ids = registered_scanner_ids or {"mock_scanner", "nmap", "owasp_zap"}
        self.approved_profiles = approved_profiles or APPROVED_SCAN_PROFILES
        self.scope_validator = scope_validator or LocalScopeValidator()
        self.max_budget = max_budget or ResourceBudget(
            max_cpu_percent=80,
            max_memory_mb=2048,
            max_rate_limit=500,
        )
        self.max_permitted_level = max_permitted_level

    def validate_recommendation(self, rec: AIPlanRecommendation) -> ScanJobRequest:
        """Validate an AI plan recommendation and convert it to an authorized ScanJobRequest.

        Raises AIRecommendationValidationError if any policy, scope, or capability check fails.
        """
        # Check 1: Scanner Registry Validation
        if rec.scanner_id not in self.registered_scanner_ids:
            raise AIRecommendationValidationError(
                f"Unknown or unregistered scanner '{rec.scanner_id}'. "
                f"Registered scanners are: {sorted(list(self.registered_scanner_ids))}."
            )

        # Check 2: Profile Validation
        if rec.profile_id not in self.approved_profiles:
            raise AIRecommendationValidationError(
                f"Unknown or unapproved scan profile '{rec.profile_id}'. "
                f"AI planner may only recommend predefined approved profiles."
            )
        profile = self.approved_profiles[rec.profile_id]

        # Check 3: Profile and Scanner Compatibility
        scanner_profile_map: dict[str, set[str]] = {
            "mock_scanner": {"mock_baseline", "mock_intrusive_approval", "mock_timeout_sim"},
            "nmap": {"nmap_fast_discovery", "nmap_service_version", "nmap_custom_ports"},
            "owasp_zap": {"zap_passive_baseline", "zap_active_baseline"},
        }
        allowed_profiles = scanner_profile_map.get(rec.scanner_id, set())
        if rec.profile_id not in allowed_profiles:
            raise AIRecommendationValidationError(
                f"Scan profile '{rec.profile_id}' is not compatible with scanner '{rec.scanner_id}'."
            )

        # Check 4: Asset Type Compatibility
        if rec.target.asset_type not in profile.supported_asset_types:
            raise AIRecommendationValidationError(
                f"Target asset type '{rec.target.asset_type.value}' is not supported by "
                f"profile '{rec.profile_id}' (supports: {[t.value for t in profile.supported_asset_types]})."
            )

        # Check 5: Authoritative Scope Enforcement
        try:
            self.scope_validator.validate_target(rec.target, assessment_id=rec.assessment_id)
        except ScopeViolationError as exc:
            raise AIRecommendationValidationError(
                f"AI recommendation rejected: Target violates assessment scope. Details: {exc}"
            ) from exc

        # Check 6: Permission Level Hierarchy
        # Level ranks: READ_ONLY (1) < SAFE_AUDIT (2) < ACTIVE_PROBE (3) < INTRUSIVE (4)
        level_order = {
            PermissionLevel.READ_ONLY: 1,
            PermissionLevel.SAFE_AUDIT: 2,
            PermissionLevel.ACTIVE_PROBE: 3,
            PermissionLevel.INTRUSIVE: 4,
        }
        rec_level_rank = level_order.get(rec.requested_permission_level, 0)
        profile_level_rank = level_order.get(profile.required_permission_level, 0)
        max_level_rank = level_order.get(self.max_permitted_level, 0)

        if rec_level_rank < profile_level_rank:
            raise AIRecommendationValidationError(
                f"Requested permission level '{rec.requested_permission_level.value}' is insufficient; "
                f"profile '{rec.profile_id}' requires '{profile.required_permission_level.value}'."
            )
        if profile_level_rank > max_level_rank:
            raise AIRecommendationValidationError(
                f"Profile '{rec.profile_id}' requires permission level '{profile.required_permission_level.value}', "
                f"which exceeds platform engagement ceiling '{self.max_permitted_level.value}'."
            )

        # Check 7: Resource Budget Constraints
        if (
            rec.resource_budget.max_cpu_percent > self.max_budget.max_cpu_percent
            or rec.resource_budget.max_memory_mb > self.max_budget.max_memory_mb
            or rec.resource_budget.max_rate_limit > self.max_budget.max_rate_limit
        ):
            raise AIRecommendationValidationError(
                f"Requested resource budget ({rec.resource_budget}) exceeds platform limits ({self.max_budget})."
            )

        # Check 8: Evidence References Validity
        if rec.evidence_ids:
            for eid in rec.evidence_ids:
                if not eid or not isinstance(eid, str) or not eid.strip():
                    raise AIRecommendationValidationError(
                        f"AI recommendation references an invalid empty or whitespace evidence ID."
                    )
                # Ensure no path traversal or suspicious tokens in evidence IDs
                if any(c in eid for c in ["/", "\\", "..", "<", ">", ";", "&"]):
                    raise AIRecommendationValidationError(
                        f"AI recommendation contains malformed or unsafe evidence ID: '{eid}'."
                    )

        # Create validated ScanJobRequest
        return ScanJobRequest(
            assessment_id=rec.assessment_id,
            asset_id=rec.asset_id,
            target=rec.target,
            scanner_id=rec.scanner_id,
            profile_id=rec.profile_id,
            permission_level=rec.requested_permission_level,
            resource_budget=rec.resource_budget,
            approved_by_operator=False,  # Still subject to operator approval check if intrusive
            options={
                "test_category": rec.test_category,
                "rationale": rec.rationale,
                "evidence_ids": rec.evidence_ids,
                **rec.metadata,
            },
        )
