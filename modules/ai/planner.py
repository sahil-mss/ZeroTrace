from typing import List, Optional
from pydantic import BaseModel, Field

from schemas.contracts import Assessment, Asset, Finding


class TestRecommendation(BaseModel):
    """A bounded proposal for a test execution profile. Subject to policy engine authorization."""
    recommended_profile: str = Field(..., description="Target test profile (e.g. passive_crawl, port_scan, api_audit)")
    target_asset_id: str = Field(..., description="Asset identifier to be probed")
    target_url_or_host: str = Field(..., description="Canonical hostname or IP")
    justification: str = Field(..., description="Reasoning based on observed asset properties or gaps")
    requires_human_approval: bool = Field(default=False, description="Flag for intrusive or active checks")
    preconditions: List[str] = Field(default_factory=list, description="Required setup or completed stages")


class SafeTestPlanner:
    """
    Intelligent test planner for next-step security testing.
    Proposes bounded test profiles to Person 1's orchestrator; does NOT execute commands directly.
    """

    def plan_next_steps(
        self,
        assessment: Assessment,
        assets: List[Asset],
        existing_findings: List[Finding],
        previously_run_profiles: Optional[List[str]] = None,
    ) -> List[TestRecommendation]:
        completed_profiles = set(previously_run_profiles or [])
        recommendations: List[TestRecommendation] = []

        # 1. Inspect un-scanned assets
        for asset in assets:
            if asset.asset_type == "web_app":
                if "passive_web_crawl" not in completed_profiles:
                    recommendations.append(
                        TestRecommendation(
                            recommended_profile="passive_web_crawl",
                            target_asset_id=asset.id,
                            target_url_or_host=asset.hostname_or_address,
                            justification="Discover endpoints, forms, and API schemas on newly observed web application.",
                            requires_human_approval=False,
                            preconditions=["Asset verified in assessment scope"],
                        )
                    )
                elif "web_active_inspection" not in completed_profiles:
                    recommendations.append(
                        TestRecommendation(
                            recommended_profile="web_active_inspection",
                            target_asset_id=asset.id,
                            target_url_or_host=asset.hostname_or_address,
                            justification="Passive reconnaissance completed; probe input parameters for SQLi and XSS.",
                            requires_human_approval=True,  # Active scans require explicit authorization
                            preconditions=["passive_web_crawl completed", "Scope policy permits active testing"],
                        )
                    )

            elif asset.asset_type in ("ip", "domain"):
                if "port_scan" not in completed_profiles:
                    recommendations.append(
                        TestRecommendation(
                            recommended_profile="port_scan",
                            target_asset_id=asset.id,
                            target_url_or_host=asset.hostname_or_address,
                            justification="Enumerate listening TCP services and identify open service ports.",
                            requires_human_approval=False,
                            preconditions=["Asset canonicalized and confirmed in scope"],
                        )
                    )

        # 2. Check if findings warrant verification retests
        unverified_findings = [
            f for f in existing_findings if f.verification_status.value == "unverified"
        ]
        for f in unverified_findings:
            recommendations.append(
                TestRecommendation(
                    recommended_profile="targeted_verification_probe",
                    target_asset_id=f.asset_id or assessment.target,
                    target_url_or_host=assessment.target,
                    justification=f"Independent confirmation probe required for candidate finding: {f.title}.",
                    requires_human_approval=False,
                    preconditions=["Low-impact confirmation check only", "Zero destructive payloads"],
                )
            )

        return recommendations
