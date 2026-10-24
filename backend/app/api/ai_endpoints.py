
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from modules.ai.config import AIConfig
from modules.ai.service import AIAnalysisService
from schemas.contracts import AIAnalysis, Evidence, Finding

router = APIRouter(tags=["AI Analysis & Upstream"])


from backend.app.api.auth import verify_api_token


class AnalyzeFindingRequest(BaseModel):
    finding: Finding
    evidence: list[Evidence] = Field(default_factory=list)


@router.get("/api/health")
def health_check():
    ai_config = AIConfig()
    return {
        "status": "healthy",
        "service": "ZeroTrace Backend Core",
        "ai_provider": ai_config.provider,
        "ai_model": ai_config.model_name,
        "external_calls_allowed": ai_config.allow_external_calls,
    }


@router.post(
    "/api/ai/analyze",
    response_model=AIAnalysis,
    summary="Analyze Finding with Grounded AI Reasoning",
)
def analyze_finding_endpoint(
    request: AnalyzeFindingRequest,
    _token: str = Depends(verify_api_token),
):
    """
    Produce structured, evidence-grounded analysis for a supplied finding.
    Enforces anti-hallucination checks, anti-upgrade rules, and safe fallback.
    """
    service = AIAnalysisService()
    analysis = service.analyze_finding(request.finding, request.evidence)
    return analysis


class RawIngestionPayload(BaseModel):
    assessment: dict | None = None
    assets: list[dict] = Field(default_factory=list)
    findings: list[dict] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    fallback_assessment_id: str = "assess_unknown"


@router.post(
    "/api/upstream/normalize",
    summary="Normalize upstream OSINT, scanner, and database outputs",
)
def normalize_upstream_payload(payload: RawIngestionPayload):
    """
    Adapter endpoint normalizing Person 1 & Person 2 upstream outputs
    into Person 3 shared contracts with strict validation and anti-upgrade checks.
    """
    from backend.adapter import UpstreamNormalizer

    normalized_assessment = (
        UpstreamNormalizer.normalize_assessment(payload.assessment) if payload.assessment else None
    )

    aid = normalized_assessment.id if normalized_assessment else payload.fallback_assessment_id

    normalized_assets = [UpstreamNormalizer.normalize_asset(a, aid) for a in payload.assets]
    normalized_evidence = [UpstreamNormalizer.normalize_evidence(e, aid) for e in payload.evidence]
    normalized_findings = [UpstreamNormalizer.normalize_finding(f, aid) for f in payload.findings]

    return {
        "assessment": normalized_assessment.model_dump(mode="json")
        if normalized_assessment
        else None,
        "assets": [a.model_dump(mode="json") for a in normalized_assets],
        "findings": [f.model_dump(mode="json") for f in normalized_findings],
        "evidence": [e.model_dump(mode="json") for e in normalized_evidence],
    }


@router.get(
    "/api/upstream/modules",
    summary="Inspect connected security and OSINT module statuses",
)
def inspect_module_statuses():
    """
    Reports honest status of upstream modules (orchestrator, osint, scanners)
    without faking completed scan states.
    """
    from backend.adapter import UpstreamAssessmentClient

    client = UpstreamAssessmentClient()
    health = client.check_health()
    return {
        "orchestrator_status": health["status"],
        "osint_status": "pending" if health["status"] == "connected" else "not_connected",
        "scanner_status": "pending" if health["status"] == "connected" else "not_connected",
        "details": health["details"],
    }
