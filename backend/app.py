import os
from typing import List, Optional
from fastapi import Depends, FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from modules.ai.config import AIConfig
from modules.ai.service import AIAnalysisService
from schemas.contracts import AIAnalysis, Evidence, Finding

app = FastAPI(
    title="ZeroTrace / AegisPT Security Core API",
    description="Backend orchestration, scope validation, and evidence-grounded AI analysis API.",
    version="1.0.0",
)

# Enable CORS for local Vite dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_api_auth_token() -> str:
    """Read API token from environment dynamically."""
    return os.getenv("API_AUTH_TOKEN", "").strip()


def verify_authentication(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> bool:
    """
    Validate incoming request credentials against configured token.
    If no token is configured in lab environment, permits local requests.
    """
    configured_token = get_api_auth_token()
    if not configured_token:
        return True  # Open lab sandbox mode

    provided_token = x_api_key
    if not provided_token and authorization:
        if authorization.lower().startswith("bearer "):
            provided_token = authorization[7:].strip()
        else:
            provided_token = authorization.strip()

    if provided_token != configured_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API authentication token.",
        )
    return True


class AnalyzeFindingRequest(BaseModel):
    finding: Finding
    evidence: List[Evidence] = Field(default_factory=list)


@app.get("/api/health")
def health_check():
    ai_config = AIConfig()
    return {
        "status": "healthy",
        "service": "AegisPT / ZeroTrace Backend Core",
        "ai_provider": ai_config.provider,
        "ai_model": ai_config.model_name,
        "external_calls_allowed": ai_config.allow_external_calls,
    }


@app.post(
    "/api/ai/analyze",
    response_model=AIAnalysis,
    summary="Analyze Finding with Grounded AI Reasoning",
)
def analyze_finding_endpoint(
    request: AnalyzeFindingRequest,
    authenticated: bool = Depends(verify_authentication),
):
    """
    Produce structured, evidence-grounded analysis for a supplied finding.
    Enforces anti-hallucination checks, anti-upgrade rules, and safe fallback.
    """
    service = AIAnalysisService()
    analysis = service.analyze_finding(request.finding, request.evidence)
    return analysis
