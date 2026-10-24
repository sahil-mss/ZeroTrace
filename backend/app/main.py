from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.ai_endpoints import router as ai_router
from backend.app.api.assessments import router as assessments_router
from backend.app.api.health import router as health_router
from backend.app.core.config import settings


def create_application(cors_origins: list[str] | None = None) -> FastAPI:
    """Factory creating and configuring the primary FastAPI application instance."""
    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="ZeroTrace: AI-Powered Penetration Testing & Security Research Platform",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Conservative CORS configuration: no arbitrary wildcard origins allowed by default
    origins = cors_origins or settings.CORS_ALLOWED_ORIGINS
    application.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
    )

    # Register API route handlers
    application.include_router(health_router)
    application.include_router(assessments_router)
    application.include_router(ai_router)

    return application


app = create_application()
