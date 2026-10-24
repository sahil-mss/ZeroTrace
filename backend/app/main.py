from fastapi import FastAPI

from backend.app.api.health import router as health_router
from backend.app.core.config import settings


def create_application() -> FastAPI:
    """Factory creating and configuring the primary FastAPI application instance."""
    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="AegisPT: AI-Powered Penetration Testing & Security Research Platform",
    )

    # Register API route handlers
    application.include_router(health_router)

    return application


app = create_application()
