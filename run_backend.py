import uvicorn

from backend.app.core.config import settings

if __name__ == "__main__":
    print("=" * 60)
    print(f"  🛡️  {settings.APP_NAME} v{settings.APP_VERSION} Backend Skeleton")
    print(f"  📡 API Server: http://{settings.HOST}:{settings.PORT}")
    print(f"  🩺 Health Check: http://{settings.HOST}:{settings.PORT}/health")
    print(f"  📚 OpenAPI Docs: http://{settings.HOST}:{settings.PORT}/docs")
    print("=" * 60)

    uvicorn.run(
        "backend.app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
