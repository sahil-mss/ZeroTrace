from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.main import app


def test_health_check_endpoint():
    """Verify that GET /health returns HTTP 200 and expected application metadata."""
    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert data["app_name"] == settings.APP_NAME
    assert data["version"] == settings.APP_VERSION
    assert "environment" in data
