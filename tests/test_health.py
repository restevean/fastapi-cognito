"""Tests for health check endpoint."""

from fastapi.testclient import TestClient


class TestHealthEndpoint:
    """Test suite for health check endpoint."""

    def test_health_returns_healthy_status(self, client: TestClient) -> None:
        """GET /health should return 200 and healthy status."""
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}
