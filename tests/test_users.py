"""Tests for user endpoints."""

from fastapi.testclient import TestClient


class TestUsersEndpoints:
    """Test suite for user-related endpoints."""

    def test_get_me_without_token_returns_401(self, client: TestClient) -> None:
        """GET /users/me without token should return 401 Unauthorized."""
        response = client.get("/users/me")

        assert response.status_code == 401
        assert response.json() == {"detail": "No se proporcionó token de autenticación"}

    def test_get_me_with_valid_token_returns_user_profile(
        self, client: TestClient
    ) -> None:
        """GET /users/me with valid token should return user profile."""
        response = client.get(
            "/users/me",
            headers={"Authorization": "Bearer test-token"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "sub" in data
        assert "email" in data
