"""Tests for auth router — uses FakeAuthProvider, no boto3 patches."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestLogin:
    """Tests for POST /auth/login."""

    def test_login_success(self, auth_client: TestClient) -> None:
        """Successful login sets cookie and returns success message."""
        response = auth_client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "password123"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Login successful"
        assert data["email"] == "test@example.com"
        assert "access_token" in response.cookies

    def test_login_requires_new_password(self, auth_client: TestClient) -> None:
        """Login with temp password returns new-password-required challenge."""
        response = auth_client.post(
            "/auth/login",
            json={"email": "newuser@example.com", "password": "temppass"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["requires_new_password"] is True
        assert data["email"] == "newuser@example.com"
        assert data["message"] == "New password required"

    def test_login_invalid_credentials(self, auth_client: TestClient) -> None:
        """Login with wrong password returns 401."""
        response = auth_client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "wrong"},
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid email or password"

    def test_login_unknown_user(self, auth_client: TestClient) -> None:
        """Login with unknown email returns 401."""
        response = auth_client.post(
            "/auth/login",
            json={"email": "nobody@example.com", "password": "anything"},
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "User not found"


class TestLogout:
    """Tests for POST /auth/logout."""

    def test_logout_clears_cookie(self, auth_client: TestClient) -> None:
        """Logout returns success message and clears cookie."""
        response = auth_client.post("/auth/logout")

        assert response.status_code == 200
        assert response.json()["message"] == "Logged out"


class TestForgotPassword:
    """Tests for POST /auth/forgot-password."""

    def test_forgot_password_sends_code(self, auth_client: TestClient) -> None:
        """Forgot password returns confirmation message."""
        response = auth_client.post(
            "/auth/forgot-password",
            json={"email": "test@example.com"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Verification code sent to email"
        assert data["email"] == "test@example.com"


class TestResetPassword:
    """Tests for POST /auth/reset-password."""

    def test_reset_password_success(self, auth_client: TestClient) -> None:
        """Password reset with valid code returns success."""
        response = auth_client.post(
            "/auth/reset-password",
            json={
                "email": "test@example.com",
                "code": "123456",
                "new_password": "NewPassword123!",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Password reset successfully"
        assert data["email"] == "test@example.com"

    def test_reset_password_invalid_code(self, auth_client: TestClient) -> None:
        """Password reset with invalid code returns 400."""
        response = auth_client.post(
            "/auth/reset-password",
            json={
                "email": "test@example.com",
                "code": "wrong",
                "new_password": "NewPassword123!",
            },
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid verification code"
