"""Tests for authentication endpoints."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def mock_cognito_success():
    """Mock successful Cognito authentication."""
    with patch("app.api.auth.boto3.client") as mock:
        mock_client = MagicMock()
        mock_client.initiate_auth.return_value = {
            "AuthenticationResult": {
                "IdToken": "mock-id-token",
                "AccessToken": "mock-access-token",
                "RefreshToken": "mock-refresh-token",
            }
        }
        mock.return_value = mock_client
        yield mock_client


@pytest.fixture
def mock_cognito_new_password_required():
    """Mock Cognito requiring new password."""
    with patch("app.api.auth.boto3.client") as mock:
        mock_client = MagicMock()
        mock_client.initiate_auth.return_value = {
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "Session": "mock-session",
        }
        mock.return_value = mock_client
        yield mock_client


class TestLogin:
    """Tests for login endpoint."""

    def test_login_success(self, client, mock_cognito_success):
        """Test successful login sets cookie."""
        response = client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "password123"},
        )

        assert response.status_code == 200
        assert response.json()["message"] == "Login exitoso"
        assert response.json()["email"] == "test@example.com"
        assert "access_token" in response.cookies

    def test_login_requires_new_password(self, client, mock_cognito_new_password_required):
        """Test login returns new password required."""
        response = client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "temppass"},
        )

        assert response.status_code == 200
        assert response.json()["requires_new_password"] is True
        assert response.json()["email"] == "test@example.com"

    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials."""
        with patch("app.api.auth.boto3.client") as mock:
            from botocore.exceptions import ClientError

            mock_client = MagicMock()
            mock_client.initiate_auth.side_effect = ClientError(
                {"Error": {"Code": "NotAuthorizedException"}},
                "InitiateAuth",
            )
            mock.return_value = mock_client

            response = client.post(
                "/auth/login",
                json={"email": "test@example.com", "password": "wrong"},
            )

            assert response.status_code == 401
            assert "incorrectos" in response.json()["detail"]


class TestLogout:
    """Tests for logout endpoint."""

    def test_logout_clears_cookie(self, client):
        """Test logout clears access token cookie."""
        response = client.post("/auth/logout")

        assert response.status_code == 200
        assert response.json()["message"] == "Sesión cerrada"


class TestForgotPassword:
    """Tests for forgot password endpoint."""

    def test_forgot_password_sends_code(self, client):
        """Test forgot password initiates reset."""
        with patch("app.api.auth.boto3.client") as mock:
            mock_client = MagicMock()
            mock.return_value = mock_client

            response = client.post(
                "/auth/forgot-password",
                json={"email": "test@example.com"},
            )

            assert response.status_code == 200
            assert "enviado" in response.json()["message"]
            mock_client.forgot_password.assert_called_once()


class TestResetPassword:
    """Tests for reset password endpoint."""

    def test_reset_password_success(self, client):
        """Test password reset with valid code."""
        with patch("app.api.auth.boto3.client") as mock:
            mock_client = MagicMock()
            mock.return_value = mock_client

            response = client.post(
                "/auth/reset-password",
                json={
                    "email": "test@example.com",
                    "code": "123456",
                    "new_password": "NewPassword123!",
                },
            )

            assert response.status_code == 200
            assert "restablecida" in response.json()["message"]
            mock_client.confirm_forgot_password.assert_called_once()

    def test_reset_password_invalid_code(self, client):
        """Test password reset with invalid code."""
        with patch("app.api.auth.boto3.client") as mock:
            from botocore.exceptions import ClientError

            mock_client = MagicMock()
            mock_client.confirm_forgot_password.side_effect = ClientError(
                {"Error": {"Code": "CodeMismatchException"}},
                "ConfirmForgotPassword",
            )
            mock.return_value = mock_client

            response = client.post(
                "/auth/reset-password",
                json={
                    "email": "test@example.com",
                    "code": "wrong",
                    "new_password": "NewPassword123!",
                },
            )

            assert response.status_code == 400
            assert "incorrecto" in response.json()["detail"]
