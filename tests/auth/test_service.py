"""Tests for AuthService — unit tests with FakeAuthProvider, no HTTP."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.auth.schemas import Messages
from app.auth.service import AuthService
from app.shared.config import Settings

from .conftest import FakeAuthProvider, _FakeUser

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings() -> Settings:
    """Test settings with Cognito configured."""
    return Settings(
        cognito_user_pool_id="eu-west-1_Fake",
        cognito_client_id="fake-client-id",
        aws_region="eu-west-1",
        cookie_secure=False,
    )


@pytest.fixture
def provider() -> FakeAuthProvider:
    """FakeAuthProvider with test users."""
    p = FakeAuthProvider()
    p.users["user@example.com"] = _FakeUser(password="correct-password")
    p.users["newuser@example.com"] = _FakeUser(
        password="temp-pass",
        requires_new_password=True,
    )
    return p


@pytest.fixture
def service(provider: FakeAuthProvider, settings: Settings) -> AuthService:
    """AuthService with FakeAuthProvider."""
    return AuthService(provider=provider, settings=settings)


# ---------------------------------------------------------------------------
# Tests: login
# ---------------------------------------------------------------------------


class TestLogin:
    """Tests for AuthService.login and login_with_tokens."""

    def test_login_success(self, service: AuthService) -> None:
        """Successful login returns success message and email."""
        response = service.login("user@example.com", "correct-password")

        assert response.message == Messages.LOGIN_SUCCESS
        assert response.email == "user@example.com"
        assert response.requires_new_password is False

    def test_login_invalid_credentials_raises(self, service: AuthService) -> None:
        """Wrong password raises HTTPException 401."""
        with pytest.raises(HTTPException) as exc_info:
            service.login("user@example.com", "wrong-password")

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid email or password"

    def test_login_new_password_required(self, service: AuthService) -> None:
        """User with temp password gets NEW_PASSWORD_REQUIRED challenge."""
        response = service.login("newuser@example.com", "temp-pass")

        assert response.message == Messages.NEW_PASSWORD_REQUIRED
        assert response.email == "newuser@example.com"
        assert response.requires_new_password is True


# ---------------------------------------------------------------------------
# Tests: set new password
# ---------------------------------------------------------------------------


class TestSetNewPassword:
    """Tests for AuthService.set_new_password."""

    def test_set_new_password_success(self, service: AuthService) -> None:
        """Successfully set new password returns tokens."""
        response, tokens = service.set_new_password(
            email="newuser@example.com",
            temporary_password="temp-pass",
            new_password="NewSecure123!",
        )

        assert response.message == Messages.NEW_PASSWORD_SET
        assert response.email == "newuser@example.com"
        assert tokens is not None
        assert "IdToken" in tokens

    def test_set_new_password_wrong_temp_password(self, service: AuthService) -> None:
        """Wrong temporary password raises HTTPException 400."""
        with pytest.raises(HTTPException) as exc_info:
            service.set_new_password(
                email="newuser@example.com",
                temporary_password="wrong-temp",
                new_password="NewSecure123!",
            )

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "Invalid email or password"


# ---------------------------------------------------------------------------
# Tests: forgot password
# ---------------------------------------------------------------------------


class TestForgotPassword:
    """Tests for AuthService.forgot_password."""

    def test_forgot_password_success(self, service: AuthService) -> None:
        """Forgot password returns confirmation message."""
        response = service.forgot_password("user@example.com")

        assert response.message == Messages.FORGOT_PASSWORD_CODE_SENT
        assert response.email == "user@example.com"


# ---------------------------------------------------------------------------
# Tests: reset password
# ---------------------------------------------------------------------------


class TestResetPassword:
    """Tests for AuthService.reset_password."""

    def test_reset_password_success(self, service: AuthService) -> None:
        """Valid reset code resets password."""
        response = service.reset_password(
            email="user@example.com",
            code="123456",
            new_password="NewPassword123!",
        )

        assert response.message == Messages.PASSWORD_RESET_SUCCESS
        assert response.email == "user@example.com"

    def test_reset_password_invalid_code(self, service: AuthService) -> None:
        """Invalid reset code raises HTTPException 400."""
        with pytest.raises(HTTPException) as exc_info:
            service.reset_password(
                email="user@example.com",
                code="wrong-code",
                new_password="NewPassword123!",
            )

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "Invalid verification code"


# ---------------------------------------------------------------------------
# Tests: provider not configured
# ---------------------------------------------------------------------------


class TestProviderNotConfigured:
    """Tests for get_auth_provider when Cognito is not configured."""

    def test_provider_not_configured_raises_503(self) -> None:
        """Missing Cognito config raises HTTPException 503."""
        from app.auth.service import get_auth_provider

        empty_settings = Settings(
            cognito_user_pool_id="",
            cognito_client_id="",
            aws_region="eu-west-1",
        )

        with pytest.raises(HTTPException) as exc_info:
            get_auth_provider(empty_settings)

        assert exc_info.value.status_code == 503
        assert exc_info.value.detail == Messages.COGNITO_NOT_CONFIGURED
