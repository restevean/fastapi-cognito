"""Auth test fixtures — FakeAuthProvider and test client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generator

import pytest
from fastapi.testclient import TestClient

from app.auth.provider import AuthProviderError, AuthResult
from app.auth.service import get_auth_provider
from app.main import app
from app.shared.config import Settings, get_settings

# ---------------------------------------------------------------------------
# FakeAuthProvider — in-memory implementation of AuthProvider Protocol
# ---------------------------------------------------------------------------

VALID_RESET_CODE = "123456"


@dataclass
class _FakeUser:
    """Internal representation of a user in FakeAuthProvider."""

    password: str
    requires_new_password: bool = False
    reset_requested: bool = False


@dataclass
class FakeAuthProvider:
    """In-memory auth provider for testing.

    Satisfies the ``AuthProvider`` Protocol via structural subtyping.
    No boto3, no network — pure logic.
    """

    users: dict[str, _FakeUser] = field(default_factory=dict)

    def authenticate(self, email: str, password: str) -> AuthResult:
        """Authenticate a user with email and password.

        Args:
            email: User's email address.
            password: User's password.

        Returns:
            AuthResult with tokens or NEW_PASSWORD_REQUIRED challenge.

        Raises:
            AuthProviderError: On invalid credentials or unknown user.
        """
        user = self.users.get(email)
        if not user:
            raise AuthProviderError(
                message="User not found",
                error_code="UserNotFoundException",
            )

        if user.password != password:
            raise AuthProviderError(
                message="Invalid email or password",
                error_code="NotAuthorizedException",
            )

        if user.requires_new_password:
            return AuthResult(
                tokens=None,
                challenge="NEW_PASSWORD_REQUIRED",
                session="fake-session-token",
                email=email,
            )

        return AuthResult(
            tokens={
                "IdToken": "fake-id-token",
                "AccessToken": "fake-access-token",
                "RefreshToken": "fake-refresh-token",
            },
            challenge=None,
            session=None,
            email=email,
        )

    def respond_to_new_password_challenge(
        self, email: str, session: str, new_password: str
    ) -> AuthResult:
        """Respond to a NEW_PASSWORD_REQUIRED challenge.

        Args:
            email: User's email address.
            session: Session token from initial auth challenge.
            new_password: The new password to set.

        Returns:
            AuthResult with tokens on success.

        Raises:
            AuthProviderError: If user not found.
        """
        user = self.users.get(email)
        if not user:
            raise AuthProviderError(
                message="User not found",
                error_code="UserNotFoundException",
            )

        user.requires_new_password = False
        user.password = new_password

        return AuthResult(
            tokens={
                "IdToken": "fake-id-token",
                "AccessToken": "fake-access-token",
                "RefreshToken": "fake-refresh-token",
            },
            challenge=None,
            session=None,
            email=email,
        )

    def forgot_password(self, email: str) -> None:
        """Initiate forgot-password flow.

        Args:
            email: User's email address.

        Raises:
            AuthProviderError: If user not found.
        """
        user = self.users.get(email)
        if not user:
            raise AuthProviderError(
                message="User not found",
                error_code="UserNotFoundException",
            )

        user.reset_requested = True

    def confirm_forgot_password(self, email: str, code: str, new_password: str) -> None:
        """Complete password reset with verification code.

        Args:
            email: User's email address.
            code: Verification code (must be ``VALID_RESET_CODE``).
            new_password: New password to set.

        Raises:
            AuthProviderError: If user not found or code is invalid.
        """
        user = self.users.get(email)
        if not user:
            raise AuthProviderError(
                message="User not found",
                error_code="UserNotFoundException",
            )

        if code != VALID_RESET_CODE:
            raise AuthProviderError(
                message="Invalid verification code",
                error_code="CodeMismatchException",
            )

        user.password = new_password
        user.reset_requested = False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_provider() -> FakeAuthProvider:
    """FakeAuthProvider pre-loaded with test users."""
    provider = FakeAuthProvider()
    provider.users["test@example.com"] = _FakeUser(password="password123")
    provider.users["newuser@example.com"] = _FakeUser(
        password="temppass",
        requires_new_password=True,
    )
    return provider


def _get_test_settings() -> Settings:
    """Test settings with Cognito configured (non-empty) and cookie_secure=False."""
    return Settings(
        cognito_user_pool_id="eu-west-1_FAKE",
        cognito_client_id="fake-client-id",
        aws_region="eu-west-1",
        cookie_secure=False,
    )


@pytest.fixture
def auth_client(fake_provider: FakeAuthProvider) -> Generator[TestClient, None, None]:
    """TestClient with FakeAuthProvider and test settings injected.

    Overrides both ``get_settings`` and ``get_auth_provider`` so the
    auth router uses FakeAuthProvider instead of CognitoAuthProvider.
    """
    app.dependency_overrides[get_settings] = _get_test_settings
    app.dependency_overrides[get_auth_provider] = lambda: fake_provider
    yield TestClient(app)
    app.dependency_overrides.clear()
