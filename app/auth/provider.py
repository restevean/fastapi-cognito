"""Auth provider port — Protocol and domain types for authentication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class AuthResult:
    """Result of an authentication operation.

    Attributes:
        tokens: Dict with IdToken, AccessToken, RefreshToken when auth succeeds.
        challenge: Challenge name (e.g. ``NEW_PASSWORD_REQUIRED``) or ``None``.
        session: Session string for multi-step challenge flows, or ``None``.
        email: The email address used in the authentication attempt.
    """

    tokens: dict[str, str] | None
    challenge: str | None
    session: str | None
    email: str


class AuthProviderError(Exception):
    """Domain exception raised by auth provider adapters.

    Attributes:
        message: Human-readable error description.
        error_code: Provider-specific error code (e.g. Cognito error code).
    """

    def __init__(self, message: str, error_code: str) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class AuthProvider(Protocol):
    """Port for external authentication providers (structural subtyping)."""

    def authenticate(self, email: str, password: str) -> AuthResult:
        """Authenticate a user with email and password.

        Args:
            email: User's email address.
            password: User's password.

        Returns:
            AuthResult with tokens on success, or challenge info if required.

        Raises:
            AuthProviderError: When the provider rejects the request.
        """
        ...

    def respond_to_new_password_challenge(
        self, email: str, session: str, new_password: str
    ) -> AuthResult:
        """Respond to a NEW_PASSWORD_REQUIRED challenge.

        Args:
            email: User's email address.
            session: Session token from the initial auth challenge.
            new_password: The new password to set.

        Returns:
            AuthResult with tokens on success.

        Raises:
            AuthProviderError: When the provider rejects the request.
        """
        ...

    def forgot_password(self, email: str) -> None:
        """Initiate the forgot-password flow (sends verification code).

        Args:
            email: User's email address.

        Raises:
            AuthProviderError: When the provider rejects the request.
        """
        ...

    def confirm_forgot_password(self, email: str, code: str, new_password: str) -> None:
        """Complete password reset with a verification code.

        Args:
            email: User's email address.
            code: Verification code received by the user.
            new_password: The new password to set.

        Raises:
            AuthProviderError: When the provider rejects the request.
        """
        ...
