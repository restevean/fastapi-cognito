"""Auth service — orchestrates authentication operations."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.auth.cognito import CognitoAuthProvider
from app.auth.provider import AuthProvider, AuthProviderError
from app.auth.schemas import AuthResponse, Messages
from app.shared.config import Settings, get_settings


class AuthService:
    """Orchestrator for authentication flows.

    Delegates to an ``AuthProvider`` for external calls and translates
    ``AuthProviderError`` into ``HTTPException``. Cookie management is
    NOT handled here — that responsibility stays in the router layer.

    Args:
        provider: An object satisfying the ``AuthProvider`` protocol.
        settings: Application settings.
    """

    def __init__(self, provider: AuthProvider, settings: Settings) -> None:
        self._provider = provider
        self._settings = settings

    def login(self, email: str, password: str) -> AuthResponse:
        """Authenticate a user and return an auth response.

        Args:
            email: User's email address.
            password: User's password.

        Returns:
            AuthResponse with login result. Callers should inspect
            ``requires_new_password`` and, on success, read
            ``result.tokens`` from the provider result (exposed via
            the ``login_with_tokens`` method).

        Raises:
            HTTPException: On authentication failure (401).
        """
        try:
            result = self._provider.authenticate(email, password)
        except AuthProviderError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=exc.message,
            ) from exc

        if result.challenge == "NEW_PASSWORD_REQUIRED":
            return AuthResponse(
                message=Messages.NEW_PASSWORD_REQUIRED,
                email=email,
                requires_new_password=True,
            )

        return AuthResponse(
            message=Messages.LOGIN_SUCCESS,
            email=email,
        )

    def login_with_tokens(
        self, email: str, password: str
    ) -> tuple[AuthResponse, dict[str, str] | None]:
        """Authenticate and return both the response and raw tokens.

        This is the method the router should call — it needs the tokens
        to set the cookie.

        Args:
            email: User's email address.
            password: User's password.

        Returns:
            Tuple of (AuthResponse, tokens dict or None).

        Raises:
            HTTPException: On authentication failure (401).
        """
        try:
            result = self._provider.authenticate(email, password)
        except AuthProviderError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=exc.message,
            ) from exc

        if result.challenge == "NEW_PASSWORD_REQUIRED":
            response = AuthResponse(
                message=Messages.NEW_PASSWORD_REQUIRED,
                email=email,
                requires_new_password=True,
            )
            return response, None

        response = AuthResponse(
            message=Messages.LOGIN_SUCCESS,
            email=email,
        )
        return response, result.tokens

    def set_new_password(
        self, email: str, temporary_password: str, new_password: str
    ) -> tuple[AuthResponse, dict[str, str] | None]:
        """Handle the first-login new-password flow.

        First authenticates with the temporary password to obtain the session,
        then responds to the NEW_PASSWORD_REQUIRED challenge.

        Args:
            email: User's email address.
            temporary_password: Admin-assigned temporary password.
            new_password: The new password chosen by the user.

        Returns:
            Tuple of (AuthResponse, tokens dict or None).

        Raises:
            HTTPException: On failure (400).
        """
        try:
            auth_result = self._provider.authenticate(email, temporary_password)
        except AuthProviderError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=exc.message,
            ) from exc

        if auth_result.challenge != "NEW_PASSWORD_REQUIRED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=Messages.PASSWORD_CHANGE_NOT_REQUIRED,
            )

        try:
            challenge_result = self._provider.respond_to_new_password_challenge(
                email=email,
                session=auth_result.session or "",
                new_password=new_password,
            )
        except AuthProviderError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=exc.message,
            ) from exc

        response = AuthResponse(
            message=Messages.NEW_PASSWORD_SET,
            email=email,
        )
        return response, challenge_result.tokens

    def forgot_password(self, email: str) -> AuthResponse:
        """Initiate forgot-password flow.

        Args:
            email: User's email address.

        Returns:
            AuthResponse confirming the code was sent.

        Raises:
            HTTPException: On failure (400).
        """
        try:
            self._provider.forgot_password(email)
        except AuthProviderError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=exc.message,
            ) from exc

        return AuthResponse(
            message=Messages.FORGOT_PASSWORD_CODE_SENT,
            email=email,
        )

    def reset_password(self, email: str, code: str, new_password: str) -> AuthResponse:
        """Complete password reset with verification code.

        Args:
            email: User's email address.
            code: Verification code.
            new_password: The new password.

        Returns:
            AuthResponse confirming the password was reset.

        Raises:
            HTTPException: On failure (400).
        """
        try:
            self._provider.confirm_forgot_password(email, code, new_password)
        except AuthProviderError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=exc.message,
            ) from exc

        return AuthResponse(
            message=Messages.PASSWORD_RESET_SUCCESS,
            email=email,
        )


# ---------------------------------------------------------------------------
# FastAPI dependency injection helpers
# ---------------------------------------------------------------------------


def get_auth_provider(
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthProvider:
    """Create an auth provider, guarding against missing Cognito config.

    Raises:
        HTTPException: 503 if Cognito is not configured.
    """
    if not settings.cognito_user_pool_id or not settings.cognito_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=Messages.COGNITO_NOT_CONFIGURED,
        )
    return CognitoAuthProvider(settings)


def get_auth_service(
    provider: Annotated[AuthProvider, Depends(get_auth_provider)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthService:
    """Create an AuthService with injected provider and settings."""
    return AuthService(provider=provider, settings=settings)
