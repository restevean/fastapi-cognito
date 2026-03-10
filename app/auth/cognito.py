"""Cognito adapter — implements AuthProvider using boto3."""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from app.auth.provider import AuthProviderError, AuthResult
from app.auth.schemas import translate_cognito_error
from app.shared.config import Settings


class CognitoAuthProvider:
    """AWS Cognito implementation of the AuthProvider protocol.

    All boto3 interactions are encapsulated here. ``ClientError`` exceptions
    are caught and re-raised as ``AuthProviderError`` with a translated
    message and the original Cognito error code.

    Args:
        settings: Application settings (needs ``cognito_client_id`` and ``aws_region``).
    """

    def __init__(self, settings: Settings) -> None:
        self._client_id = settings.cognito_client_id
        self._client = boto3.client("cognito-idp", region_name=settings.aws_region)

    # ------------------------------------------------------------------
    # AuthProvider protocol methods
    # ------------------------------------------------------------------

    def authenticate(self, email: str, password: str) -> AuthResult:
        """Authenticate a user with email and password via Cognito.

        Args:
            email: User's email address.
            password: User's password.

        Returns:
            AuthResult with tokens or challenge information.

        Raises:
            AuthProviderError: On Cognito ``ClientError``.
        """
        try:
            response = self._client.initiate_auth(
                ClientId=self._client_id,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": email,
                    "PASSWORD": password,
                },
            )

            if response.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
                return AuthResult(
                    tokens=None,
                    challenge="NEW_PASSWORD_REQUIRED",
                    session=response.get("Session"),
                    email=email,
                )

            tokens = response["AuthenticationResult"]
            return AuthResult(
                tokens={
                    "IdToken": tokens["IdToken"],
                    "AccessToken": tokens.get("AccessToken", ""),
                    "RefreshToken": tokens.get("RefreshToken", ""),
                },
                challenge=None,
                session=None,
                email=email,
            )
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            raise AuthProviderError(
                message=translate_cognito_error(error_code),
                error_code=error_code,
            ) from exc

    def respond_to_new_password_challenge(
        self, email: str, session: str, new_password: str
    ) -> AuthResult:
        """Respond to a NEW_PASSWORD_REQUIRED challenge.

        Args:
            email: User's email address.
            session: Session token from the initial authentication challenge.
            new_password: The new password to set.

        Returns:
            AuthResult with tokens on success.

        Raises:
            AuthProviderError: On Cognito ``ClientError``.
        """
        try:
            response = self._client.respond_to_auth_challenge(
                ClientId=self._client_id,
                ChallengeName="NEW_PASSWORD_REQUIRED",
                Session=session,
                ChallengeResponses={
                    "USERNAME": email,
                    "NEW_PASSWORD": new_password,
                },
            )

            tokens = response["AuthenticationResult"]
            return AuthResult(
                tokens={
                    "IdToken": tokens["IdToken"],
                    "AccessToken": tokens.get("AccessToken", ""),
                    "RefreshToken": tokens.get("RefreshToken", ""),
                },
                challenge=None,
                session=None,
                email=email,
            )
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            raise AuthProviderError(
                message=translate_cognito_error(error_code),
                error_code=error_code,
            ) from exc

    def forgot_password(self, email: str) -> None:
        """Initiate forgot-password flow via Cognito.

        Args:
            email: User's email address.

        Raises:
            AuthProviderError: On Cognito ``ClientError``.
        """
        try:
            self._client.forgot_password(
                ClientId=self._client_id,
                Username=email,
            )
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            raise AuthProviderError(
                message=translate_cognito_error(error_code),
                error_code=error_code,
            ) from exc

    def confirm_forgot_password(self, email: str, code: str, new_password: str) -> None:
        """Complete password reset with a verification code.

        Args:
            email: User's email address.
            code: Verification code received by the user.
            new_password: The new password to set.

        Raises:
            AuthProviderError: On Cognito ``ClientError``.
        """
        try:
            self._client.confirm_forgot_password(
                ClientId=self._client_id,
                Username=email,
                ConfirmationCode=code,
                Password=new_password,
            )
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            raise AuthProviderError(
                message=translate_cognito_error(error_code),
                error_code=error_code,
            ) from exc
