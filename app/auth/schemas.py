"""Auth request/response schemas and message constants."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr

# ---------------------------------------------------------------------------
# Message constants (English) — replace Spanish strings during Phase 2
# ---------------------------------------------------------------------------


class Messages:
    """Centralised English message strings for auth responses."""

    LOGIN_SUCCESS = "Login successful"
    LOGOUT_SUCCESS = "Logged out"
    NEW_PASSWORD_REQUIRED = "New password required"
    NEW_PASSWORD_SET = "Password set successfully"
    PASSWORD_CHANGE_NOT_REQUIRED = "Password change not required"
    FORGOT_PASSWORD_CODE_SENT = "Verification code sent to email"
    PASSWORD_RESET_SUCCESS = "Password reset successfully"
    COGNITO_NOT_CONFIGURED = "Authentication service unavailable"
    NO_TOKEN_PROVIDED = "Authentication token not provided"


# ---------------------------------------------------------------------------
# Cognito error code translations (English)
# ---------------------------------------------------------------------------

COGNITO_ERROR_MESSAGES: dict[str, str] = {
    "UserNotFoundException": "User not found",
    "NotAuthorizedException": "Invalid email or password",
    "UserNotConfirmedException": "User not confirmed",
    "PasswordResetRequiredException": "Password reset required",
    "CodeMismatchException": "Invalid verification code",
    "ExpiredCodeException": "Verification code has expired",
    "InvalidPasswordException": "Password does not meet requirements",
    "LimitExceededException": "Too many attempts. Try again later",
    "InvalidParameterException": "Invalid parameter",
}


def translate_cognito_error(error_code: str) -> str:
    """Translate a Cognito error code to an English message.

    Args:
        error_code: The AWS Cognito error code string.

    Returns:
        Human-readable error message in English.
    """
    return COGNITO_ERROR_MESSAGES.get(error_code, f"Error: {error_code}")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """Login request body."""

    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    """Forgot password request body."""

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Reset password request body."""

    email: EmailStr
    code: str
    new_password: str


class NewPasswordRequest(BaseModel):
    """New password request for first login after admin-created account."""

    email: EmailStr
    temporary_password: str
    new_password: str


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


class AuthResponse(BaseModel):
    """Authentication response returned by all auth endpoints."""

    message: str
    email: str | None = None
    requires_new_password: bool = False
