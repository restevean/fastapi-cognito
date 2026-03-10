"""Auth router — thin HTTP endpoints that delegate to AuthService."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response

from app.auth.schemas import (
    AuthResponse,
    ForgotPasswordRequest,
    LoginRequest,
    Messages,
    NewPasswordRequest,
    ResetPasswordRequest,
)
from app.auth.service import AuthService, get_auth_service
from app.shared.config import Settings, get_settings

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=AuthResponse)
def login(
    request: LoginRequest,
    response: Response,
    service: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthResponse:
    """Authenticate user with email and password.

    Returns JWT token in HttpOnly cookie on success.
    """
    auth_response, tokens = service.login_with_tokens(request.email, request.password)

    if tokens:
        id_token = tokens.get("IdToken", "")
        response.set_cookie(
            key="access_token",
            value=id_token,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="lax",
            max_age=3600,
        )

    return auth_response


@router.post("/new-password", response_model=AuthResponse)
def set_new_password(
    request: NewPasswordRequest,
    response: Response,
    service: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthResponse:
    """Set new password for first login after admin-created account.

    Returns JWT token in HttpOnly cookie on success.
    """
    auth_response, tokens = service.set_new_password(
        email=request.email,
        temporary_password=request.temporary_password,
        new_password=request.new_password,
    )

    if tokens:
        id_token = tokens.get("IdToken", "")
        response.set_cookie(
            key="access_token",
            value=id_token,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="lax",
            max_age=3600,
        )

    return auth_response


@router.post("/forgot-password", response_model=AuthResponse)
def forgot_password(
    request: ForgotPasswordRequest,
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> AuthResponse:
    """Initiate forgot-password flow. Sends verification code to email."""
    return service.forgot_password(request.email)


@router.post("/reset-password", response_model=AuthResponse)
def reset_password(
    request: ResetPasswordRequest,
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> AuthResponse:
    """Complete password reset with verification code."""
    return service.reset_password(
        email=request.email,
        code=request.code,
        new_password=request.new_password,
    )


@router.post("/logout", response_model=AuthResponse)
def logout(response: Response) -> AuthResponse:
    """Logout user by clearing the access token cookie."""
    response.delete_cookie(key="access_token")
    return AuthResponse(message=Messages.LOGOUT_SUCCESS)
