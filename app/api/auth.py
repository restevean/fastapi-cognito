"""Authentication endpoints using AWS Cognito with boto3."""

from typing import Annotated

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr

from app.config import Settings, get_settings

router = APIRouter(prefix="/auth", tags=["auth"])


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
    """New password request for first login."""

    email: EmailStr
    temporary_password: str
    new_password: str


class AuthResponse(BaseModel):
    """Authentication response."""

    message: str
    email: str | None = None
    requires_new_password: bool = False


def _get_cognito_client(settings: Settings) -> boto3.client:
    """Get boto3 Cognito client."""
    return boto3.client("cognito-idp", region_name=settings.aws_region)


def _translate_cognito_error(error_code: str) -> str:
    """Translate Cognito error codes to Spanish."""
    errors = {
        "UserNotFoundException": "Usuario no encontrado",
        "NotAuthorizedException": "Usuario o contraseña incorrectos",
        "UserNotConfirmedException": "Usuario no confirmado",
        "PasswordResetRequiredException": "Debes restablecer tu contraseña",
        "CodeMismatchException": "Código de verificación incorrecto",
        "ExpiredCodeException": "El código ha expirado",
        "InvalidPasswordException": "La contraseña no cumple los requisitos",
        "LimitExceededException": "Demasiados intentos. Intenta más tarde",
        "InvalidParameterException": "Parámetro inválido",
    }
    return errors.get(error_code, f"Error: {error_code}")


@router.post("/login", response_model=AuthResponse)
def login(
    request: LoginRequest,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthResponse:
    """
    Authenticate user with email and password.

    Returns JWT token in HttpOnly cookie.
    """
    if not settings.cognito_user_pool_id or not settings.cognito_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cognito no está configurado",
        )

    client = _get_cognito_client(settings)

    try:
        auth_response = client.initiate_auth(
            ClientId=settings.cognito_client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": request.email,
                "PASSWORD": request.password,
            },
        )

        # Check if new password is required
        if auth_response.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
            return AuthResponse(
                message="Se requiere establecer una nueva contraseña",
                email=request.email,
                requires_new_password=True,
            )

        # Get tokens from successful auth
        tokens = auth_response["AuthenticationResult"]
        id_token = tokens["IdToken"]

        # Set token in HttpOnly cookie
        response.set_cookie(
            key="access_token",
            value=id_token,
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax",
            max_age=3600,  # 1 hour
        )

        return AuthResponse(message="Login exitoso", email=request.email)

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_translate_cognito_error(error_code),
        ) from e


@router.post("/new-password", response_model=AuthResponse)
def set_new_password(
    request: NewPasswordRequest,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthResponse:
    """
    Set new password for first login after admin creates user.

    Returns JWT token in HttpOnly cookie.
    """
    if not settings.cognito_user_pool_id or not settings.cognito_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cognito no está configurado",
        )

    client = _get_cognito_client(settings)

    try:
        # First, initiate auth to get the session
        auth_response = client.initiate_auth(
            ClientId=settings.cognito_client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": request.email,
                "PASSWORD": request.temporary_password,
            },
        )

        if auth_response.get("ChallengeName") != "NEW_PASSWORD_REQUIRED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No se requiere cambio de contraseña",
            )

        # Respond to the challenge
        challenge_response = client.respond_to_auth_challenge(
            ClientId=settings.cognito_client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=auth_response["Session"],
            ChallengeResponses={
                "USERNAME": request.email,
                "NEW_PASSWORD": request.new_password,
            },
        )

        # Get tokens from successful challenge response
        tokens = challenge_response["AuthenticationResult"]
        id_token = tokens["IdToken"]

        # Set token in HttpOnly cookie
        response.set_cookie(
            key="access_token",
            value=id_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=3600,
        )

        return AuthResponse(message="Contraseña establecida correctamente", email=request.email)

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_translate_cognito_error(error_code),
        ) from e


@router.post("/forgot-password", response_model=AuthResponse)
def forgot_password(
    request: ForgotPasswordRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthResponse:
    """
    Initiate forgot password flow.

    Sends verification code to user's email.
    """
    if not settings.cognito_user_pool_id or not settings.cognito_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cognito no está configurado",
        )

    client = _get_cognito_client(settings)

    try:
        client.forgot_password(
            ClientId=settings.cognito_client_id,
            Username=request.email,
        )

        return AuthResponse(
            message="Código de verificación enviado al email",
            email=request.email,
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_translate_cognito_error(error_code),
        ) from e


@router.post("/reset-password", response_model=AuthResponse)
def reset_password(
    request: ResetPasswordRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthResponse:
    """
    Complete password reset with verification code.
    """
    if not settings.cognito_user_pool_id or not settings.cognito_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cognito no está configurado",
        )

    client = _get_cognito_client(settings)

    try:
        client.confirm_forgot_password(
            ClientId=settings.cognito_client_id,
            Username=request.email,
            ConfirmationCode=request.code,
            Password=request.new_password,
        )

        return AuthResponse(
            message="Contraseña restablecida correctamente",
            email=request.email,
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_translate_cognito_error(error_code),
        ) from e


@router.post("/logout", response_model=AuthResponse)
def logout(response: Response) -> AuthResponse:
    """
    Logout user by clearing the access token cookie.
    """
    response.delete_cookie(key="access_token")
    return AuthResponse(message="Sesión cerrada")
