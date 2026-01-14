"""Authentication module with AWS Cognito JWT validation."""

import time
from typing import Annotated

import httpx
from fastapi import Cookie, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError

from app.config import Settings, get_settings

security = HTTPBearer(auto_error=False)

# Cache for JWKS to avoid fetching on every request
_jwks_cache: dict = {"keys": [], "fetched_at": 0}
JWKS_CACHE_TTL = 3600  # 1 hour


def _get_jwks(settings: Settings) -> list[dict]:
    """
    Fetch and cache JWKS from Cognito.

    Args:
        settings: Application settings with Cognito configuration.

    Returns:
        List of JWK keys.

    Raises:
        HTTPException: If JWKS cannot be fetched.
    """
    current_time = time.time()

    # Return cached keys if still valid
    if _jwks_cache["keys"] and (current_time - _jwks_cache["fetched_at"]) < JWKS_CACHE_TTL:
        return _jwks_cache["keys"]

    # Fetch fresh JWKS
    try:
        response = httpx.get(settings.cognito_jwks_url, timeout=10.0)
        response.raise_for_status()
        jwks = response.json()
        _jwks_cache["keys"] = jwks.get("keys", [])
        _jwks_cache["fetched_at"] = current_time
        return _jwks_cache["keys"]
    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Could not fetch JWKS: {e}",
        ) from e


def _get_signing_key(token: str, jwks: list[dict]) -> dict | None:
    """
    Find the signing key for a token from JWKS.

    Args:
        token: The JWT token.
        jwks: List of JWK keys.

    Returns:
        The matching JWK or None if not found.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError:
        return None

    kid = unverified_header.get("kid")
    for key in jwks:
        if key.get("kid") == kid:
            return key
    return None


def _decode_and_validate_token(token: str, settings: Settings) -> dict:
    """
    Decode and validate a Cognito JWT token.

    Args:
        token: The JWT token to validate.
        settings: Application settings with Cognito configuration.

    Returns:
        The decoded token claims.

    Raises:
        HTTPException: If token validation fails.
    """
    # Check if Cognito is configured
    if not settings.cognito_user_pool_id or not settings.cognito_client_id:
        # Fallback to mock mode for development without Cognito
        return {
            "sub": "mock-user-id",
            "email": "mock@example.com",
            "token_use": "access",
        }

    jwks = _get_jwks(settings)
    signing_key = _get_signing_key(token, jwks)

    if not signing_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature",
        )

    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=settings.cognito_client_id,
            issuer=settings.cognito_issuer,
            options={
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
            },
        )
        return claims
    except ExpiredSignatureError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        ) from e
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
        ) from e


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    settings: Annotated[Settings, Depends(get_settings)],
    access_token: Annotated[str | None, Cookie()] = None,
) -> dict:
    """
    Validate the bearer token and return the current user.

    Accepts token from either Authorization header or HttpOnly cookie.

    Args:
        credentials: The HTTP Authorization credentials from the request header.
        settings: Application settings.
        access_token: Token from HttpOnly cookie (set by /auth/login).

    Returns:
        A dict containing the user claims from the JWT.

    Raises:
        HTTPException: If authentication fails (401 Unauthorized).
    """
    # Get token from header or cookie
    token = None
    if credentials:
        token = credentials.credentials
    elif access_token:
        token = access_token

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se proporcionó token de autenticación",
        )

    claims = _decode_and_validate_token(token, settings)

    return {
        "sub": claims.get("sub"),
        "email": claims.get("email"),
        "token_use": claims.get("token_use"),
    }
