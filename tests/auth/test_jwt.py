"""Tests for JWT validation — app/auth/jwt.py.

Uses RSA key generation and python-jose to create real (but test) JWTs.
Patches httpx.get to return mock JWKS.
"""

from __future__ import annotations

import time
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

from app.auth import jwt as jwt_module
from app.auth.jwt import _get_signing_key, _jwks_cache
from app.main import app
from app.shared.config import Settings, get_settings

# ---------------------------------------------------------------------------
# RSA key fixtures for signing test JWTs
# ---------------------------------------------------------------------------

_TEST_KID = "test-key-id"


def _generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, dict[str, Any]]:
    """Generate an RSA private key and its JWK representation.

    Returns:
        Tuple of (private_key, jwk_dict).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Export public key numbers to build JWK
    pub = private_key.public_key()
    pub_numbers = pub.public_numbers()

    def _int_to_base64url(n: int, length: int) -> str:
        """Convert an integer to a base64url-encoded string."""
        import base64

        data = n.to_bytes(length, byteorder="big")
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    jwk = {
        "kty": "RSA",
        "kid": _TEST_KID,
        "use": "sig",
        "alg": "RS256",
        "n": _int_to_base64url(pub_numbers.n, 256),
        "e": _int_to_base64url(pub_numbers.e, 3),
    }

    return private_key, jwk


_PRIVATE_KEY, _TEST_JWK = _generate_rsa_keypair()

# PEM for python-jose to sign tokens
_PRIVATE_KEY_PEM = _PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

# Test Cognito settings
_TEST_POOL_ID = "eu-west-1_TestPool"
_TEST_CLIENT_ID = "test-client-id"
_TEST_REGION = "eu-west-1"
_TEST_ISSUER = f"https://cognito-idp.{_TEST_REGION}.amazonaws.com/{_TEST_POOL_ID}"


def _make_test_settings(
    pool_id: str = _TEST_POOL_ID,
    client_id: str = _TEST_CLIENT_ID,
) -> Settings:
    """Create test Settings with given Cognito config."""
    return Settings(
        cognito_user_pool_id=pool_id,
        cognito_client_id=client_id,
        aws_region=_TEST_REGION,
        cookie_secure=False,
    )


def _create_token(
    claims: dict[str, Any] | None = None,
    kid: str = _TEST_KID,
    expired: bool = False,
) -> str:
    """Create a signed JWT for testing.

    Args:
        claims: Custom claims to include.
        kid: Key ID to put in the JWT header.
        expired: If True, set exp in the past.

    Returns:
        Signed JWT string.
    """
    now = int(time.time())
    default_claims: dict[str, Any] = {
        "sub": "test-user-id",
        "email": "test@example.com",
        "token_use": "id",
        "iss": _TEST_ISSUER,
        "aud": _TEST_CLIENT_ID,
        "iat": now - 60,
        "exp": now - 300 if expired else now + 3600,
    }
    if claims:
        default_claims.update(claims)

    return jose_jwt.encode(
        default_claims,
        _PRIVATE_KEY_PEM,
        algorithm="RS256",
        headers={"kid": kid},
    )


def _mock_jwks_response() -> MagicMock:
    """Create a mock httpx response returning the test JWKS."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"keys": [_TEST_JWK]}
    mock_response.raise_for_status = MagicMock()
    return mock_response


@pytest.fixture(autouse=True)
def _clear_jwks_cache() -> Generator[None, None, None]:
    """Clear the JWKS cache before each test."""
    _jwks_cache["keys"] = []
    _jwks_cache["fetched_at"] = 0
    yield
    _jwks_cache["keys"] = []
    _jwks_cache["fetched_at"] = 0


# ---------------------------------------------------------------------------
# Test: mock mode
# ---------------------------------------------------------------------------


class TestMockMode:
    """JWT validation in mock mode (Cognito not configured)."""

    def test_mock_mode_returns_mock_user(self) -> None:
        """When cognito_user_pool_id is empty, returns mock user without real JWT."""
        mock_settings = _make_test_settings(pool_id="", client_id="")

        app.dependency_overrides[get_settings] = lambda: mock_settings
        try:
            client = TestClient(app)
            response = client.get(
                "/users/me",
                headers={"Authorization": "Bearer any-token"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["sub"] == "mock-user-id"
            assert data["email"] == "mock@example.com"
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Test: token extraction
# ---------------------------------------------------------------------------


class TestTokenExtraction:
    """Tests for how tokens are extracted from requests."""

    def test_no_token_raises_401(self) -> None:
        """Request with no header and no cookie returns 401."""
        settings = _make_test_settings()
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            client = TestClient(app)
            response = client.get("/users/me")

            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    @patch("app.auth.jwt.httpx.get")
    def test_token_from_cookie(self, mock_httpx_get: MagicMock) -> None:
        """Token can be read from access_token cookie."""
        mock_httpx_get.return_value = _mock_jwks_response()
        settings = _make_test_settings()
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            token = _create_token()
            client = TestClient(app, cookies={"access_token": token})
            response = client.get("/users/me")

            assert response.status_code == 200
            data = response.json()
            assert data["email"] == "test@example.com"
        finally:
            app.dependency_overrides.clear()

    @patch("app.auth.jwt.httpx.get")
    def test_token_from_bearer_header(self, mock_httpx_get: MagicMock) -> None:
        """Token can be read from Authorization: Bearer header."""
        mock_httpx_get.return_value = _mock_jwks_response()
        settings = _make_test_settings()
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            token = _create_token()
            client = TestClient(app)
            response = client.get(
                "/users/me",
                headers={"Authorization": f"Bearer {token}"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["email"] == "test@example.com"
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Test: JWKS caching
# ---------------------------------------------------------------------------


class TestJWKSCache:
    """Tests for JWKS fetch and caching behaviour."""

    @patch("app.auth.jwt.httpx.get")
    def test_jwks_cache_hit(self, mock_httpx_get: MagicMock) -> None:
        """Second call within TTL uses cached keys (no extra HTTP call)."""
        mock_httpx_get.return_value = _mock_jwks_response()
        settings = _make_test_settings()

        from app.auth.jwt import _get_jwks

        # First call — fetches
        keys1 = _get_jwks(settings)
        assert len(keys1) == 1
        assert mock_httpx_get.call_count == 1

        # Second call — should use cache
        keys2 = _get_jwks(settings)
        assert keys2 == keys1
        assert mock_httpx_get.call_count == 1  # Still 1 — no extra fetch

    @patch("app.auth.jwt.httpx.get")
    def test_jwks_cache_expired(self, mock_httpx_get: MagicMock) -> None:
        """After TTL expires, keys are re-fetched."""
        mock_httpx_get.return_value = _mock_jwks_response()
        settings = _make_test_settings()

        from app.auth.jwt import _get_jwks

        # First call — fetches
        _get_jwks(settings)
        assert mock_httpx_get.call_count == 1

        # Simulate cache expiry
        _jwks_cache["fetched_at"] = time.time() - jwt_module.JWKS_CACHE_TTL - 1

        # Second call — should re-fetch
        _get_jwks(settings)
        assert mock_httpx_get.call_count == 2


# ---------------------------------------------------------------------------
# Test: signing key lookup
# ---------------------------------------------------------------------------


class TestSigningKey:
    """Tests for _get_signing_key."""

    def test_invalid_token_header_returns_none(self) -> None:
        """Malformed JWT returns None (no signing key found)."""
        result = _get_signing_key("not.a.valid.jwt", [_TEST_JWK])
        assert result is None

    def test_signing_key_not_found_raises_401(self) -> None:
        """Token with unknown kid results in 401."""
        settings = _make_test_settings()
        token = _create_token(kid="unknown-kid")

        app.dependency_overrides[get_settings] = lambda: settings
        try:
            # Pre-load cache with our test JWK (kid = _TEST_KID)
            _jwks_cache["keys"] = [_TEST_JWK]
            _jwks_cache["fetched_at"] = time.time()

            client = TestClient(app)
            response = client.get(
                "/users/me",
                headers={"Authorization": f"Bearer {token}"},
            )

            assert response.status_code == 401
            assert "Invalid token signature" in response.json()["detail"]
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Test: token validation errors
# ---------------------------------------------------------------------------


class TestTokenValidation:
    """Tests for expired/invalid tokens."""

    def test_expired_token_raises_401(self) -> None:
        """Expired JWT returns 401."""
        settings = _make_test_settings()
        token = _create_token(expired=True)

        app.dependency_overrides[get_settings] = lambda: settings
        try:
            _jwks_cache["keys"] = [_TEST_JWK]
            _jwks_cache["fetched_at"] = time.time()

            client = TestClient(app)
            response = client.get(
                "/users/me",
                headers={"Authorization": f"Bearer {token}"},
            )

            assert response.status_code == 401
            assert "expired" in response.json()["detail"].lower()
        finally:
            app.dependency_overrides.clear()

    def test_invalid_signature_raises_401(self) -> None:
        """Token signed with different key returns 401."""
        # Generate a DIFFERENT key pair
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        now = int(time.time())
        token = jose_jwt.encode(
            {
                "sub": "test-user-id",
                "email": "test@example.com",
                "token_use": "id",
                "iss": _TEST_ISSUER,
                "aud": _TEST_CLIENT_ID,
                "iat": now - 60,
                "exp": now + 3600,
            },
            other_pem,
            algorithm="RS256",
            headers={"kid": _TEST_KID},
        )

        settings = _make_test_settings()
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            _jwks_cache["keys"] = [_TEST_JWK]
            _jwks_cache["fetched_at"] = time.time()

            client = TestClient(app)
            response = client.get(
                "/users/me",
                headers={"Authorization": f"Bearer {token}"},
            )

            assert response.status_code == 401
            assert "Invalid token" in response.json()["detail"]
        finally:
            app.dependency_overrides.clear()
