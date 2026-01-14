"""Pytest configuration and fixtures."""

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.main import app


def get_test_settings() -> Settings:
    """Get settings for testing (no Cognito configured = mock mode)."""
    return Settings(
        cognito_user_pool_id="",
        cognito_client_id="",
        aws_region="eu-west-1",
    )


@pytest.fixture
def client() -> TestClient:
    """Create a test client with mocked settings."""
    app.dependency_overrides[get_settings] = get_test_settings
    yield TestClient(app)
    app.dependency_overrides.clear()
