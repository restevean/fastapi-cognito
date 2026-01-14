"""Application configuration using pydantic-settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application info
    app_name: str = "FastAPI Cognito"
    app_description: str = "Autenticación segura con AWS Cognito"
    app_version: str = "0.1.0"

    # Cognito configuration
    cognito_user_pool_id: str = ""
    cognito_client_id: str = ""
    aws_region: str = "eu-west-1"

    @property
    def cognito_issuer(self) -> str:
        """Get the Cognito token issuer URL."""
        return f"https://cognito-idp.{self.aws_region}.amazonaws.com/{self.cognito_user_pool_id}"

    @property
    def cognito_jwks_url(self) -> str:
        """Get the JWKS URL for JWT validation."""
        return f"{self.cognito_issuer}/.well-known/jwks.json"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
