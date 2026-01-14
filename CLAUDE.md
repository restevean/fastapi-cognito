# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**fastapi-cognito** - A FastAPI boilerplate with AWS Cognito authentication, including frontend integration and infrastructure as code.

- **Python**: 3.12+
- **Package Manager**: uv
- **Infrastructure**: Terraform (AWS Cognito User Pool)
- **Frontend**: Jinja2 templates + minimal JavaScript

## Development Commands

```bash
# Install dependencies
uv sync

# Run the application
uv run uvicorn app.main:app --reload

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=app --cov-report=term-missing

# Run a single test file
uv run pytest tests/test_health.py

# Run a single test function
uv run pytest tests/test_health.py::test_health_check_returns_healthy

# Linting
uv run ruff check .

# Format code
uv run ruff format .
```

## Project Structure

```
fastapi_cognito/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI entry point, Jinja2 templates
│   ├── config.py            # Settings from environment variables
│   ├── api/
│   │   ├── __init__.py
│   │   ├── auth.py          # Auth endpoints: login, logout, password reset
│   │   ├── health.py        # Public endpoint: GET /health
│   │   └── users.py         # Private endpoint: GET /users/me
│   ├── core/
│   │   ├── __init__.py
│   │   └── auth.py          # JWT validation with Cognito JWKS
│   ├── static/
│   │   ├── app.js           # Frontend logic (fetch calls to /auth endpoints)
│   │   └── style.css        # Styles
│   └── templates/
│       └── index.html       # Login page (Jinja2)
├── terraform/
│   ├── main.tf              # AWS provider
│   ├── variables.tf         # Configuration variables
│   ├── cognito.tf           # User Pool + App Client
│   ├── outputs.tf           # IDs for .env configuration
│   └── terraform.tfvars.example
├── tests/
│   ├── __init__.py
│   ├── conftest.py          # Pytest fixtures with auth mock
│   ├── test_auth.py         # Auth endpoint tests
│   ├── test_health.py       # Health endpoint tests
│   └── test_users.py        # User endpoint tests
├── .env                     # Local configuration (not in git)
├── .env.example             # Example configuration
└── pyproject.toml
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | No | Login page (HTML) |
| `/health` | GET | No | Health check |
| `/users/me` | GET | Yes | Current user profile |
| `/auth/login` | POST | No | Login (returns cookie) |
| `/auth/logout` | POST | No | Logout (clears cookie) |
| `/auth/forgot-password` | POST | No | Request password reset |
| `/auth/reset-password` | POST | No | Reset password with code |
| `/auth/new-password` | POST | No | Set new password (first login) |

## Configuration

Environment variables (`.env`):

```bash
# Application
APP_NAME=FastAPI Cognito
APP_DESCRIPTION=Secure authentication with AWS Cognito
APP_VERSION=0.1.0

# Cognito (from Terraform outputs)
COGNITO_USER_POOL_ID=eu-west-1_XXXXXXX
COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_REGION=eu-west-1
```

## Authentication Flow

Uses OAuth 2.0 ROPC (Resource Owner Password Credentials) grant via boto3:

1. **Frontend**: User enters credentials in login form
2. **Backend**: `POST /auth/login` calls Cognito via boto3 (USER_PASSWORD_AUTH)
3. **JWT Token**: Cognito returns ID token, stored in HttpOnly cookie
4. **API Calls**: Cookie sent automatically with requests
5. **Backend Validation**: `get_current_user` dependency validates JWT against Cognito JWKS

Note: ROPC allows custom UI but credentials pass through the backend. For third-party apps or higher security, consider Authorization Code + PKCE flow with Cognito Hosted UI.

## Key Implementation Details

### JWT Validation (app/core/auth.py)
- Fetches and caches JWKS from Cognito (1 hour TTL)
- Validates token signature, audience, issuer, and expiration
- Falls back to mock mode if Cognito not configured (development only)

### Mock Mode
When `COGNITO_USER_POOL_ID` or `COGNITO_CLIENT_ID` are empty, authentication returns a mock user. This allows running tests and local development without AWS.

### Cognito Configuration
- **Admin-only user creation**: `allow_admin_create_user_only = true`
- **Email as username**: Users authenticate with email
- **Password reset**: Enabled (users receive code via email)

## Testing

Tests use mock authentication via `conftest.py`:

```python
# Override get_current_user to skip real JWT validation
app.dependency_overrides[get_current_user] = lambda: {
    "sub": "test-user-id",
    "email": "test@example.com",
    "token_use": "id",
}
```

## Terraform Workflow

```bash
cd terraform

# Initialize
terraform init

# Preview changes
terraform plan

# Apply (creates Cognito resources)
terraform apply

# Get outputs for .env
terraform output
```

## Dependencies

Main dependencies:
- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `pydantic-settings` - Configuration management
- `python-jose[cryptography]` - JWT validation
- `httpx` - HTTP client for JWKS
- `jinja2` - Template engine
- `boto3` - AWS SDK for Cognito authentication
- `email-validator` - Email validation for Pydantic

Dev dependencies:
- `pytest` - Testing framework
- `pytest-cov` - Coverage reports
- `ruff` - Linter and formatter
