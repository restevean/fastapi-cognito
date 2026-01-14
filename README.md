# FastAPI Cognito

A FastAPI boilerplate with AWS Cognito authentication integration, including a ready-to-use frontend and infrastructure as code.

## Features

- **FastAPI Backend**: Modern Python web framework with automatic OpenAPI docs
- **AWS Cognito Authentication**: Secure JWT-based authentication
- **Integrated Frontend**: Login page with password reset functionality
- **Infrastructure as Code**: Terraform configuration for Cognito User Pool
- **Mock Mode**: Development without AWS credentials
- **TDD Ready**: Test suite with authentication mocking

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    AWS Cloud                         │
│  ┌─────────────────────────────────────────────┐    │
│  │           Cognito User Pool                  │    │
│  │  - Admin-only user creation                  │    │
│  │  - Email + Password authentication           │    │
│  │  - Password reset enabled                    │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
                         ▲
                         │ boto3
                         │
┌─────────────────────────────────────────────────────┐
│                  FastAPI Application                 │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │   Frontend   │───▶│      Backend API         │   │
│  │  (Jinja2 +   │    │  - Auth via boto3        │   │
│  │  minimal JS) │    │  - JWT validation        │   │
│  └──────────────┘    │  - HttpOnly cookies      │   │
│                      └──────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [Terraform](https://www.terraform.io/) (optional, for AWS infrastructure)
- AWS Account with credentials configured (optional)

## Quick Start

### 1. Clone and Install Dependencies

```bash
git clone <repository-url>
cd fastapi_cognito
uv sync
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

For development without AWS:
```bash
# Leave COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID empty
# The app will run in mock mode
```

### 3. Run the Application

```bash
uv run uvicorn app.main:app --reload
```

Visit http://localhost:8000 for the login page or http://localhost:8000/docs for API documentation.

## AWS Cognito Setup (Optional)

### 1. Configure Terraform

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your preferences
```

### 2. Create Cognito Resources

```bash
terraform init
terraform plan
terraform apply
```

### 3. Update Environment Variables

```bash
# Copy outputs to .env
terraform output -raw user_pool_id      # → COGNITO_USER_POOL_ID
terraform output -raw app_client_id     # → COGNITO_CLIENT_ID
terraform output -raw aws_region        # → AWS_REGION
```

### 4. Create a User

Users can only be created by an administrator:

```bash
aws cognito-idp admin-create-user \
    --user-pool-id <your-user-pool-id> \
    --username user@example.com \
    --user-attributes Name=email,Value=user@example.com Name=email_verified,Value=true \
    --temporary-password TempPass123!

# Set a permanent password
aws cognito-idp admin-set-user-password \
    --user-pool-id <your-user-pool-id> \
    --username user@example.com \
    --password YourSecurePassword123! \
    --permanent
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | No | Login page (HTML) |
| `/health` | GET | No | Health check |
| `/users/me` | GET | Yes | Current user profile |
| `/auth/login` | POST | No | Login (returns HttpOnly cookie) |
| `/auth/logout` | POST | No | Logout (clears cookie) |
| `/auth/forgot-password` | POST | No | Request password reset code |
| `/auth/reset-password` | POST | No | Reset password with code |
| `/auth/new-password` | POST | No | Set new password (first login) |
| `/docs` | GET | No | OpenAPI documentation |

### Authentication

Protected endpoints require a Bearer token:

```bash
curl -H "Authorization: Bearer <your-jwt-token>" http://localhost:8000/users/me
```

## Project Structure

```
fastapi_cognito/
├── app/
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Environment configuration
│   ├── api/
│   │   ├── auth.py          # Auth endpoints (boto3)
│   │   ├── health.py        # Health check endpoint
│   │   └── users.py         # User endpoints
│   ├── core/
│   │   └── auth.py          # JWT validation logic
│   ├── static/              # Frontend assets (app.js, style.css)
│   └── templates/           # Jinja2 templates
├── terraform/               # AWS infrastructure
├── tests/                   # Test suite (test_auth, test_health, test_users)
├── .env.example             # Configuration template
└── pyproject.toml           # Project dependencies
```

## Development

### Running Tests

```bash
# All tests
uv run pytest

# With coverage
uv run pytest --cov=app --cov-report=term-missing

# Specific test
uv run pytest tests/test_health.py -v
```

### Linting and Formatting

```bash
# Check for issues
uv run ruff check .

# Auto-format
uv run ruff format .
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_NAME` | Application name (shown in UI) | FastAPI Cognito |
| `APP_DESCRIPTION` | Application description | - |
| `APP_VERSION` | API version | 0.1.0 |
| `COGNITO_USER_POOL_ID` | Cognito User Pool ID | (empty = mock mode) |
| `COGNITO_CLIENT_ID` | Cognito App Client ID | (empty = mock mode) |
| `AWS_REGION` | AWS region | eu-west-1 |

## Authentication Flow

Uses **OAuth 2.0 ROPC** (Resource Owner Password Credentials) grant:

1. **User Login**: Enters email/password in the frontend form
2. **Backend Auth**: FastAPI calls Cognito via boto3 (`USER_PASSWORD_AUTH`)
3. **Token Storage**: JWT token stored in HttpOnly cookie (secure)
4. **API Requests**: Cookie sent automatically with requests
5. **Backend Validation**: FastAPI validates token against Cognito JWKS

> **Note**: ROPC grant allows custom UI control. For third-party apps or social login (Google, Facebook), consider using Authorization Code + PKCE flow with Cognito Hosted UI.

## Mock Mode

When Cognito credentials are not configured, the application runs in mock mode:
- Authentication always succeeds
- Returns a mock user: `mock@example.com`
- Useful for local development and testing

## Security Notes

- **Admin-only user creation**: Regular users cannot self-register
- **JWT validation**: Tokens validated against Cognito's JWKS
- **HTTPS required**: In production, always use HTTPS
- **Token expiration**: Tokens expire after 1 hour (Cognito default)

## License

MIT
