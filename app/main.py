"""FastAPI application entry point."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import auth, health, users
from app.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description=settings.app_description,
    version=settings.app_version,
)

# API routers
app.include_router(health.router)
app.include_router(users.router)
app.include_router(auth.router)

# Static files (frontend assets)
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Templates
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=templates_dir)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def root(request: Request) -> HTMLResponse:
    """Render the login page."""
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "app_name": settings.app_name,
            "app_description": settings.app_description,
        },
    )
