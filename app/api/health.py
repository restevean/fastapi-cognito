"""Health check endpoint."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check() -> dict:
    """
    Health check endpoint.

    Returns:
        Service status information.
    """
    return {"status": "healthy"}
