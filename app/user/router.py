"""User router — user profile endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.auth.jwt import get_current_user

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me")
def get_current_user_profile(
    current_user: Annotated[dict, Depends(get_current_user)],
) -> dict:
    """Get the current authenticated user's profile.

    Args:
        current_user: The authenticated user from the auth dependency.

    Returns:
        The current user's profile information.
    """
    return current_user
