import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel

from authly.api.admin_dependencies import require_admin_user
from authly.api.users_dependencies import get_current_user, get_user_service
from authly.api.validation_models import create_user_create_model, create_user_update_model
from authly.users.models import UserModel
from authly.users.service import UserService

logger = logging.getLogger(__name__)

# Create models with config-based validation
UserCreate = create_user_create_model()
UserUpdate = create_user_update_model()


class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    created_at: datetime
    updated_at: datetime
    last_login: datetime | None = None
    is_active: bool
    is_verified: bool
    is_admin: bool


# Router Definition
router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        500: {"description": "Internal Server Error"},
    },
)


@router.post(
    "/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account",
    description="Create a new user account with a unique username and email.",
)
async def create_user(
    user_create: UserCreate,
    user_service: UserService = Depends(get_user_service),
):
    """
    Create a new user account.
    """
    return await user_service.create_user(
        username=user_create.username,
        email=user_create.email,
        password=user_create.password,
        is_admin=False,
        is_verified=False,
        is_active=True,
    )


@router.get("/me", response_model=UserResponse, deprecated=True)
async def get_current_user_info(current_user: UserModel = Depends(get_current_user)):
    """
    Get information about the currently authenticated user.

    **DEPRECATED**: This endpoint is deprecated in favor of the OIDC-compliant
    GET /oidc/userinfo endpoint which provides standardized user claims based
    on granted scopes. Please migrate to /oidc/userinfo for better compatibility
    with OpenID Connect standards.

    This endpoint will be removed in a future version.
    """
    logger.warning(
        f"Deprecated /users/me endpoint accessed by user {current_user.id}. Client should migrate to /oidc/userinfo"
    )
    return current_user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    current_user: UserModel = Depends(require_admin_user),
    user_service: UserService = Depends(get_user_service),
):
    """Get user by ID - ADMIN ONLY"""
    return await user_service.get_user_by_id(user_id, admin_context=True)


@router.get("/", response_model=list[UserResponse])
async def get_users(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=100),
    current_user: UserModel = Depends(require_admin_user),
    user_service: UserService = Depends(get_user_service),
):
    """Get a list of users with pagination - ADMIN ONLY."""
    return await user_service.get_users_paginated(skip=skip, limit=limit, admin_context=True)


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    current_user: UserModel = Depends(require_admin_user),
    user_service: UserService = Depends(get_user_service),
):
    """
    Update user information - ADMIN ONLY.

    This endpoint is restricted to administrators only. Regular users should
    use the OIDC-compliant PUT /oidc/userinfo endpoint to update their profile.
    """
    update_data = user_update.model_dump(exclude_unset=True)
    return await user_service.update_user(
        user_id=user_id,
        update_data=update_data,
        requesting_user=current_user,
        admin_override=True,
        admin_context=True,
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    current_user: UserModel = Depends(require_admin_user),
    user_service: UserService = Depends(get_user_service),
):
    """Delete user account - ADMIN ONLY."""
    await user_service.delete_user(user_id=user_id, requesting_user=current_user, admin_override=True)


@router.put("/{user_id}/verify", response_model=UserResponse)
async def verify_user(
    user_id: UUID,
    current_user: UserModel = Depends(require_admin_user),
    user_service: UserService = Depends(get_user_service),
):
    """
    Verify a user's account - ADMIN ONLY.
    """
    return await user_service.verify_user(user_id=user_id, requesting_user=current_user)
