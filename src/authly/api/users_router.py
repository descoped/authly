import logging
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, constr

from authly.api.users_dependencies import get_current_user, get_current_user_no_update, get_user_service
from authly.users.models import UserModel
from authly.users.service import UserService

logger = logging.getLogger(__name__)


# Import dynamic validation models
from authly.api.validation_models import create_user_create_model, create_user_update_model

# Create models with config-based validation
UserCreate = create_user_create_model()
UserUpdate = create_user_update_model()


class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
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


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: UserModel = Depends(get_current_user)):
    """
    Get information about the currently authenticated user.
    """
    return current_user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: UUID, user_service: UserService = Depends(get_user_service)):
    """Get user by ID - no auth required"""
    return await user_service.get_user_by_id(user_id)


@router.get("/", response_model=List[UserResponse])
async def get_users(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=100),
    user_service: UserService = Depends(get_user_service),
):
    """Get a list of users with pagination."""
    return await user_service.get_users_paginated(skip=skip, limit=limit)


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    current_user: UserModel = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    """
    Update user information.
    """
    update_data = user_update.model_dump(exclude_unset=True)
    return await user_service.update_user(
        user_id=user_id,
        update_data=update_data,
        requesting_user=current_user,
        admin_override=False,
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    current_user: UserModel = Depends(get_current_user_no_update),
    user_service: UserService = Depends(get_user_service),
):
    """Delete user account."""
    await user_service.delete_user(user_id=user_id, requesting_user=current_user)


@router.put("/{user_id}/verify", response_model=UserResponse)
async def verify_user(
    user_id: UUID,
    current_user: UserModel = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    """
    Verify a user's account.
    """
    return await user_service.verify_user(user_id=user_id, requesting_user=current_user)
