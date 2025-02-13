import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from psycopg_toolkit.exceptions import OperationError, RecordNotFoundError
from pydantic import BaseModel, constr

from authly.api.users_dependencies import get_current_user, get_current_user_no_update, get_user_repository
from authly.auth.core import get_password_hash
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


# Request/Response Models
class UserCreate(BaseModel):
    username: constr(min_length=1, max_length=50)
    email: str
    password: constr(min_length=8)


class UserUpdate(BaseModel):
    username: Optional[constr(min_length=1, max_length=50)] = None
    email: Optional[str] = None
    password: Optional[constr(min_length=8)] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_admin: Optional[bool] = None


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
        500: {"description": "Internal Server Error"}
    }
)


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
        user_create: UserCreate,
        user_repo: UserRepository = Depends(get_user_repository),
):
    """
    Create a new user account.
    """
    try:
        # Check for existing username/email
        if await user_repo.get_by_username(user_create.username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )

        if await user_repo.get_by_email(user_create.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        # Create user model
        user = UserModel(
            id=uuid4(),
            username=user_create.username,
            email=user_create.email,
            password_hash=get_password_hash(user_create.password),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

        return await user_repo.create(user)

    except OperationError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
        current_user: UserModel = Depends(get_current_user)
):
    """
    Get information about the currently authenticated user.
    """
    return current_user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
        user_id: UUID,
        user_repo: UserRepository = Depends(get_user_repository)
):
    """Get user by ID - no auth required"""
    try:
        user = await user_repo.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return user
    except RecordNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )


@router.get("/", response_model=List[UserResponse])
async def get_users(
        skip: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=100),
        user_repo: UserRepository = Depends(get_user_repository)
):
    """Get a list of users with pagination."""
    try:
        return await user_repo.get_paginated(skip=skip, limit=limit)
    except OperationError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
        user_id: UUID,
        user_update: UserUpdate,
        current_user: UserModel = Depends(get_current_user),
        user_repo: UserRepository = Depends(get_user_repository)
):
    """
    Update user information.
    """
    # Check permission
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user"
        )

    try:
        # Check if user exists
        if not await user_repo.get_by_id(user_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Prepare update data
        update_data = user_update.model_dump(exclude_unset=True)

        # Handle password update
        if "password" in update_data:
            update_data["password_hash"] = get_password_hash(update_data.pop("password"))

        # Set updated_at timestamp
        update_data["updated_at"] = datetime.now(timezone.utc)

        # Check username uniqueness if being updated
        if "username" in update_data:
            existing_user = await user_repo.get_by_username(update_data["username"])
            if existing_user and existing_user.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already taken"
                )

        # Check email uniqueness if being updated
        if "email" in update_data:
            existing_user = await user_repo.get_by_email(update_data["email"])
            if existing_user and existing_user.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )

        return await user_repo.update(user_id, update_data)

    except OperationError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
        user_id: UUID,
        current_user: UserModel = Depends(get_current_user_no_update),
        user_repo: UserRepository = Depends(get_user_repository)
):
    # Check permission
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this user"
        )

    try:
        await user_repo.delete(user_id)
    except RecordNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    except OperationError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
    # todo: consider removing this or use Exception catch all over the place
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.put("/{user_id}/verify", response_model=UserResponse)
async def verify_user(
        user_id: UUID,
        current_user: UserModel = Depends(get_current_user),
        user_repo: UserRepository = Depends(get_user_repository)
):
    """
    Verify a user's account.
    """
    try:
        user = await user_repo.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Allow self-verification or admin action
        if current_user.id != user_id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to verify this user"
            )

        update_data = {
            "is_verified": True,
            "updated_at": datetime.now(timezone.utc)
        }

        return await user_repo.update(user_id, update_data)

    except OperationError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
