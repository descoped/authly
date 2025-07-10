"""User service layer for centralizing business logic."""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from psycopg_toolkit import OperationError, RecordNotFoundError

from authly.auth.core import get_password_hash
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


class UserService:
    """
    Service layer for user management business logic.

    Centralizes user-related business rules, validation, and operations
    that were previously scattered across routers and dependencies.
    """

    def __init__(self, user_repo: UserRepository):
        self._repo = user_repo

    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        is_admin: bool = False,
        is_verified: bool = False,
        is_active: bool = True,
    ) -> UserModel:
        """
        Create a new user with business logic validation.

        Args:
            username: Unique username
            email: Unique email address
            password: Plain text password (will be hashed)
            is_admin: Admin privileges flag
            is_verified: Email verification status
            is_active: Account active status

        Returns:
            UserModel: Created user

        Raises:
            HTTPException: If validation fails or user already exists
        """
        try:
            # Check for existing username
            if await self._repo.get_by_username(username):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")

            # Check for existing email
            if await self._repo.get_by_email(email):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

            # Create user model with hashed password
            user = UserModel(
                id=uuid4(),
                username=username,
                email=email,
                password_hash=get_password_hash(password),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                is_active=is_active,
                is_verified=is_verified,
                is_admin=is_admin,
            )

            created_user = await self._repo.create(user)
            logger.info(f"Created new user: {username} (ID: {created_user.id})")
            return created_user

        except OperationError as e:
            logger.error(f"Database error creating user {username}: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user")

    async def update_user(
        self,
        user_id: UUID,
        update_data: Dict,
        requesting_user: UserModel,
        admin_override: bool = False,
    ) -> UserModel:
        """
        Update user with business logic validation and permission checks.

        Args:
            user_id: ID of user to update
            update_data: Dictionary of fields to update
            requesting_user: User making the request
            admin_override: Allow admin to update any user

        Returns:
            UserModel: Updated user

        Raises:
            HTTPException: If validation fails or permission denied
        """
        try:
            # Permission check: users can only update themselves unless admin override
            if not admin_override and requesting_user.id != user_id:
                if not requesting_user.is_admin:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update this user"
                    )

            # Check if target user exists
            try:
                existing_user = await self._repo.get_by_id(user_id)
            except RecordNotFoundError:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            # Prepare sanitized update data
            sanitized_data = update_data.copy()

            # Handle password update with hashing
            if "password" in sanitized_data:
                sanitized_data["password_hash"] = get_password_hash(sanitized_data.pop("password"))

            # Always update the timestamp
            sanitized_data["updated_at"] = datetime.now(timezone.utc)

            # Validate username uniqueness if being updated
            if "username" in sanitized_data:
                await self._validate_username_uniqueness(sanitized_data["username"], user_id)

            # Validate email uniqueness if being updated
            if "email" in sanitized_data:
                await self._validate_email_uniqueness(sanitized_data["email"], user_id)

            # Perform the update
            updated_user = await self._repo.update(user_id, sanitized_data)
            logger.info(f"Updated user {user_id} by user {requesting_user.id}")
            return updated_user

        except OperationError as e:
            logger.error(f"Database error updating user {user_id}: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update user")

    async def delete_user(self, user_id: UUID, requesting_user: UserModel) -> None:
        """
        Delete user with permission validation.

        Args:
            user_id: ID of user to delete
            requesting_user: User making the request

        Raises:
            HTTPException: If permission denied or user not found
        """
        # Permission check: users can only delete themselves (or admin override)
        if requesting_user.id != user_id and not requesting_user.is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this user")

        try:
            await self._repo.delete(user_id)
            logger.info(f"Deleted user {user_id} by user {requesting_user.id}")
        except RecordNotFoundError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        except OperationError as e:
            logger.error(f"Database error deleting user {user_id}: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete user")

    async def verify_user(self, user_id: UUID, requesting_user: UserModel) -> UserModel:
        """
        Verify a user account.

        Args:
            user_id: ID of user to verify
            requesting_user: User making the request

        Returns:
            UserModel: Verified user

        Raises:
            HTTPException: If permission denied or user not found
        """
        # Users can verify themselves, or admins can verify anyone
        if requesting_user.id != user_id and not requesting_user.is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to verify this user")

        try:
            # Check if user exists
            try:
                await self._repo.get_by_id(user_id)
            except RecordNotFoundError:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            # Update verification status
            update_data = {"is_verified": True, "updated_at": datetime.now(timezone.utc)}

            verified_user = await self._repo.update(user_id, update_data)
            logger.info(f"Verified user {user_id} by user {requesting_user.id}")
            return verified_user

        except OperationError as e:
            logger.error(f"Database error verifying user {user_id}: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to verify user")

    async def get_user_by_id(self, user_id: UUID) -> UserModel:
        """
        Get user by ID with proper error handling.

        Args:
            user_id: User ID to retrieve

        Returns:
            UserModel: Retrieved user

        Raises:
            HTTPException: If user not found
        """
        try:
            return await self._repo.get_by_id(user_id)
        except RecordNotFoundError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        except OperationError as e:
            logger.error(f"Database error retrieving user {user_id}: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve user")

    async def get_users_paginated(self, skip: int = 0, limit: int = 100) -> List[UserModel]:
        """
        Get paginated list of users.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List[UserModel]: List of users

        Raises:
            HTTPException: If database error occurs
        """
        try:
            return await self._repo.get_paginated(skip=skip, limit=limit)
        except OperationError as e:
            logger.error(f"Database error retrieving users: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve users")

    async def _validate_username_uniqueness(self, username: str, exclude_user_id: Optional[UUID] = None) -> None:
        """
        Validate that username is unique.

        Args:
            username: Username to check
            exclude_user_id: User ID to exclude from check (for updates)

        Raises:
            HTTPException: If username is already taken
        """
        existing_user = await self._repo.get_by_username(username)
        if existing_user and existing_user.id != exclude_user_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")

    async def _validate_email_uniqueness(self, email: str, exclude_user_id: Optional[UUID] = None) -> None:
        """
        Validate that email is unique.

        Args:
            email: Email to check
            exclude_user_id: User ID to exclude from check (for updates)

        Raises:
            HTTPException: If email is already registered
        """
        existing_user = await self._repo.get_by_email(email)
        if existing_user and existing_user.id != exclude_user_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
