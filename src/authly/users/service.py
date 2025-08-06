"""User service layer for centralizing business logic."""

import logging
import secrets
import string
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from psycopg_toolkit import OperationError, RecordNotFoundError

from authly.auth.core import get_password_hash
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)

# Define admin-only fields that require elevated privileges to access
ADMIN_ONLY_FIELDS = {
    "password_hash",
    "is_admin",
    "is_active",
    "is_verified",
    "requires_password_change",
    "last_login",
    "created_at",
    "updated_at",
}


class UserService:
    """
    Service layer for user management business logic.

    Centralizes user-related business rules, validation, and operations
    that were previously scattered across routers and dependencies.
    """

    def __init__(self, user_repo: UserRepository):
        self._repo = user_repo

    def generate_temporary_password(self, length: int = 12) -> str:
        """
        Generate a secure temporary password.

        Args:
            length: Length of the password (minimum 8, default 12)

        Returns:
            str: Generated temporary password

        The password will contain:
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        - Remaining characters from all categories
        """
        if length < 8:
            length = 8

        # Define character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*"
        all_chars = uppercase + lowercase + digits + special

        # Ensure at least one character from each required category
        password_chars = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special),
        ]

        # Fill remaining length with random characters from all categories
        for _ in range(length - 4):
            password_chars.append(secrets.choice(all_chars))

        # Shuffle the list to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)

        return "".join(password_chars)

    def _filter_user_fields(
        self, user: UserModel, is_admin_context: bool = False, include_admin_fields: bool = False
    ) -> dict:
        """
        Filter user fields based on admin context and permissions.

        Args:
            user: UserModel to filter
            is_admin_context: Whether the request is from an admin context
            include_admin_fields: Whether to include admin-only fields (requires is_admin_context=True)

        Returns:
            Dict: Filtered user data
        """
        user_dict = user.model_dump()

        # If not admin context or explicitly excluding admin fields, remove them
        if not is_admin_context or not include_admin_fields:
            for field in ADMIN_ONLY_FIELDS:
                user_dict.pop(field, None)

        return user_dict

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
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                is_active=is_active,
                is_verified=is_verified,
                is_admin=is_admin,
            )

            created_user = await self._repo.create(user)
            logger.info(f"Created new user: {username} (ID: {created_user.id})")
            return created_user

        except OperationError as e:
            logger.error(f"Database error creating user {username}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user"
            ) from None

    async def create_admin_user(
        self,
        user_data: dict,
        requesting_user: UserModel,
        generate_temp_password: bool = False,
    ) -> tuple[UserModel, str | None]:
        """
        Create a new user with admin privileges and comprehensive field support.

        This method allows administrators to create users with:
        - Admin privileges (is_admin, is_verified, is_active)
        - All OIDC profile fields
        - Password policy enforcement
        - Temporary password generation option

        Args:
            user_data: Complete user data including all fields
            requesting_user: Admin user making the request
            generate_temp_password: If True, generates temporary password and sets requires_password_change

        Returns:
            Tuple[UserModel, Optional[str]]: Created user and optional temporary password

        Raises:
            HTTPException: If validation fails or user already exists
        """
        try:
            # Extract required fields
            username = user_data["username"]
            email = user_data["email"]

            # Handle password - either use provided or generate temporary
            temp_password = None
            if generate_temp_password:
                password = self.generate_temporary_password()
                temp_password = password
            else:
                password = user_data.get("password")
                if not password:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Password is required when not generating temporary password",
                    )

            # Check for existing username
            if await self._repo.get_by_username(username):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")

            # Check for existing email
            if await self._repo.get_by_email(email):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

            # Create comprehensive user model with all provided fields
            user_fields = {
                "id": uuid4(),
                "username": username,
                "email": email,
                "password_hash": get_password_hash(password),
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
                # Admin-controllable fields with defaults
                "is_active": user_data.get("is_active", True),
                "is_verified": user_data.get("is_verified", False),
                "is_admin": user_data.get("is_admin", False),
                "requires_password_change": generate_temp_password or user_data.get("requires_password_change", False),
            }

            # Add all OIDC profile fields if provided
            oidc_fields = [
                "given_name",
                "family_name",
                "middle_name",
                "nickname",
                "preferred_username",
                "profile",
                "picture",
                "website",
                "gender",
                "birthdate",
                "zoneinfo",
                "locale",
                "phone_number",
                "phone_number_verified",
                "address",
            ]

            for field in oidc_fields:
                if field in user_data and user_data[field] is not None:
                    user_fields[field] = user_data[field]

            # Create user model
            user = UserModel(**user_fields)

            created_user = await self._repo.create(user)

            logger.info(
                f"Admin {requesting_user.username} created user: {username} "
                f"(ID: {created_user.id}, is_admin: {created_user.is_admin}, temp_password: {generate_temp_password})"
            )
            return created_user, temp_password

        except OperationError as e:
            logger.error(f"Database error creating admin user {username}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user"
            ) from None

    async def update_user(
        self,
        user_id: UUID,
        update_data: dict,
        requesting_user: UserModel,
        admin_override: bool = False,
        admin_context: bool = False,
    ) -> UserModel:
        """
        Update user with business logic validation and permission checks.

        Args:
            user_id: ID of user to update
            update_data: Dictionary of fields to update
            requesting_user: User making the request
            admin_override: Allow admin to update any user
            admin_context: Whether this is an admin operation (affects field filtering)

        Returns:
            UserModel: Updated user

        Raises:
            HTTPException: If validation fails or permission denied
        """
        try:
            # Permission check: users can only update themselves unless admin override
            if not admin_override and requesting_user.id != user_id and not requesting_user.is_admin:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update this user")

            # Check if target user exists
            try:
                await self._repo.get_by_id(user_id)
            except RecordNotFoundError as e:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from e

            # Prepare sanitized update data
            sanitized_data = update_data.copy()
            # Check for admin-only field updates without proper context
            admin_fields_in_update = set(sanitized_data.keys()) & ADMIN_ONLY_FIELDS
            if admin_fields_in_update and not (admin_context and requesting_user.is_admin):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Admin privileges required to update fields: {', '.join(admin_fields_in_update)}",
                )

            # Handle password update with hashing
            if "password" in sanitized_data:
                sanitized_data["password_hash"] = get_password_hash(sanitized_data.pop("password"))

            # Always update the timestamp
            sanitized_data["updated_at"] = datetime.now(UTC)

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
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update user"
            ) from None

    async def delete_user(self, user_id: UUID, requesting_user: UserModel, admin_override: bool = False) -> None:
        """
        Delete user with permission validation.

        Args:
            user_id: ID of user to delete
            requesting_user: User making the request
            admin_override: Allow admin to delete any user

        Raises:
            HTTPException: If permission denied or user not found
        """
        # Permission check: users can only delete themselves unless admin override
        if not admin_override and requesting_user.id != user_id and not requesting_user.is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this user")

        try:
            await self._repo.delete(user_id)
            logger.info(f"Deleted user {user_id} by user {requesting_user.id}")
        except RecordNotFoundError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from e

        except OperationError as e:
            logger.error(f"Database error deleting user {user_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete user"
            ) from None

    async def cascade_delete_user(self, user_id: UUID, requesting_user: UserModel) -> dict[str, int]:
        """
        Delete user with cascade cleanup of all related data.

        This method performs a complete cleanup of user data including:
        - User tokens (access and refresh tokens)
        - OAuth authorization codes
        - The user record itself

        Args:
            user_id: ID of user to delete
            requesting_user: Admin user making the request

        Returns:
            Dict with counts of deleted items

        Raises:
            HTTPException: If user not found or operation fails
        """
        try:
            # First check if the user exists
            user = await self.get_user_by_id(user_id, admin_context=True)

            # Track what we're deleting for audit
            deletion_stats = {"tokens_invalidated": 0, "auth_codes_revoked": 0, "user_deleted": False}

            # Import repositories needed for cascade deletion
            from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
            from authly.tokens.repository import TokenRepository

            # Use the same connection as the user repository
            conn = self._repo.db_connection

            # 1. Invalidate all user tokens
            token_repo = TokenRepository(conn)
            await token_repo.invalidate_user_tokens(user_id)
            deletion_stats["tokens_invalidated"] = await token_repo.get_invalidated_token_count(user_id)

            # 2. Revoke all unused authorization codes
            auth_code_repo = AuthorizationCodeRepository(conn)
            deletion_stats["auth_codes_revoked"] = await auth_code_repo.revoke_codes_for_user(user_id)

            # 3. Delete the user record
            await self._repo.delete(user_id)
            deletion_stats["user_deleted"] = True

            logger.info(
                f"Admin {requesting_user.username} cascade deleted user {user.username} "
                f"(ID: {user_id}): {deletion_stats}"
            )

            return deletion_stats

        except RecordNotFoundError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from e

        except Exception as e:
            logger.error(f"Failed to cascade delete user {user_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user: {e!s}"
            ) from None

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
            except RecordNotFoundError as e:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from e

            # Update verification status
            update_data = {"is_verified": True, "updated_at": datetime.now(UTC)}
            verified_user = await self._repo.update(user_id, update_data)
            logger.info(f"Verified user {user_id} by user {requesting_user.id}")
            return verified_user

        except OperationError as e:
            logger.error(f"Database error verifying user {user_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to verify user"
            ) from None

    async def get_user_by_id(self, user_id: UUID, admin_context: bool = False) -> UserModel:
        """
        Get user by ID with proper error handling.

        Args:
            user_id: User ID to retrieve
            admin_context: Whether this is an admin operation (affects field filtering)

        Returns:
            UserModel: Retrieved user

        Raises:
            HTTPException: If user not found
        """
        try:
            return await self._repo.get_by_id(user_id)
        except RecordNotFoundError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from e

        except OperationError as e:
            logger.error(f"Database error retrieving user {user_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve user"
            ) from None

    async def get_users_paginated(
        self, skip: int = 0, limit: int = 100, admin_context: bool = False, filters: dict | None = None
    ) -> list[UserModel]:
        """
        Get paginated list of users.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return
            admin_context: Whether this is an admin operation (affects field filtering)
            filters: Optional filters for admin queries

        Returns:
            List[UserModel]: List of users

        Raises:
            HTTPException: If database error occurs
        """
        try:
            if filters:
                return await self._repo.get_filtered_paginated(filters=filters, skip=skip, limit=limit)
            else:
                return await self._repo.get_paginated(skip=skip, limit=limit)
        except OperationError as e:
            logger.error(f"Database error retrieving users: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve users"
            ) from None

    async def count_users(self, filters: dict | None = None) -> int:
        """
        Count total users matching filter criteria.

        Args:
            filters: Optional filters for counting

        Returns:
            Total count of users

        Raises:
            HTTPException: If database error occurs
        """
        try:
            return await self._repo.count_filtered(filters=filters)
        except OperationError as e:
            logger.error(f"Database error counting users: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to count users"
            ) from None

    async def get_optimized_admin_listing(
        self, skip: int = 0, limit: int = 100, filters: dict | None = None
    ) -> tuple[list[dict], int, int]:
        """
        Get optimized admin user listing with session counts using a single CTE query.

        This method provides significant performance improvements over separate queries:
        - Single database round trip
        - Inline session count calculation
        - CTE-based filtering and counting
        - Optimized for large datasets

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return
            filters: Optional filters for admin queries

        Returns:
            Tuple of (user_list_with_sessions, total_count, active_users_count)

        Raises:
            HTTPException: If database error occurs
        """
        try:
            return await self._repo.get_optimized_admin_listing(filters=filters, skip=skip, limit=limit)
        except OperationError as e:
            logger.error(f"Database error in optimized admin listing: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve optimized admin listing"
            ) from None

    async def get_user_with_sessions(self, user_id: UUID, admin_context: bool = False) -> dict | None:
        """
        Get a user with their active session count efficiently.

        Args:
            user_id: User ID to retrieve
            admin_context: Whether this is an admin operation

        Returns:
            User data dict with active_sessions field, or None if not found

        Raises:
            HTTPException: If database error occurs
        """
        try:
            user_data = await self._repo.get_user_with_session_count(user_id)
            if not user_data:
                return None

            # Filter fields based on admin context
            if not admin_context:
                for field in ADMIN_ONLY_FIELDS:
                    user_data.pop(field, None)

            return user_data
        except OperationError as e:
            logger.error(f"Database error retrieving user with sessions: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve user with session information",
            ) from None

    async def _validate_username_uniqueness(self, username: str, exclude_user_id: UUID | None = None) -> None:
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

    async def _validate_email_uniqueness(self, email: str, exclude_user_id: UUID | None = None) -> None:
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
