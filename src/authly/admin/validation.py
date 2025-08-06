"""
Admin Validation Module for Authly.

This module provides business rule validation for admin operations,
ensuring data integrity and enforcing business constraints before
operations are performed.
"""

import logging
import re
from typing import Any
from uuid import UUID

from psycopg import AsyncConnection

from authly.admin.errors import (
    AdminErrorCode,
    AdminValidationError,
    ErrorDetail,
    create_last_admin_error,
    create_self_admin_revoke_error,
    create_user_not_found_error,
)
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


class AdminUserValidation:
    """
    Validation rules for admin user management operations.

    This class enforces business rules and data validation for user
    management operations performed by administrators.
    """

    def __init__(self, db_connection: AsyncConnection):
        """
        Initialize user validation with database connection.

        Args:
            db_connection: Database connection for validation queries
        """
        self.db_connection = db_connection
        self.user_repository = UserRepository(db_connection)

    async def validate_user_creation(self, user_data: dict[str, Any], requesting_admin: UserModel) -> None:
        """
        Validate user creation request.

        Args:
            user_data: User data to validate
            requesting_admin: Admin user making the request

        Raises:
            AdminValidationError: If validation fails
        """
        errors = []

        # Validate required fields (password is optional if temp password generation is requested)
        required_fields = ["username", "email"]
        generate_temp_password = user_data.get("generate_temp_password", False)

        if not generate_temp_password:
            required_fields.append("password")

        for field in required_fields:
            if not user_data.get(field):
                errors.append(
                    ErrorDetail(
                        field=field,
                        code=AdminErrorCode.MISSING_REQUIRED_FIELD,
                        message=f"Field '{field}' is required",
                    )
                )

        # Validate username format
        username = user_data.get("username")
        if username:
            username_error = self._validate_username_format(username)
            if username_error:
                errors.append(username_error)

        # Validate email format
        email = user_data.get("email")
        if email:
            email_error = self._validate_email_format(email)
            if email_error:
                errors.append(email_error)

        # Check for existing username
        if username:
            existing_user = await self.user_repository.get_by_username(username)
            if existing_user:
                errors.append(
                    ErrorDetail(
                        field="username",
                        code=AdminErrorCode.USER_ALREADY_EXISTS,
                        message=f"Username '{username}' already exists",
                        value=username,
                    )
                )

        # Check for existing email
        if email:
            existing_user = await self.user_repository.get_by_email(email)
            if existing_user:
                errors.append(
                    ErrorDetail(
                        field="email",
                        code=AdminErrorCode.USER_ALREADY_EXISTS,
                        message=f"Email '{email}' already exists",
                        value=email,
                    )
                )

        # Validate password if provided (skip validation for temp password placeholder)
        password = user_data.get("password")
        if password and password != "temp_password_placeholder":
            password_errors = self._validate_password_strength(password)
            errors.extend(password_errors)

        # Validate admin privilege assignment
        is_admin = user_data.get("is_admin", False)
        if is_admin:
            # Log admin privilege assignment
            logger.info(
                f"Admin {requesting_admin.username} creating new admin user: {username}",
                extra={
                    "requesting_admin_id": requesting_admin.id,
                    "new_admin_username": username,
                },
            )

        if errors:
            raise AdminValidationError(
                message=f"User creation validation failed with {len(errors)} errors",
                error_code=AdminErrorCode.VALIDATION_FAILED,
                details=errors,
            )

    async def validate_user_update(
        self, user_id: UUID, update_data: dict[str, Any], requesting_admin: UserModel
    ) -> UserModel:
        """
        Validate user update request.

        Args:
            user_id: ID of user to update
            update_data: Update data to validate
            requesting_admin: Admin user making the request

        Returns:
            UserModel: The user being updated

        Raises:
            AdminValidationError: If validation fails
        """
        errors = []

        # Get the user being updated
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise create_user_not_found_error(user_id)

        # Validate username if being updated
        new_username = update_data.get("username")
        if new_username and new_username != user.username:
            # Validate format
            username_error = self._validate_username_format(new_username)
            if username_error:
                errors.append(username_error)

            # Check for conflicts
            existing_user = await self.user_repository.get_by_username(new_username)
            if existing_user and existing_user.id != user.id:
                errors.append(
                    ErrorDetail(
                        field="username",
                        code=AdminErrorCode.USER_ALREADY_EXISTS,
                        message=f"Username '{new_username}' already exists",
                        value=new_username,
                    )
                )

        # Validate email if being updated
        new_email = update_data.get("email")
        if new_email and new_email != user.email:
            # Validate format
            email_error = self._validate_email_format(new_email)
            if email_error:
                errors.append(email_error)

            # Check for conflicts
            existing_user = await self.user_repository.get_by_email(new_email)
            if existing_user and existing_user.id != user.id:
                errors.append(
                    ErrorDetail(
                        field="email",
                        code=AdminErrorCode.USER_ALREADY_EXISTS,
                        message=f"Email '{new_email}' already exists",
                        value=new_email,
                    )
                )

        # Validate admin privilege changes
        new_is_admin = update_data.get("is_admin")
        if new_is_admin is not None and new_is_admin != user.is_admin:
            admin_error = await self._validate_admin_privilege_change(user, new_is_admin, requesting_admin)
            if admin_error:
                raise admin_error

        # Validate password if being updated
        new_password = update_data.get("password")
        if new_password:
            password_errors = self._validate_password_strength(new_password)
            errors.extend(password_errors)

        if errors:
            raise AdminValidationError(
                message=f"User update validation failed with {len(errors)} errors",
                error_code=AdminErrorCode.VALIDATION_FAILED,
                details=errors,
            )

        return user

    async def validate_user_deletion(self, user_id: UUID, requesting_admin: UserModel) -> UserModel:
        """
        Validate user deletion request.

        Args:
            user_id: ID of user to delete
            requesting_admin: Admin user making the request

        Returns:
            UserModel: The user being deleted

        Raises:
            AdminValidationError: If validation fails
        """
        # Get the user being deleted
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise create_user_not_found_error(user_id)

        # Check if this is the last admin user
        if user.is_admin:
            admin_count = await self._count_admin_users()
            if admin_count <= 1:
                raise create_last_admin_error()

        # Log the deletion attempt
        logger.warning(
            f"Admin {requesting_admin.username} deleting user: {user.username}",
            extra={
                "requesting_admin_id": requesting_admin.id,
                "deleted_user_id": user.id,
                "deleted_user_username": user.username,
                "deleted_user_is_admin": user.is_admin,
            },
        )

        return user

    async def validate_password_reset(self, user_id: UUID, requesting_admin: UserModel) -> UserModel:
        """
        Validate password reset request.

        Args:
            user_id: ID of user to reset password for
            requesting_admin: Admin user making the request

        Returns:
            UserModel: The user whose password will be reset

        Raises:
            AdminValidationError: If validation fails
        """
        # Get the user whose password will be reset
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise create_user_not_found_error(user_id)

        # Log the password reset attempt for audit purposes
        logger.warning(
            f"Admin {requesting_admin.username} resetting password for user: {user.username}",
            extra={
                "requesting_admin_id": requesting_admin.id,
                "target_user_id": user.id,
                "target_username": user.username,
                "target_is_admin": user.is_admin,
            },
        )

        return user

    async def validate_session_access(self, user_id: UUID, requesting_admin: UserModel) -> UserModel:
        """
        Validate session access request.

        Args:
            user_id: ID of user whose sessions are being accessed
            requesting_admin: Admin user making the request

        Returns:
            UserModel: The user whose sessions are being accessed

        Raises:
            AdminValidationError: If validation fails
        """
        # Get the user whose sessions are being accessed
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise create_user_not_found_error(user_id)

        # Log the session access for audit purposes
        logger.info(
            f"Admin {requesting_admin.username} accessing sessions for user: {user.username}",
            extra={
                "requesting_admin_id": requesting_admin.id,
                "target_user_id": user.id,
                "target_username": user.username,
                "target_is_admin": user.is_admin,
            },
        )

        return user

    async def validate_session_revocation(
        self, user_id: UUID, requesting_admin: UserModel, session_id: UUID | None = None
    ) -> UserModel:
        """
        Validate session revocation request.

        Args:
            user_id: ID of user whose sessions are being revoked
            requesting_admin: Admin user making the request
            session_id: Optional specific session ID being revoked

        Returns:
            UserModel: The user whose sessions are being revoked

        Raises:
            AdminValidationError: If validation fails
        """
        # Get the user whose sessions are being revoked
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise create_user_not_found_error(user_id)

        # Log the session revocation attempt for audit purposes
        action = f"specific session {session_id}" if session_id else "all sessions"
        logger.warning(
            f"Admin {requesting_admin.username} revoking {action} for user: {user.username}",
            extra={
                "requesting_admin_id": requesting_admin.id,
                "target_user_id": user.id,
                "target_username": user.username,
                "target_is_admin": user.is_admin,
                "session_id": session_id,
                "action": "revoke_session" if session_id else "revoke_all_sessions",
            },
        )

        return user

    async def _validate_admin_privilege_change(
        self, user: UserModel, new_is_admin: bool, requesting_admin: UserModel
    ) -> AdminValidationError | None:
        """
        Validate admin privilege changes.

        Args:
            user: User being modified
            new_is_admin: New admin status
            requesting_admin: Admin making the request

        Returns:
            AdminValidationError if validation fails, None otherwise
        """
        # Check if admin is trying to revoke their own privileges
        if user.id == requesting_admin.id and not new_is_admin:
            return create_self_admin_revoke_error()

        # Check if removing admin would leave no admins
        if user.is_admin and not new_is_admin:
            admin_count = await self._count_admin_users()
            if admin_count <= 1:
                return create_last_admin_error()

        # Log privilege changes
        if new_is_admin and not user.is_admin:
            logger.info(
                f"Admin {requesting_admin.username} granting admin privileges to: {user.username}",
                extra={
                    "requesting_admin_id": requesting_admin.id,
                    "target_user_id": user.id,
                    "target_username": user.username,
                },
            )
        elif not new_is_admin and user.is_admin:
            logger.warning(
                f"Admin {requesting_admin.username} revoking admin privileges from: {user.username}",
                extra={
                    "requesting_admin_id": requesting_admin.id,
                    "target_user_id": user.id,
                    "target_username": user.username,
                },
            )

        return None

    async def _count_admin_users(self) -> int:
        """
        Count the number of admin users in the system.

        Returns:
            Number of admin users
        """
        # This could be optimized with a direct count query
        admin_users = await self.user_repository.get_admin_users()
        return len(admin_users)

    def _validate_username_format(self, username: str) -> ErrorDetail | None:
        """
        Validate username format.

        Args:
            username: Username to validate

        Returns:
            ErrorDetail if validation fails, None otherwise
        """
        if not username:
            return ErrorDetail(
                field="username",
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message="Username cannot be empty",
            )

        if len(username) < 3:
            return ErrorDetail(
                field="username",
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message="Username must be at least 3 characters long",
                value=username,
            )

        if len(username) > 32:
            return ErrorDetail(
                field="username",
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message="Username must be no more than 32 characters long",
                value=username,
            )

        # Username must contain only alphanumeric characters and underscores
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            return ErrorDetail(
                field="username",
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message="Username can only contain letters, numbers, and underscores",
                value=username,
            )

        return None

    def _validate_email_format(self, email: str) -> ErrorDetail | None:
        """
        Validate email format.

        Args:
            email: Email to validate

        Returns:
            ErrorDetail if validation fails, None otherwise
        """
        if not email:
            return ErrorDetail(
                field="email",
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message="Email cannot be empty",
            )

        # Basic email validation regex
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, email):
            return ErrorDetail(
                field="email",
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message="Invalid email format",
                value=email,
            )

        if len(email) > 254:  # RFC 5321 limit
            return ErrorDetail(
                field="email",
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message="Email address is too long",
                value=email,
            )

        return None

    def _validate_password_strength(self, password: str) -> list[ErrorDetail]:
        """
        Validate password strength.

        Args:
            password: Password to validate

        Returns:
            List of ErrorDetail objects for any validation failures
        """
        errors = []

        if not password:
            errors.append(
                ErrorDetail(
                    field="password",
                    code=AdminErrorCode.FIELD_VALUE_INVALID,
                    message="Password cannot be empty",
                )
            )
            return errors

        if len(password) < 8:
            errors.append(
                ErrorDetail(
                    field="password",
                    code=AdminErrorCode.FIELD_VALUE_INVALID,
                    message="Password must be at least 8 characters long",
                )
            )

        if not re.search(r"[A-Z]", password):
            errors.append(
                ErrorDetail(
                    field="password",
                    code=AdminErrorCode.FIELD_VALUE_INVALID,
                    message="Password must contain at least one uppercase letter",
                )
            )

        if not re.search(r"[a-z]", password):
            errors.append(
                ErrorDetail(
                    field="password",
                    code=AdminErrorCode.FIELD_VALUE_INVALID,
                    message="Password must contain at least one lowercase letter",
                )
            )

        if not re.search(r"[0-9]", password):
            errors.append(
                ErrorDetail(
                    field="password",
                    code=AdminErrorCode.FIELD_VALUE_INVALID,
                    message="Password must contain at least one number",
                )
            )

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append(
                ErrorDetail(
                    field="password",
                    code=AdminErrorCode.FIELD_VALUE_INVALID,
                    message="Password must contain at least one special character",
                )
            )

        return errors


class AdminClientValidation:
    """
    Validation rules for admin client management operations.
    """

    def validate_client_creation(self, client_data: dict[str, Any]) -> None:
        """
        Validate OAuth client creation request.

        Args:
            client_data: Client data to validate

        Raises:
            AdminValidationError: If validation fails
        """
        errors = []

        # Validate required fields
        required_fields = ["client_name", "client_type"]
        for field in required_fields:
            if not client_data.get(field):
                errors.append(
                    ErrorDetail(
                        field=field,
                        code=AdminErrorCode.MISSING_REQUIRED_FIELD,
                        message=f"Field '{field}' is required",
                    )
                )

        # Validate client name
        client_name = client_data.get("client_name")
        if client_name and len(client_name) > 100:
            errors.append(
                ErrorDetail(
                    field="client_name",
                    code=AdminErrorCode.FIELD_VALUE_INVALID,
                    message="Client name must be no more than 100 characters",
                    value=client_name,
                )
            )

        # Validate redirect URIs if provided
        redirect_uris = client_data.get("redirect_uris", [])
        if redirect_uris:
            uri_errors = self._validate_redirect_uris(redirect_uris)
            errors.extend(uri_errors)

        if errors:
            raise AdminValidationError(
                message=f"Client creation validation failed with {len(errors)} errors",
                error_code=AdminErrorCode.VALIDATION_FAILED,
                details=errors,
            )

    def _validate_redirect_uris(self, redirect_uris: list[str]) -> list[ErrorDetail]:
        """
        Validate redirect URIs.

        Args:
            redirect_uris: List of redirect URIs to validate

        Returns:
            List of validation errors
        """
        errors = []

        for i, uri in enumerate(redirect_uris):
            if not uri.startswith(("http://", "https://")):
                errors.append(
                    ErrorDetail(
                        field=f"redirect_uris[{i}]",
                        code=AdminErrorCode.FIELD_VALUE_INVALID,
                        message="Redirect URI must use http or https scheme",
                        value=uri,
                    )
                )

        return errors


class AdminScopeValidation:
    """
    Validation rules for admin scope management operations.
    """

    def validate_scope_creation(self, scope_data: dict[str, Any]) -> None:
        """
        Validate OAuth scope creation request.

        Args:
            scope_data: Scope data to validate

        Raises:
            AdminValidationError: If validation fails
        """
        errors = []

        # Validate required fields
        scope_name = scope_data.get("scope_name")
        if not scope_name:
            errors.append(
                ErrorDetail(
                    field="scope_name",
                    code=AdminErrorCode.MISSING_REQUIRED_FIELD,
                    message="Scope name is required",
                )
            )

        # Validate scope name format
        if scope_name and not re.match(r"^[a-zA-Z0-9:._-]+$", scope_name):
            errors.append(
                ErrorDetail(
                    field="scope_name",
                    code=AdminErrorCode.FIELD_VALUE_INVALID,
                    message="Scope name can only contain letters, numbers, colons, dots, underscores, and hyphens",
                    value=scope_name,
                )
            )

        if errors:
            raise AdminValidationError(
                message=f"Scope creation validation failed with {len(errors)} errors",
                error_code=AdminErrorCode.VALIDATION_FAILED,
                details=errors,
            )
