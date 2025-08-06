"""
Admin Error Handling Module for Authly.

This module provides standardized error handling for admin operations,
including error codes, detailed error responses, and business rule validation errors.

Design Principles:
- Consistent error format across all admin endpoints
- Traceable errors with request IDs
- User-friendly error messages
- Machine-readable error codes
- Security-conscious error disclosure
"""

import logging
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AdminErrorCode(str, Enum):
    """
    Standardized error codes for admin operations.

    These codes provide machine-readable error identification and
    enable consistent error handling across different admin operations.
    """

    # Authentication and Authorization Errors
    UNAUTHORIZED = "ADMIN_UNAUTHORIZED"
    INSUFFICIENT_PRIVILEGES = "ADMIN_INSUFFICIENT_PRIVILEGES"
    TOKEN_EXPIRED = "ADMIN_TOKEN_EXPIRED"
    TOKEN_INVALID = "ADMIN_TOKEN_INVALID"

    # User Management Errors
    USER_NOT_FOUND = "ADMIN_USER_NOT_FOUND"
    USER_ALREADY_EXISTS = "ADMIN_USER_ALREADY_EXISTS"
    USER_CANNOT_BE_DELETED = "ADMIN_USER_CANNOT_BE_DELETED"
    USER_CANNOT_BE_MODIFIED = "ADMIN_USER_CANNOT_BE_MODIFIED"
    LAST_ADMIN_PROTECTION = "ADMIN_LAST_ADMIN_PROTECTION"
    SELF_ADMIN_REVOKE_DENIED = "ADMIN_SELF_ADMIN_REVOKE_DENIED"

    # Client Management Errors
    CLIENT_NOT_FOUND = "ADMIN_CLIENT_NOT_FOUND"
    CLIENT_ALREADY_EXISTS = "ADMIN_CLIENT_ALREADY_EXISTS"
    CLIENT_IN_USE = "ADMIN_CLIENT_IN_USE"
    CLIENT_INVALID_CONFIG = "ADMIN_CLIENT_INVALID_CONFIG"

    # Scope Management Errors
    SCOPE_NOT_FOUND = "ADMIN_SCOPE_NOT_FOUND"
    SCOPE_ALREADY_EXISTS = "ADMIN_SCOPE_ALREADY_EXISTS"
    SCOPE_IN_USE = "ADMIN_SCOPE_IN_USE"
    SCOPE_REQUIRED = "ADMIN_SCOPE_REQUIRED"

    # Validation Errors
    VALIDATION_FAILED = "ADMIN_VALIDATION_FAILED"
    INVALID_INPUT = "ADMIN_INVALID_INPUT"
    MISSING_REQUIRED_FIELD = "ADMIN_MISSING_REQUIRED_FIELD"
    FIELD_VALUE_INVALID = "ADMIN_FIELD_VALUE_INVALID"

    # System Errors
    INTERNAL_ERROR = "ADMIN_INTERNAL_ERROR"
    DATABASE_ERROR = "ADMIN_DATABASE_ERROR"
    EXTERNAL_SERVICE_ERROR = "ADMIN_EXTERNAL_SERVICE_ERROR"
    RATE_LIMIT_EXCEEDED = "ADMIN_RATE_LIMIT_EXCEEDED"

    # Operation Errors
    OPERATION_NOT_PERMITTED = "ADMIN_OPERATION_NOT_PERMITTED"
    RESOURCE_CONFLICT = "ADMIN_RESOURCE_CONFLICT"
    OPERATION_FAILED = "ADMIN_OPERATION_FAILED"


class ErrorDetail(BaseModel):
    """
    Detailed error information for specific field or validation errors.

    This model provides granular error details that help clients
    understand exactly what went wrong and how to fix it.
    """

    field: str | None = Field(None, description="Field name that caused the error")
    code: AdminErrorCode = Field(..., description="Specific error code")
    message: str = Field(..., description="Human-readable error message")
    value: Any | None = Field(None, description="Invalid value that caused the error")

    class Config:
        # Allow arbitrary types for the value field
        arbitrary_types_allowed = True


class AdminErrorResponse(BaseModel):
    """
    Standardized error response for all admin operations.

    This model ensures consistent error responses across all admin endpoints,
    making it easier for clients to handle errors programmatically.
    """

    success: bool = Field(False, description="Always false for error responses")
    error_code: AdminErrorCode = Field(..., description="Primary error code")
    message: str = Field(..., description="Primary error message")
    details: list[ErrorDetail] | None = Field(None, description="Detailed error information")
    request_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique request identifier")
    timestamp: str = Field(..., description="ISO timestamp when error occurred")

    # Optional debugging information (only in development)
    debug_info: dict[str, Any] | None = Field(None, description="Debug information (development only)")


class AdminValidationError(Exception):
    """
    Exception for admin validation errors.

    This exception is raised when admin operations fail due to business rule
    violations or validation errors. It carries structured error information
    that can be converted to a standardized error response.
    """

    def __init__(
        self,
        message: str,
        error_code: AdminErrorCode = AdminErrorCode.VALIDATION_FAILED,
        details: list[ErrorDetail] | None = None,
        debug_info: dict[str, Any] | None = None,
    ):
        """
        Initialize admin validation error.

        Args:
            message: Primary error message
            error_code: Specific error code
            details: List of detailed error information
            debug_info: Optional debug information
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or []
        self.debug_info = debug_info

        # Log the validation error
        logger.warning(f"Admin validation error: {error_code.value} - {message}")


class AdminOperationError(Exception):
    """
    Exception for admin operation errors.

    This exception is raised when admin operations fail due to system errors,
    resource conflicts, or other operational issues.
    """

    def __init__(
        self,
        message: str,
        error_code: AdminErrorCode = AdminErrorCode.OPERATION_FAILED,
        debug_info: dict[str, Any] | None = None,
    ):
        """
        Initialize admin operation error.

        Args:
            message: Primary error message
            error_code: Specific error code
            debug_info: Optional debug information
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.debug_info = debug_info

        # Log the operation error
        logger.error(f"Admin operation error: {error_code.value} - {message}")


# Convenience functions for common error scenarios


def create_user_not_found_error(user_id: str | int) -> AdminValidationError:
    """Create a standardized user not found error."""
    return AdminValidationError(
        message=f"User not found: {user_id}",
        error_code=AdminErrorCode.USER_NOT_FOUND,
        details=[
            ErrorDetail(
                field="user_id",
                code=AdminErrorCode.USER_NOT_FOUND,
                message="The specified user does not exist",
                value=user_id,
            )
        ],
    )


def create_last_admin_error() -> AdminValidationError:
    """Create a standardized last admin protection error."""
    return AdminValidationError(
        message="Cannot remove admin privileges from or delete the last admin user",
        error_code=AdminErrorCode.LAST_ADMIN_PROTECTION,
        details=[
            ErrorDetail(
                code=AdminErrorCode.LAST_ADMIN_PROTECTION,
                message="This operation would leave the system without any admin users",
            )
        ],
    )


def create_self_admin_revoke_error() -> AdminValidationError:
    """Create a standardized self admin revoke error."""
    return AdminValidationError(
        message="Cannot remove your own admin privileges",
        error_code=AdminErrorCode.SELF_ADMIN_REVOKE_DENIED,
        details=[
            ErrorDetail(
                code=AdminErrorCode.SELF_ADMIN_REVOKE_DENIED,
                message="Admin users cannot revoke their own admin privileges for security reasons",
            )
        ],
    )


def create_client_not_found_error(client_id: str) -> AdminValidationError:
    """Create a standardized client not found error."""
    return AdminValidationError(
        message=f"OAuth client not found: {client_id}",
        error_code=AdminErrorCode.CLIENT_NOT_FOUND,
        details=[
            ErrorDetail(
                field="client_id",
                code=AdminErrorCode.CLIENT_NOT_FOUND,
                message="The specified OAuth client does not exist",
                value=client_id,
            )
        ],
    )


def create_scope_not_found_error(scope_name: str) -> AdminValidationError:
    """Create a standardized scope not found error."""
    return AdminValidationError(
        message=f"OAuth scope not found: {scope_name}",
        error_code=AdminErrorCode.SCOPE_NOT_FOUND,
        details=[
            ErrorDetail(
                field="scope_name",
                code=AdminErrorCode.SCOPE_NOT_FOUND,
                message="The specified OAuth scope does not exist",
                value=scope_name,
            )
        ],
    )


def create_validation_error(field: str, message: str, value: Any = None) -> AdminValidationError:
    """Create a standardized field validation error."""
    return AdminValidationError(
        message=f"Validation failed for field '{field}': {message}",
        error_code=AdminErrorCode.FIELD_VALUE_INVALID,
        details=[
            ErrorDetail(
                field=field,
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message=message,
                value=value,
            )
        ],
    )
