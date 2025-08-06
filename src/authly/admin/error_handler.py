"""
Admin Error Handler for Authly.

This module provides centralized error handling for admin operations,
converting exceptions to standardized error responses with proper logging
and request tracing.
"""

import logging
import traceback
from datetime import UTC, datetime

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from authly.admin.errors import (
    AdminErrorCode,
    AdminErrorResponse,
    AdminOperationError,
    AdminValidationError,
    ErrorDetail,
)

logger = logging.getLogger(__name__)


def get_request_id(request: Request) -> str:
    """
    Extract request ID from request.

    Args:
        request: FastAPI request object

    Returns:
        Request ID string
    """
    # Try to get request ID from headers (set by middleware)
    request_id = getattr(request.state, "request_id", None)
    if request_id:
        return request_id

    # Fallback to generating a new request ID
    import uuid

    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    return request_id


def is_development_mode() -> bool:
    """
    Check if application is running in development mode.

    Returns:
        True if in development mode
    """
    # This could be enhanced to check environment variables or config
    import os

    return os.getenv("AUTHLY_ENV", "production").lower() in ("development", "dev", "debug")


async def admin_validation_error_handler(request: Request, exc: AdminValidationError) -> JSONResponse:
    """
    Handle AdminValidationError exceptions.

    Args:
        request: FastAPI request object
        exc: AdminValidationError exception

    Returns:
        JSONResponse with standardized error format
    """
    request_id = get_request_id(request)

    # Log the validation error with context
    logger.warning(
        f"Admin validation error [request_id={request_id}]: {exc.error_code.value} - {exc.message}",
        extra={
            "request_id": request_id,
            "error_code": exc.error_code.value,
            "url": str(request.url),
            "method": request.method,
        },
    )

    # Create standardized error response
    error_response = AdminErrorResponse(
        error_code=exc.error_code,
        message=exc.message,
        details=exc.details,
        request_id=request_id,
        timestamp=datetime.now(UTC).isoformat(),
        debug_info=exc.debug_info if is_development_mode() else None,
    )

    # Determine HTTP status code based on error code
    status_code = _get_status_code_for_error(exc.error_code)

    return JSONResponse(
        status_code=status_code,
        content=error_response.model_dump(exclude_none=True),
    )


async def admin_operation_error_handler(request: Request, exc: AdminOperationError) -> JSONResponse:
    """
    Handle AdminOperationError exceptions.

    Args:
        request: FastAPI request object
        exc: AdminOperationError exception

    Returns:
        JSONResponse with standardized error format
    """
    request_id = get_request_id(request)

    # Log the operation error with context
    logger.error(
        f"Admin operation error [request_id={request_id}]: {exc.error_code.value} - {exc.message}",
        extra={
            "request_id": request_id,
            "error_code": exc.error_code.value,
            "url": str(request.url),
            "method": request.method,
        },
    )

    # Create standardized error response
    error_response = AdminErrorResponse(
        error_code=exc.error_code,
        message=exc.message,
        request_id=request_id,
        timestamp=datetime.now(UTC).isoformat(),
        debug_info=exc.debug_info if is_development_mode() else None,
    )

    # Determine HTTP status code based on error code
    status_code = _get_status_code_for_error(exc.error_code)

    return JSONResponse(
        status_code=status_code,
        content=error_response.model_dump(exclude_none=True),
    )


async def admin_http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """
    Handle HTTPException for admin endpoints.

    Args:
        request: FastAPI request object
        exc: HTTPException

    Returns:
        JSONResponse with standardized error format
    """
    request_id = get_request_id(request)

    # Map HTTP status codes to admin error codes
    error_code = _get_admin_error_code_for_status(exc.status_code)

    # Log the HTTP exception
    logger.warning(
        f"Admin HTTP exception [request_id={request_id}]: {exc.status_code} - {exc.detail}",
        extra={
            "request_id": request_id,
            "status_code": exc.status_code,
            "url": str(request.url),
            "method": request.method,
        },
    )

    # Create standardized error response
    error_response = AdminErrorResponse(
        error_code=error_code,
        message=str(exc.detail),
        request_id=request_id,
        timestamp=datetime.now(UTC).isoformat(),
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.model_dump(exclude_none=True),
    )


async def admin_validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Handle Pydantic validation errors for admin endpoints.

    Args:
        request: FastAPI request object
        exc: RequestValidationError

    Returns:
        JSONResponse with standardized error format
    """
    request_id = get_request_id(request)

    # Convert Pydantic validation errors to our error details format
    error_details = []
    for error in exc.errors():
        field_name = ".".join(str(loc) for loc in error["loc"][1:])  # Skip 'body' prefix
        error_details.append(
            ErrorDetail(
                field=field_name if field_name else None,
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message=error["msg"],
                value=error.get("input"),
            )
        )

    # Log the validation error
    logger.warning(
        f"Admin request validation error [request_id={request_id}]: {len(error_details)} validation errors",
        extra={
            "request_id": request_id,
            "url": str(request.url),
            "method": request.method,
            "validation_errors": len(error_details),
        },
    )

    # Create standardized error response
    error_response = AdminErrorResponse(
        error_code=AdminErrorCode.VALIDATION_FAILED,
        message="Request validation failed",
        details=error_details,
        request_id=request_id,
        timestamp=datetime.now(UTC).isoformat(),
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_response.model_dump(exclude_none=True),
    )


async def admin_generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle unexpected exceptions for admin endpoints.

    Args:
        request: FastAPI request object
        exc: Generic exception

    Returns:
        JSONResponse with standardized error format
    """
    request_id = get_request_id(request)

    # Log the unexpected exception with full traceback
    logger.error(
        f"Unexpected admin error [request_id={request_id}]: {type(exc).__name__}: {exc!s}",
        extra={
            "request_id": request_id,
            "exception_type": type(exc).__name__,
            "url": str(request.url),
            "method": request.method,
        },
        exc_info=True,  # Include full traceback in logs
    )

    # Create standardized error response
    error_response = AdminErrorResponse(
        error_code=AdminErrorCode.INTERNAL_ERROR,
        message="An unexpected error occurred while processing your request",
        request_id=request_id,
        timestamp=datetime.now(UTC).isoformat(),
        debug_info={
            "exception_type": type(exc).__name__,
            "traceback": traceback.format_exc(),
        }
        if is_development_mode()
        else None,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump(exclude_none=True),
    )


def _get_status_code_for_error(error_code: AdminErrorCode) -> int:
    """
    Map admin error codes to HTTP status codes.

    Args:
        error_code: AdminErrorCode

    Returns:
        HTTP status code
    """
    error_code_to_status = {
        # Authentication/Authorization errors
        AdminErrorCode.UNAUTHORIZED: status.HTTP_401_UNAUTHORIZED,
        AdminErrorCode.INSUFFICIENT_PRIVILEGES: status.HTTP_403_FORBIDDEN,
        AdminErrorCode.TOKEN_EXPIRED: status.HTTP_401_UNAUTHORIZED,
        AdminErrorCode.TOKEN_INVALID: status.HTTP_401_UNAUTHORIZED,
        # Not found errors
        AdminErrorCode.USER_NOT_FOUND: status.HTTP_404_NOT_FOUND,
        AdminErrorCode.CLIENT_NOT_FOUND: status.HTTP_404_NOT_FOUND,
        AdminErrorCode.SCOPE_NOT_FOUND: status.HTTP_404_NOT_FOUND,
        # Conflict errors
        AdminErrorCode.USER_ALREADY_EXISTS: status.HTTP_409_CONFLICT,
        AdminErrorCode.CLIENT_ALREADY_EXISTS: status.HTTP_409_CONFLICT,
        AdminErrorCode.SCOPE_ALREADY_EXISTS: status.HTTP_409_CONFLICT,
        AdminErrorCode.RESOURCE_CONFLICT: status.HTTP_409_CONFLICT,
        # Business rule violations
        AdminErrorCode.USER_CANNOT_BE_DELETED: status.HTTP_422_UNPROCESSABLE_ENTITY,
        AdminErrorCode.USER_CANNOT_BE_MODIFIED: status.HTTP_422_UNPROCESSABLE_ENTITY,
        AdminErrorCode.LAST_ADMIN_PROTECTION: status.HTTP_422_UNPROCESSABLE_ENTITY,
        AdminErrorCode.SELF_ADMIN_REVOKE_DENIED: status.HTTP_422_UNPROCESSABLE_ENTITY,
        AdminErrorCode.CLIENT_IN_USE: status.HTTP_422_UNPROCESSABLE_ENTITY,
        AdminErrorCode.SCOPE_IN_USE: status.HTTP_422_UNPROCESSABLE_ENTITY,
        AdminErrorCode.SCOPE_REQUIRED: status.HTTP_422_UNPROCESSABLE_ENTITY,
        AdminErrorCode.OPERATION_NOT_PERMITTED: status.HTTP_422_UNPROCESSABLE_ENTITY,
        # Validation errors
        AdminErrorCode.VALIDATION_FAILED: status.HTTP_422_UNPROCESSABLE_ENTITY,
        AdminErrorCode.INVALID_INPUT: status.HTTP_400_BAD_REQUEST,
        AdminErrorCode.MISSING_REQUIRED_FIELD: status.HTTP_400_BAD_REQUEST,
        AdminErrorCode.FIELD_VALUE_INVALID: status.HTTP_422_UNPROCESSABLE_ENTITY,
        AdminErrorCode.CLIENT_INVALID_CONFIG: status.HTTP_422_UNPROCESSABLE_ENTITY,
        # Rate limiting
        AdminErrorCode.RATE_LIMIT_EXCEEDED: status.HTTP_429_TOO_MANY_REQUESTS,
        # System errors
        AdminErrorCode.INTERNAL_ERROR: status.HTTP_500_INTERNAL_SERVER_ERROR,
        AdminErrorCode.DATABASE_ERROR: status.HTTP_500_INTERNAL_SERVER_ERROR,
        AdminErrorCode.EXTERNAL_SERVICE_ERROR: status.HTTP_502_BAD_GATEWAY,
        AdminErrorCode.OPERATION_FAILED: status.HTTP_500_INTERNAL_SERVER_ERROR,
    }

    return error_code_to_status.get(error_code, status.HTTP_500_INTERNAL_SERVER_ERROR)


def _get_admin_error_code_for_status(status_code: int) -> AdminErrorCode:
    """
    Map HTTP status codes to admin error codes.

    Args:
        status_code: HTTP status code

    Returns:
        AdminErrorCode
    """
    status_to_error_code = {
        status.HTTP_401_UNAUTHORIZED: AdminErrorCode.UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN: AdminErrorCode.INSUFFICIENT_PRIVILEGES,
        status.HTTP_404_NOT_FOUND: AdminErrorCode.USER_NOT_FOUND,  # Generic not found
        status.HTTP_409_CONFLICT: AdminErrorCode.RESOURCE_CONFLICT,
        status.HTTP_422_UNPROCESSABLE_ENTITY: AdminErrorCode.VALIDATION_FAILED,
        status.HTTP_429_TOO_MANY_REQUESTS: AdminErrorCode.RATE_LIMIT_EXCEEDED,
        status.HTTP_500_INTERNAL_SERVER_ERROR: AdminErrorCode.INTERNAL_ERROR,
    }

    return status_to_error_code.get(status_code, AdminErrorCode.INTERNAL_ERROR)


def register_admin_error_handlers(app) -> None:
    """
    Register all admin error handlers with the FastAPI application.

    Args:
        app: FastAPI application instance
    """
    # Register custom admin exception handlers
    app.add_exception_handler(AdminValidationError, admin_validation_error_handler)
    app.add_exception_handler(AdminOperationError, admin_operation_error_handler)

    # Register handlers for standard exceptions on admin routes
    # Note: These will only apply to routes that raise these exceptions
    # We might need middleware to scope this to admin routes only

    logger.info("Admin error handlers registered successfully")
