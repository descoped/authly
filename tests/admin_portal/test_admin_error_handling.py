"""
Tests for Admin Error Handling Infrastructure.

This module tests the standardized error handling, validation,
and request tracing functionality for admin operations.
"""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from authly.admin.error_handler import (
    _get_admin_error_code_for_status,
    _get_status_code_for_error,
    admin_generic_exception_handler,
    admin_http_exception_handler,
    admin_operation_error_handler,
    admin_validation_error_handler,
    get_request_id,
)
from authly.admin.errors import (
    AdminErrorCode,
    AdminErrorResponse,
    AdminOperationError,
    AdminValidationError,
    ErrorDetail,
    create_last_admin_error,
    create_self_admin_revoke_error,
    create_user_not_found_error,
    create_validation_error,
)
from authly.admin.request_middleware import AdminRequestContextMiddleware, AdminRequestIDMiddleware
from authly.admin.validation import AdminClientValidation, AdminScopeValidation, AdminUserValidation
from authly.users.models import UserModel
from authly.users.repository import UserRepository


class TestAdminErrorModels:
    """Test admin error models and exceptions."""

    def test_error_detail_creation(self):
        """Test ErrorDetail model creation."""
        detail = ErrorDetail(
            field="username",
            code=AdminErrorCode.FIELD_VALUE_INVALID,
            message="Invalid username format",
            value="bad@user",
        )

        assert detail.field == "username"
        assert detail.code == AdminErrorCode.FIELD_VALUE_INVALID
        assert detail.message == "Invalid username format"
        assert detail.value == "bad@user"

    def test_admin_error_response_creation(self):
        """Test AdminErrorResponse model creation."""
        details = [
            ErrorDetail(
                field="username",
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message="Invalid username",
            )
        ]

        response = AdminErrorResponse(
            error_code=AdminErrorCode.VALIDATION_FAILED,
            message="Validation failed",
            details=details,
            timestamp=datetime.now(UTC).isoformat(),
        )

        assert response.success is False
        assert response.error_code == AdminErrorCode.VALIDATION_FAILED
        assert response.message == "Validation failed"
        assert len(response.details) == 1
        assert response.request_id is not None  # Generated automatically

    def test_admin_validation_error(self):
        """Test AdminValidationError exception."""
        details = [
            ErrorDetail(
                field="email",
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message="Invalid email format",
            )
        ]

        error = AdminValidationError(
            message="Validation failed",
            error_code=AdminErrorCode.VALIDATION_FAILED,
            details=details,
        )

        assert str(error) == "Validation failed"
        assert error.error_code == AdminErrorCode.VALIDATION_FAILED
        assert len(error.details) == 1

    def test_admin_operation_error(self):
        """Test AdminOperationError exception."""
        error = AdminOperationError(
            message="Database connection failed",
            error_code=AdminErrorCode.DATABASE_ERROR,
            debug_info={"connection": "localhost:5432"},
        )

        assert str(error) == "Database connection failed"
        assert error.error_code == AdminErrorCode.DATABASE_ERROR
        assert error.debug_info["connection"] == "localhost:5432"

    def test_convenience_error_functions(self):
        """Test convenience functions for creating common errors."""
        # Test user not found error
        user_error = create_user_not_found_error("123")
        assert user_error.error_code == AdminErrorCode.USER_NOT_FOUND
        assert "User not found: 123" in user_error.message

        # Test last admin error
        admin_error = create_last_admin_error()
        assert admin_error.error_code == AdminErrorCode.LAST_ADMIN_PROTECTION
        assert "last admin" in admin_error.message.lower()

        # Test self admin revoke error
        self_error = create_self_admin_revoke_error()
        assert self_error.error_code == AdminErrorCode.SELF_ADMIN_REVOKE_DENIED
        assert "own admin privileges" in self_error.message.lower()

        # Test validation error
        val_error = create_validation_error("username", "Too short", "ab")
        assert val_error.error_code == AdminErrorCode.FIELD_VALUE_INVALID
        assert val_error.details[0].field == "username"
        assert val_error.details[0].value == "ab"


class TestAdminErrorHandlers:
    """Test admin error handlers."""

    @pytest.fixture
    def mock_request(self):
        """Create a mock request object."""
        request = MagicMock(spec=Request)
        request.url.path = "/admin/users"
        request.method = "POST"
        request.state.request_id = "test-request-123"
        return request

    @pytest.mark.asyncio
    async def test_admin_validation_error_handler(self, mock_request):
        """Test AdminValidationError handler."""
        details = [
            ErrorDetail(
                field="username",
                code=AdminErrorCode.FIELD_VALUE_INVALID,
                message="Invalid username",
            )
        ]

        error = AdminValidationError(
            message="Validation failed",
            error_code=AdminErrorCode.VALIDATION_FAILED,
            details=details,
        )

        response = await admin_validation_error_handler(mock_request, error)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 422  # Unprocessable Entity

        # Parse response content
        content = json.loads(response.body.decode())
        assert content["success"] is False
        assert content["error_code"] == AdminErrorCode.VALIDATION_FAILED.value
        assert content["message"] == "Validation failed"
        assert content["request_id"] == "test-request-123"
        assert len(content["details"]) == 1

    @pytest.mark.asyncio
    async def test_admin_operation_error_handler(self, mock_request):
        """Test AdminOperationError handler."""
        error = AdminOperationError(
            message="Database error",
            error_code=AdminErrorCode.DATABASE_ERROR,
        )

        response = await admin_operation_error_handler(mock_request, error)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 500  # Internal Server Error

        content = json.loads(response.body.decode())
        assert content["error_code"] == AdminErrorCode.DATABASE_ERROR.value
        assert content["message"] == "Database error"

    @pytest.mark.asyncio
    async def test_admin_http_exception_handler(self, mock_request):
        """Test HTTPException handler for admin routes."""
        error = HTTPException(status_code=404, detail="Not found")

        response = await admin_http_exception_handler(mock_request, error)

        assert response.status_code == 404

        content = json.loads(response.body.decode())
        assert content["success"] is False
        assert content["message"] == "Not found"
        assert content["request_id"] == "test-request-123"

    @pytest.mark.asyncio
    async def test_admin_generic_exception_handler(self, mock_request):
        """Test generic exception handler."""
        error = ValueError("Something went wrong")

        response = await admin_generic_exception_handler(mock_request, error)

        assert response.status_code == 500

        content = json.loads(response.body.decode())
        assert content["error_code"] == AdminErrorCode.INTERNAL_ERROR.value
        assert "unexpected error" in content["message"].lower()

    def test_get_request_id(self):
        """Test request ID extraction."""
        # Test with request ID in state
        request = MagicMock()
        request.state.request_id = "existing-id"

        request_id = get_request_id(request)
        assert request_id == "existing-id"

        # Test without request ID
        request.state.request_id = None
        request_id = get_request_id(request)
        assert len(request_id) == 36  # UUID format

    def test_status_code_mapping(self):
        """Test error code to status code mapping."""
        # Test validation errors
        assert _get_status_code_for_error(AdminErrorCode.VALIDATION_FAILED) == 422
        assert _get_status_code_for_error(AdminErrorCode.FIELD_VALUE_INVALID) == 422

        # Test authorization errors
        assert _get_status_code_for_error(AdminErrorCode.UNAUTHORIZED) == 401
        assert _get_status_code_for_error(AdminErrorCode.INSUFFICIENT_PRIVILEGES) == 403

        # Test not found errors
        assert _get_status_code_for_error(AdminErrorCode.USER_NOT_FOUND) == 404

        # Test conflict errors
        assert _get_status_code_for_error(AdminErrorCode.USER_ALREADY_EXISTS) == 409

        # Test system errors
        assert _get_status_code_for_error(AdminErrorCode.INTERNAL_ERROR) == 500

    def test_admin_error_code_mapping(self):
        """Test status code to admin error code mapping."""
        assert _get_admin_error_code_for_status(401) == AdminErrorCode.UNAUTHORIZED
        assert _get_admin_error_code_for_status(403) == AdminErrorCode.INSUFFICIENT_PRIVILEGES
        assert _get_admin_error_code_for_status(404) == AdminErrorCode.USER_NOT_FOUND
        assert _get_admin_error_code_for_status(422) == AdminErrorCode.VALIDATION_FAILED
        assert _get_admin_error_code_for_status(500) == AdminErrorCode.INTERNAL_ERROR


class TestAdminRequestMiddleware:
    """Test admin request middleware."""

    @pytest.fixture
    def app(self):
        """Create test FastAPI app."""
        app = FastAPI()

        @app.get("/admin/test")
        async def test_endpoint():
            return {"message": "test"}

        @app.get("/api/test")
        async def non_admin_endpoint():
            return {"message": "non-admin"}

        return app

    @pytest.mark.asyncio
    async def test_request_id_middleware_admin_route(self, app):
        """Test request ID middleware on admin routes."""
        middleware = AdminRequestIDMiddleware(app)

        # Mock request
        mock_request = MagicMock()
        mock_request.url.path = "/admin/test"
        mock_request.method = "GET"
        mock_request.headers.get.return_value = None
        mock_request.client.host = "127.0.0.1"

        # Mock call_next
        mock_response = MagicMock()
        mock_response.headers = {}

        async def mock_call_next(request):
            return mock_response

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Check that request ID was added
        assert hasattr(mock_request.state, "request_id")
        assert "X-Request-ID" in response.headers
        assert "X-Processing-Time" in response.headers

    @pytest.mark.asyncio
    async def test_request_id_middleware_non_admin_route(self, app):
        """Test request ID middleware skips non-admin routes."""
        middleware = AdminRequestIDMiddleware(app)

        mock_request = MagicMock()
        mock_request.url.path = "/api/test"

        mock_response = MagicMock()

        async def mock_call_next(request):
            return mock_response

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should pass through without modification
        assert response == mock_response

    @pytest.mark.asyncio
    async def test_request_context_middleware(self, app):
        """Test request context middleware."""
        middleware = AdminRequestContextMiddleware(app)

        mock_request = MagicMock()
        mock_request.url.path = "/admin/users"
        mock_request.headers.get.side_effect = lambda key, default=None: {
            "authorization": "Bearer token123",
            "user-agent": "TestClient/1.0",
            "X-Forwarded-For": "192.168.1.1",
        }.get(key, default)

        async def mock_call_next(request):
            # Check that context was added
            assert request.state.is_admin_request is True
            assert request.state.admin_path == "/admin/users"
            assert request.state.has_bearer_token is True
            assert request.state.client_ip == "192.168.1.1"
            assert request.state.user_agent == "TestClient/1.0"
            return MagicMock()

        await middleware.dispatch(mock_request, mock_call_next)


class TestAdminValidation:
    """Test admin validation rules with real database integration."""

    async def create_test_user(self, conn, username="testuser", email="test@example.com"):
        """Create a test user in the database."""
        user_repository = UserRepository(conn)
        user = UserModel(
            id=uuid4(),
            username=username,
            email=email,
            password_hash="hashed_password",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_admin=False,
            is_active=True,
            is_verified=True,
        )
        return await user_repository.create(user)

    @pytest.mark.asyncio
    async def test_validate_user_creation_success(self, transaction_manager):
        """Test successful user creation validation with real database."""
        async with transaction_manager.transaction() as conn:
            admin_user_validation = AdminUserValidation(conn)

            user_data = {
                "username": "newuser",
                "email": "new@example.com",
                "password": "SecurePass123!",
            }

            requesting_admin = UserModel(
                id=uuid4(),
                username="admin",
                email="admin@example.com",
                password_hash="hash",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                is_admin=True,
                is_active=True,
                is_verified=True,
            )

            # Should not raise an exception since username and email don't exist
            await admin_user_validation.validate_user_creation(user_data, requesting_admin)

    @pytest.mark.asyncio
    async def test_validate_user_creation_missing_fields(self, transaction_manager):
        """Test user creation validation with missing fields."""
        async with transaction_manager.transaction() as conn:
            admin_user_validation = AdminUserValidation(conn)
            user_data = {}  # Missing required fields

            requesting_admin = UserModel(
                id=uuid4(),
                username="admin",
                email="admin@example.com",
                password_hash="hash",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                is_admin=True,
                is_active=True,
                is_verified=True,
            )

            with pytest.raises(AdminValidationError) as exc_info:
                await admin_user_validation.validate_user_creation(user_data, requesting_admin)

            error = exc_info.value
            assert error.error_code == AdminErrorCode.VALIDATION_FAILED
            assert len(error.details) >= 2  # username and email are required

    @pytest.mark.asyncio
    async def test_validate_user_creation_duplicate_username(self, transaction_manager):
        """Test user creation validation with duplicate username using real database."""
        async with transaction_manager.transaction() as conn:
            # Create existing user
            await self.create_test_user(conn, username="existinguser", email="existing@example.com")

            admin_user_validation = AdminUserValidation(conn)

            user_data = {
                "username": "existinguser",  # Duplicate username
                "email": "new@example.com",
            }

            requesting_admin = UserModel(
                id=uuid4(),
                username="admin",
                email="admin@example.com",
                password_hash="hash",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                is_admin=True,
                is_active=True,
                is_verified=True,
            )

            with pytest.raises(AdminValidationError) as exc_info:
                await admin_user_validation.validate_user_creation(user_data, requesting_admin)

            error = exc_info.value
            assert any(detail.code == AdminErrorCode.USER_ALREADY_EXISTS for detail in error.details)

    @pytest.mark.asyncio
    async def test_validate_username_format(self, transaction_manager):
        """Test username format validation."""
        async with transaction_manager.transaction() as conn:
            admin_user_validation = AdminUserValidation(conn)

            # Valid usernames
            assert admin_user_validation._validate_username_format("validuser") is None
            assert admin_user_validation._validate_username_format("user_123") is None

            # Invalid usernames
            assert admin_user_validation._validate_username_format("ab") is not None  # Too short
            assert admin_user_validation._validate_username_format("user@name") is not None  # Invalid chars
            assert admin_user_validation._validate_username_format("") is not None  # Empty

    @pytest.mark.asyncio
    async def test_validate_email_format(self, transaction_manager):
        """Test email format validation."""
        async with transaction_manager.transaction() as conn:
            admin_user_validation = AdminUserValidation(conn)

            # Valid emails
            assert admin_user_validation._validate_email_format("user@example.com") is None
            assert admin_user_validation._validate_email_format("test.email+tag@domain.co.uk") is None

            # Invalid emails
            assert admin_user_validation._validate_email_format("invalid-email") is not None
            assert admin_user_validation._validate_email_format("@example.com") is not None
            assert admin_user_validation._validate_email_format("user@") is not None

    @pytest.mark.asyncio
    async def test_validate_password_strength(self, transaction_manager):
        """Test password strength validation."""
        async with transaction_manager.transaction() as conn:
            admin_user_validation = AdminUserValidation(conn)

            # Strong password
            errors = admin_user_validation._validate_password_strength("SecurePass123!")
            assert len(errors) == 0

            # Weak passwords
            weak_errors = admin_user_validation._validate_password_strength("weak")
            assert len(weak_errors) > 0

            no_upper_errors = admin_user_validation._validate_password_strength("password123!")
            assert any("uppercase" in error.message for error in no_upper_errors)

    def test_client_validation(self):
        """Test client validation rules."""
        validation = AdminClientValidation()

        # Valid client data
        valid_data = {
            "client_name": "Test Client",
            "client_type": "confidential",
            "redirect_uris": ["https://example.com/callback"],
        }

        # Should not raise
        validation.validate_client_creation(valid_data)

        # Invalid client data - missing name
        invalid_data = {
            "client_type": "public",
        }

        with pytest.raises(AdminValidationError):
            validation.validate_client_creation(invalid_data)

    def test_scope_validation(self):
        """Test scope validation rules."""
        validation = AdminScopeValidation()

        # Valid scope data
        valid_data = {
            "scope_name": "read:users",
            "description": "Read user information",
        }

        # Should not raise
        validation.validate_scope_creation(valid_data)

        # Invalid scope data - bad name format
        invalid_data = {
            "scope_name": "invalid scope name!",
        }

        with pytest.raises(AdminValidationError):
            validation.validate_scope_creation(invalid_data)
