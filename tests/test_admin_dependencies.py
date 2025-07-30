"""
Tests for Admin Authentication Dependencies.

This module tests the admin authentication and authorization logic,
including the two-layer security model (intrinsic authority + scoped permissions).
"""

import logging
import random
import string
from datetime import datetime, timezone
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt
from psycopg_toolkit import TransactionManager

from authly.api.admin_dependencies import (
    ADMIN_SCOPES,
    get_admin_scopes,
    require_admin_scope,
    require_admin_user,
    validate_admin_scopes,
)
from authly.auth.core import get_password_hash
from authly.bootstrap.admin_seeding import bootstrap_admin_system
from authly.core.resource_manager import AuthlyResourceManager
from authly.tokens import TokenRepository, TokenService
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


def generate_random_identifier(length: int = 10) -> str:
    """Generate a random string for testing."""
    return "".join(random.choices(string.ascii_lowercase, k=length))


@pytest.fixture()
async def test_admin_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a test admin user with proper privileges."""
    async with transaction_manager.transaction() as conn:
        identifier = generate_random_identifier()
        admin_user = UserModel(
            id=uuid4(),
            username=f"admin_{identifier}",
            email=f"admin_{identifier}@example.com",
            password_hash=get_password_hash("AdminTest123!"),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=True,
            is_admin=True,  # Critical: Admin privileges
        )

        user_repo = UserRepository(conn)
        created_user = await user_repo.create(admin_user)

        return created_user


@pytest.fixture()
async def test_regular_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a test regular user without admin privileges."""
    async with transaction_manager.transaction() as conn:
        identifier = generate_random_identifier()
        regular_user = UserModel(
            id=uuid4(),
            username=f"user_{identifier}",
            email=f"user_{identifier}@example.com",
            password_hash=get_password_hash("UserTest123!"),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=True,
            is_admin=False,  # No admin privileges
        )

        user_repo = UserRepository(conn)
        created_user = await user_repo.create(regular_user)

        return created_user


@pytest.fixture()
async def admin_token_with_all_scopes(
    initialize_authly: AuthlyResourceManager, test_admin_user: UserModel, transaction_manager: TransactionManager
) -> str:
    """Create admin token with all admin scopes."""
    async with transaction_manager.transaction() as conn:
        # Only register admin scopes, don't create admin user (avoid conflict with bootstrap tests)
        from authly.bootstrap.admin_seeding import register_admin_scopes

        await register_admin_scopes(conn)

        config = initialize_authly.get_config()
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo, config, None)
        all_admin_scopes = list(ADMIN_SCOPES.keys())

        token_pair = await token_service.create_token_pair(user=test_admin_user, scope=" ".join(all_admin_scopes))

        return token_pair.access_token


@pytest.fixture()
async def admin_token_limited_scopes(
    initialize_authly: AuthlyResourceManager, test_admin_user: UserModel, transaction_manager: TransactionManager
) -> str:
    """Create admin token with limited admin scopes."""
    async with transaction_manager.transaction() as conn:
        # Only register admin scopes, don't create admin user (avoid conflict with bootstrap tests)
        from authly.bootstrap.admin_seeding import register_admin_scopes

        await register_admin_scopes(conn)

        config = initialize_authly.get_config()
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo, config, None)

        limited_scopes = ["admin:clients:read", "admin:scopes:read"]

        token_pair = await token_service.create_token_pair(user=test_admin_user, scope=" ".join(limited_scopes))

        return token_pair.access_token


@pytest.fixture()
async def regular_user_token(
    initialize_authly: AuthlyResourceManager, test_regular_user: UserModel, transaction_manager: TransactionManager
) -> str:
    """Create token for regular user without admin scopes."""
    async with transaction_manager.transaction() as conn:
        config = initialize_authly.get_config()
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo, config, None)

        token_pair = await token_service.create_token_pair(
            user=test_regular_user,
            scope="read write",  # Regular scopes, no admin scopes
        )

        return token_pair.access_token


class TestRequireAdminUser:
    """Test the require_admin_user dependency."""

    @pytest.mark.asyncio
    async def test_require_admin_user_success(self, test_admin_user: UserModel):
        """Test require_admin_user with valid admin user."""
        result = await require_admin_user(current_user=test_admin_user)

        assert result == test_admin_user
        assert result.is_admin is True

    @pytest.mark.asyncio
    async def test_require_admin_user_failure_non_admin(self, test_regular_user: UserModel):
        """Test require_admin_user with non-admin user."""
        with pytest.raises(HTTPException) as exc_info:
            await require_admin_user(current_user=test_regular_user)

        assert exc_info.value.status_code == 403
        assert "Administrative privileges required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_admin_user_inactive_admin(self, transaction_manager: TransactionManager):
        """Test require_admin_user with inactive admin user."""
        async with transaction_manager.transaction() as conn:
            identifier = generate_random_identifier()
            inactive_admin = UserModel(
                id=uuid4(),
                username=f"inactive_admin_{identifier}",
                email=f"inactive_admin_{identifier}@example.com",
                password_hash=get_password_hash("AdminTest123!"),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                is_active=False,  # Inactive
                is_verified=True,
                is_admin=True,
            )

            user_repo = UserRepository(conn)
            created_user = await user_repo.create(inactive_admin)

            # Should still pass require_admin_user since it only checks is_admin flag
            # The is_active check is handled by other dependencies in the chain
            result = await require_admin_user(current_user=created_user)
            assert result == created_user


class TestRequireAdminScope:
    """Test the require_admin_scope dependency factory."""

    @pytest.mark.asyncio
    async def test_require_admin_scope_success(
        self, test_admin_user: UserModel, admin_token_with_all_scopes: str, initialize_authly: AuthlyResourceManager
    ):
        """Test require_admin_scope with valid admin and correct scope."""
        # Create the scope dependency
        require_clients_write = require_admin_scope("admin:clients:write")

        # Create mock credentials
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=admin_token_with_all_scopes)

        # Call the dependency with actual config
        config = initialize_authly.get_config()
        result = await require_clients_write(admin_user=test_admin_user, credentials=credentials, config=config)

        assert result == test_admin_user

    @pytest.mark.asyncio
    async def test_require_admin_scope_missing_scope(
        self, test_admin_user: UserModel, admin_token_limited_scopes: str, initialize_authly: AuthlyResourceManager
    ):
        """Test require_admin_scope with admin user but missing required scope."""
        # Create dependency that requires write scope
        require_clients_write = require_admin_scope("admin:clients:write")

        # Use token with only read scopes
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=admin_token_limited_scopes)

        with pytest.raises(HTTPException) as exc_info:
            config = initialize_authly.get_config()
            await require_clients_write(admin_user=test_admin_user, credentials=credentials, config=config)

        assert exc_info.value.status_code == 403
        assert "Missing required admin scope: admin:clients:write" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_admin_scope_invalid_token(
        self, test_admin_user: UserModel, initialize_authly: AuthlyResourceManager
    ):
        """Test require_admin_scope with invalid JWT token."""
        require_clients_read = require_admin_scope("admin:clients:read")

        # Use invalid token
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid_jwt_token")

        with pytest.raises(HTTPException) as exc_info:
            config = initialize_authly.get_config()
            await require_clients_read(admin_user=test_admin_user, credentials=credentials, config=config)

        assert exc_info.value.status_code == 401
        assert "Invalid authentication token" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_admin_scope_unknown_scope(
        self, test_admin_user: UserModel, admin_token_with_all_scopes: str, initialize_authly: AuthlyResourceManager
    ):
        """Test require_admin_scope with unknown scope name."""
        # Try to create dependency with unknown scope
        require_unknown_scope = require_admin_scope("admin:unknown:scope")

        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=admin_token_with_all_scopes)

        with pytest.raises(HTTPException) as exc_info:
            config = initialize_authly.get_config()
            await require_unknown_scope(admin_user=test_admin_user, credentials=credentials, config=config)

        assert exc_info.value.status_code == 500
        assert "Unknown admin scope: admin:unknown:scope" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_admin_scope_regular_user_token(
        self,
        test_admin_user: UserModel,  # Admin user but wrong token
        regular_user_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test require_admin_scope with admin user but regular user token."""
        require_clients_read = require_admin_scope("admin:clients:read")

        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=regular_user_token)

        with pytest.raises(HTTPException) as exc_info:
            config = initialize_authly.get_config()
            await require_clients_read(admin_user=test_admin_user, credentials=credentials, config=config)

        assert exc_info.value.status_code == 403
        assert "Missing required admin scope" in exc_info.value.detail


class TestAdminScopeUtilities:
    """Test admin scope utility functions."""

    @pytest.mark.asyncio
    async def test_get_admin_scopes(self):
        """Test getting all admin scopes."""
        scopes = await get_admin_scopes()

        assert isinstance(scopes, dict)
        assert len(scopes) == len(ADMIN_SCOPES)

        # Verify all expected scopes are present
        expected_scopes = {
            "admin:clients:read",
            "admin:clients:write",
            "admin:scopes:read",
            "admin:scopes:write",
            "admin:users:read",
            "admin:users:write",
            "admin:system:read",
            "admin:system:write",
        }

        assert set(scopes.keys()) == expected_scopes

        # Verify all scopes have descriptions
        for scope_name, description in scopes.items():
            assert isinstance(description, str)
            assert len(description) > 0

    @pytest.mark.asyncio
    async def test_validate_admin_scopes_success(self):
        """Test validating valid admin scopes."""
        valid_scopes = ["admin:clients:read", "admin:scopes:write"]

        result = await validate_admin_scopes(valid_scopes)
        assert result == valid_scopes

    @pytest.mark.asyncio
    async def test_validate_admin_scopes_invalid(self):
        """Test validating invalid admin scopes."""
        invalid_scopes = ["admin:clients:read", "invalid:scope", "admin:unknown:action"]

        with pytest.raises(HTTPException) as exc_info:
            await validate_admin_scopes(invalid_scopes)

        assert exc_info.value.status_code == 400
        assert "Invalid admin scopes" in exc_info.value.detail
        assert "invalid:scope" in exc_info.value.detail
        assert "admin:unknown:action" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_validate_admin_scopes_empty_list(self):
        """Test validating empty scope list."""
        result = await validate_admin_scopes([])
        assert result == []

    @pytest.mark.asyncio
    async def test_validate_admin_scopes_all_valid(self):
        """Test validating all defined admin scopes."""
        all_scopes = list(ADMIN_SCOPES.keys())

        result = await validate_admin_scopes(all_scopes)
        assert result == all_scopes


class TestConvenienceDependencies:
    """Test convenience dependencies for common admin operations."""

    @pytest.mark.asyncio
    async def test_convenience_dependencies_import(self):
        """Test that all convenience dependencies can be imported."""
        from authly.api.admin_dependencies import (
            require_admin_client_read,
            require_admin_client_write,
            require_admin_scope_read,
            require_admin_scope_write,
            require_admin_system_read,
            require_admin_system_write,
            require_admin_user_read,
            require_admin_user_write,
        )

        # Verify they are callable (dependency functions)
        assert callable(require_admin_client_read)
        assert callable(require_admin_client_write)
        assert callable(require_admin_scope_read)
        assert callable(require_admin_scope_write)
        assert callable(require_admin_user_read)
        assert callable(require_admin_user_write)
        assert callable(require_admin_system_read)
        assert callable(require_admin_system_write)


class TestTwoLayerSecurityModel:
    """Test the two-layer security model integration."""

    @pytest.mark.asyncio
    async def test_two_layer_security_both_checks_pass(
        self, test_admin_user: UserModel, admin_token_with_all_scopes: str, initialize_authly: AuthlyResourceManager
    ):
        """Test two-layer security where both intrinsic authority and scopes pass."""
        # First layer: intrinsic authority
        admin_user_result = await require_admin_user(current_user=test_admin_user)
        assert admin_user_result.is_admin is True

        # Second layer: scoped permissions
        require_clients_write = require_admin_scope("admin:clients:write")
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=admin_token_with_all_scopes)

        config = initialize_authly.get_config()
        scope_result = await require_clients_write(admin_user=admin_user_result, credentials=credentials, config=config)

        assert scope_result == test_admin_user

    @pytest.mark.asyncio
    async def test_two_layer_security_first_layer_fails(self, test_regular_user: UserModel, regular_user_token: str):
        """Test two-layer security where first layer (intrinsic authority) fails."""
        # First layer should fail for non-admin user
        with pytest.raises(HTTPException) as exc_info:
            await require_admin_user(current_user=test_regular_user)

        assert exc_info.value.status_code == 403
        assert "Administrative privileges required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_two_layer_security_second_layer_fails(
        self, test_admin_user: UserModel, admin_token_limited_scopes: str, initialize_authly: AuthlyResourceManager
    ):
        """Test two-layer security where second layer (scoped permissions) fails."""
        # First layer: should pass
        admin_user_result = await require_admin_user(current_user=test_admin_user)
        assert admin_user_result.is_admin is True

        # Second layer: should fail due to missing scope
        require_clients_write = require_admin_scope("admin:clients:write")
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=admin_token_limited_scopes,  # Only has read scopes
        )

        with pytest.raises(HTTPException) as exc_info:
            config = initialize_authly.get_config()
            await require_clients_write(admin_user=admin_user_result, credentials=credentials, config=config)

        assert exc_info.value.status_code == 403
        assert "Missing required admin scope" in exc_info.value.detail
