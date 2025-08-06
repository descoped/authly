"""
Tests for DELETE /admin/users/{user_id} endpoint.

This module tests the admin user deletion endpoint with comprehensive scenarios
including cascade deletion, permissions, and business rule validation.
"""

import logging
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import status
from psycopg_toolkit import TransactionManager

from authly.auth.core import get_password_hash
from authly.bootstrap.admin_seeding import register_admin_scopes
from authly.core.resource_manager import AuthlyResourceManager
from authly.tokens.repository import TokenRepository
from authly.tokens.service import TokenService
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


@pytest.fixture()
async def test_admin_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a test admin user."""
    async with transaction_manager.transaction() as conn:
        admin_user = UserModel(
            id=uuid4(),
            username=f"testadmin_{uuid4().hex[:8]}",
            email=f"testadmin_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("AdminTest123!"),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=True,
            is_admin=True,
        )

        user_repo = UserRepository(conn)
        return await user_repo.create(admin_user)


@pytest.fixture()
async def test_regular_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a regular user for testing."""
    async with transaction_manager.transaction() as conn:
        regular_user = UserModel(
            id=uuid4(),
            username=f"testuser_{uuid4().hex[:8]}",
            email=f"testuser_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("UserTest123!"),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=False,
            is_admin=False,
            given_name="John",
            family_name="Doe",
        )

        user_repo = UserRepository(conn)
        return await user_repo.create(regular_user)


@pytest.fixture()
async def second_admin_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a second admin user for testing scenarios that require multiple admins."""
    async with transaction_manager.transaction() as conn:
        admin_user = UserModel(
            id=uuid4(),
            username=f"secondadmin_{uuid4().hex[:8]}",
            email=f"secondadmin_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("Admin2Test123!"),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=True,
            is_admin=True,
        )

        user_repo = UserRepository(conn)
        return await user_repo.create(admin_user)


@pytest.fixture()
async def admin_write_token(
    initialize_authly: AuthlyResourceManager, test_admin_user: UserModel, transaction_manager: TransactionManager
) -> str:
    """Create admin token with user write and read scopes."""
    async with transaction_manager.transaction() as conn:
        await register_admin_scopes(conn)

        config = initialize_authly.get_config()
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo, config, None)

        token_pair = await token_service.create_token_pair(
            user=test_admin_user, scope="admin:users:write admin:users:read"
        )

        return token_pair.access_token


@pytest.fixture()
async def admin_read_token(
    initialize_authly: AuthlyResourceManager, test_admin_user: UserModel, transaction_manager: TransactionManager
) -> str:
    """Create admin token with user read scope only."""
    async with transaction_manager.transaction() as conn:
        await register_admin_scopes(conn)

        config = initialize_authly.get_config()
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo, config, None)

        token_pair = await token_service.create_token_pair(user=test_admin_user, scope="admin:users:read")

        return token_pair.access_token


@pytest.fixture()
async def user_with_tokens_and_codes(
    transaction_manager: TransactionManager,
    initialize_authly: AuthlyResourceManager,
) -> tuple[UserModel, dict]:
    """Create a user with tokens and authorization codes for cascade testing."""
    async with transaction_manager.transaction() as conn:
        # Create user
        user = UserModel(
            id=uuid4(),
            username=f"userwithtokens_{uuid4().hex[:8]}",
            email=f"userwithtokens_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("UserTokens123!"),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=True,
            is_admin=False,
        )

        user_repo = UserRepository(conn)
        created_user = await user_repo.create(user)

        # Create tokens
        config = initialize_authly.get_config()
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo, config, None)

        # Create multiple token pairs
        token_pair1 = await token_service.create_token_pair(user=created_user, scope="openid profile")
        token_pair2 = await token_service.create_token_pair(user=created_user, scope="openid email")

        # Count initial data
        active_tokens = await token_repo.count_user_valid_tokens(created_user.id)

        return created_user, {
            "active_tokens": active_tokens,
            "token_pairs": [token_pair1, token_pair2],
        }


class TestAdminUserDelete:
    """Test DELETE /admin/users/{user_id} endpoint."""

    @pytest.mark.asyncio
    async def test_delete_user_successful(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test successful user deletion."""
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify user is deleted
        response = await test_server.client.get(
            f"/admin/users/{test_regular_user.id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_delete_user_with_cascade_cleanup(
        self,
        test_server,
        test_admin_user: UserModel,
        user_with_tokens_and_codes: tuple[UserModel, dict],
        admin_write_token: str,
        transaction_manager: TransactionManager,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test that deleting a user cascades to cleanup tokens and auth codes."""
        user, initial_data = user_with_tokens_and_codes

        # Verify user has tokens before deletion
        assert initial_data["active_tokens"] > 0, "User should have active tokens before deletion"

        # Delete the user
        response = await test_server.client.delete(
            f"/admin/users/{user.id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify cascade cleanup - user should be deleted
        response = await test_server.client.get(
            f"/admin/users/{user.id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_cannot_delete_last_admin(
        self,
        test_server,
        test_admin_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test that the last admin user cannot be deleted."""
        # Ensure we have only one admin user by cleaning up any extra admins
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)

            # Get all admin users
            admin_users = await user_repo.get_filtered_paginated(filters={"is_admin": True}, skip=0, limit=100)

            # Delete all admin users except our test admin user
            for admin in admin_users:
                if admin.id != test_admin_user.id:
                    await user_repo.delete(admin.id)

        # Now try to delete the only admin user
        response = await test_server.client.delete(
            f"/admin/users/{test_admin_user.id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        data = await response.json()
        assert "last admin" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_can_delete_admin_when_others_exist(
        self,
        test_server,
        test_admin_user: UserModel,
        second_admin_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test that an admin can be deleted when other admins exist."""
        # Delete the second admin (not the last one)
        response = await test_server.client.delete(
            f"/admin/users/{second_admin_user.id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify the admin is deleted
        response = await test_server.client.get(
            f"/admin/users/{second_admin_user.id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_delete_nonexistent_user(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test deleting a non-existent user."""
        non_existent_id = uuid4()

        response = await test_server.client.delete(
            f"/admin/users/{non_existent_id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

        data = await response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_delete_with_read_only_scope(
        self,
        test_server,
        test_regular_user: UserModel,
        admin_read_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test that read-only scope cannot delete users."""
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}",
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

        data = await response.json()
        assert "admin:users:write" in data["detail"]

    @pytest.mark.asyncio
    async def test_delete_unauthorized(
        self,
        test_server,
        test_regular_user: UserModel,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test deleting without authentication."""
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}",
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_regular_user_cannot_delete(
        self,
        test_server,
        test_regular_user: UserModel,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test that regular users cannot use the admin delete endpoint."""
        # Create a regular user token
        async with transaction_manager.transaction() as conn:
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            token_pair = await token_service.create_token_pair(user=test_regular_user, scope="openid profile")
            regular_token = token_pair.access_token

        # Try to delete using regular user token
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}",
            headers={"Authorization": f"Bearer {regular_token}"},
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

        data = await response.json()
        assert "admin" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_delete_user_idempotent(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test that deleting an already deleted user returns 404."""
        # First deletion should succeed
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Second deletion should return 404
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
