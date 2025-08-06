"""
Tests for POST /admin/users/{user_id}/reset-password endpoint.

This module tests the admin password reset endpoint with comprehensive scenarios
including validation, security, temporary password generation, and session invalidation.
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
    """Create a regular user for testing password reset."""
    async with transaction_manager.transaction() as conn:
        regular_user = UserModel(
            id=uuid4(),
            username=f"testuser_{uuid4().hex[:8]}",
            email=f"testuser_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("UserTest123!"),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=True,
            is_admin=False,
        )

        user_repo = UserRepository(conn)
        return await user_repo.create(regular_user)


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


class TestAdminPasswordReset:
    """Test POST /admin/users/{user_id}/reset-password endpoint."""

    @pytest.mark.asyncio
    async def test_reset_password_success(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test successful password reset."""
        response = await test_server.client.post(
            f"/admin/users/{test_regular_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()
        assert data["user_id"] == str(test_regular_user.id)
        assert data["username"] == test_regular_user.username
        assert "temporary_password" in data
        assert data["temporary_password"] is not None
        assert len(data["temporary_password"]) >= 8
        assert data["requires_password_change"] is True
        assert "invalidated_sessions" in data
        assert data["message"] == "Password reset successfully. User must change password on next login."

        # Verify password complexity
        temp_password = data["temporary_password"]
        assert any(c.isupper() for c in temp_password)  # Uppercase
        assert any(c.islower() for c in temp_password)  # Lowercase
        assert any(c.isdigit() for c in temp_password)  # Digit
        assert any(c in "!@#$%^&*" for c in temp_password)  # Special char

    @pytest.mark.asyncio
    async def test_reset_password_with_active_sessions(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test password reset invalidates active sessions."""
        # Create active sessions for the test user
        async with transaction_manager.transaction() as conn:
            await register_admin_scopes(conn)
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            # Create multiple tokens to simulate active sessions
            for _ in range(3):
                await token_service.create_token_pair(user=test_regular_user, scope="openid profile")

            # Verify user has active sessions before reset
            active_sessions_before = await token_repo.count_active_sessions(test_regular_user.id)
            assert active_sessions_before > 0

        response = await test_server.client.post(
            f"/admin/users/{test_regular_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()
        assert data["invalidated_sessions"] == active_sessions_before
        assert data["invalidated_sessions"] > 0

        # Verify sessions are actually invalidated
        async with transaction_manager.transaction() as conn:
            token_repo = TokenRepository(conn)
            active_sessions_after = await token_repo.count_active_sessions(test_regular_user.id)
            assert active_sessions_after == 0

    @pytest.mark.asyncio
    async def test_reset_password_user_not_found(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test password reset for non-existent user."""
        fake_user_id = uuid4()
        response = await test_server.client.post(
            f"/admin/users/{fake_user_id}/reset-password",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = await response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_reset_password_insufficient_permissions(
        self,
        test_server,
        test_regular_user: UserModel,
        admin_read_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test password reset with read-only permissions."""
        response = await test_server.client.post(
            f"/admin/users/{test_regular_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        data = await response.json()
        assert "admin:users:write" in data["detail"]

    @pytest.mark.asyncio
    async def test_reset_password_unauthorized(
        self,
        test_server,
        test_regular_user: UserModel,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test password reset without authentication."""
        response = await test_server.client.post(
            f"/admin/users/{test_regular_user.id}/reset-password",
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_reset_password_regular_user_cannot_access(
        self,
        test_server,
        test_regular_user: UserModel,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test that regular users cannot access admin password reset endpoint."""
        # Create a regular user token
        async with transaction_manager.transaction() as conn:
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            token_pair = await token_service.create_token_pair(user=test_regular_user, scope="openid profile")
            regular_token = token_pair.access_token

        # Create another user to attempt password reset on
        target_user_id = uuid4()

        response = await test_server.client.post(
            f"/admin/users/{target_user_id}/reset-password",
            headers={"Authorization": f"Bearer {regular_token}"},
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        data = await response.json()
        assert "admin" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_reset_password_multiple_requests(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test multiple password reset requests generate different passwords."""
        # First reset
        response1 = await test_server.client.post(
            f"/admin/users/{test_regular_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response1.status_code == status.HTTP_200_OK
        data1 = await response1.json()
        temp_password1 = data1["temporary_password"]

        # Second reset
        response2 = await test_server.client.post(
            f"/admin/users/{test_regular_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response2.status_code == status.HTTP_200_OK
        data2 = await response2.json()
        temp_password2 = data2["temporary_password"]

        # Passwords should be different
        assert temp_password1 != temp_password2

        # Both should have proper complexity
        for temp_password in [temp_password1, temp_password2]:
            assert len(temp_password) >= 8
            assert any(c.isupper() for c in temp_password)
            assert any(c.islower() for c in temp_password)
            assert any(c.isdigit() for c in temp_password)
            assert any(c in "!@#$%^&*" for c in temp_password)

    @pytest.mark.asyncio
    async def test_reset_password_updates_user_record(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test that password reset properly updates user record."""
        # Get user details before reset
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            user_before = await user_repo.get_by_id(test_regular_user.id)
            original_password_hash = user_before.password_hash

        # Reset password
        response = await test_server.client.post(
            f"/admin/users/{test_regular_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_200_OK

        # Verify user record was updated
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            user_after = await user_repo.get_by_id(test_regular_user.id)

            # Password hash should be different
            assert user_after.password_hash != original_password_hash

            # requires_password_change should now be True
            assert user_after.requires_password_change is True

            # Other fields should remain unchanged
            assert user_after.username == test_regular_user.username
            assert user_after.email == test_regular_user.email
            assert user_after.is_active == test_regular_user.is_active
            assert user_after.is_verified == test_regular_user.is_verified
            assert user_after.is_admin == test_regular_user.is_admin

    @pytest.mark.asyncio
    async def test_reset_password_invalid_user_id_format(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test password reset with invalid UUID format."""
        response = await test_server.client.post(
            "/admin/users/not-a-uuid/reset-password",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
