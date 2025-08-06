"""
Tests for admin session management endpoints.

This module tests the admin session management endpoints with comprehensive scenarios
including session listing, pagination, revocation (all and specific), validation, and permissions.
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
    """Create a regular user for testing session management."""
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


class TestAdminSessionManagement:
    """Test admin session management endpoints."""

    @pytest.mark.asyncio
    async def test_get_user_sessions_empty(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_read_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test getting sessions for user with no sessions."""
        response = await test_server.client.get(
            f"/admin/users/{test_regular_user.id}/sessions",
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()
        assert data["sessions"] == []
        assert data["total_count"] == 0
        assert data["active_count"] == 0
        assert data["page_info"]["total_pages"] == 0

    @pytest.mark.asyncio
    async def test_get_user_sessions_with_active_sessions(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_read_token: str,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test getting sessions for user with active sessions."""
        # Create active sessions for the test user
        async with transaction_manager.transaction() as conn:
            await register_admin_scopes(conn)
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            # Create multiple token pairs (access + refresh)
            session_ids = []
            for _ in range(3):
                await token_service.create_token_pair(user=test_regular_user, scope="openid profile")
                # Get the session IDs from the token repository
                tokens = await token_repo.get_user_sessions(test_regular_user.id, include_inactive=False)
                if tokens:
                    session_ids.extend([token.id for token in tokens if token.id not in session_ids])

        response = await test_server.client.get(
            f"/admin/users/{test_regular_user.id}/sessions",
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()
        assert len(data["sessions"]) > 0
        assert data["total_count"] > 0
        assert data["active_count"] > 0

        # Verify session structure
        session = data["sessions"][0]
        assert "session_id" in session
        assert "token_jti" in session
        assert "token_type" in session
        assert "created_at" in session
        assert "expires_at" in session
        assert "is_active" in session
        assert "is_expired" in session
        assert "is_invalidated" in session

    @pytest.mark.asyncio
    async def test_get_user_sessions_pagination(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_read_token: str,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test session listing with pagination."""
        # Create several sessions
        async with transaction_manager.transaction() as conn:
            await register_admin_scopes(conn)
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            # Create 5 token pairs (will create 10 tokens: 5 access + 5 refresh)
            for _ in range(5):
                await token_service.create_token_pair(user=test_regular_user, scope="openid profile")

        # Test first page
        response = await test_server.client.get(
            f"/admin/users/{test_regular_user.id}/sessions?limit=5&skip=0",
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = await response.json()

        assert len(data["sessions"]) <= 5  # Should be <= 5 (first page)
        assert data["total_count"] >= 5
        assert data["page_info"]["current_page"] == 1
        assert data["page_info"]["limit"] == 5
        assert data["page_info"]["skip"] == 0

    @pytest.mark.asyncio
    async def test_get_user_sessions_include_inactive_filter(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_read_token: str,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test session listing with include_inactive filter."""
        # Create and then invalidate some sessions
        async with transaction_manager.transaction() as conn:
            await register_admin_scopes(conn)
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            # Create sessions
            await token_service.create_token_pair(user=test_regular_user, scope="openid profile")

            # Invalidate some sessions
            await token_repo.invalidate_user_sessions(test_regular_user.id)

        # Test including inactive sessions
        response = await test_server.client.get(
            f"/admin/users/{test_regular_user.id}/sessions?include_inactive=true",
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data_with_inactive = await response.json()

        # Test excluding inactive sessions
        response = await test_server.client.get(
            f"/admin/users/{test_regular_user.id}/sessions?include_inactive=false",
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data_without_inactive = await response.json()

        # Should have more sessions when including inactive
        assert data_with_inactive["total_count"] >= data_without_inactive["total_count"]

    @pytest.mark.asyncio
    async def test_revoke_all_user_sessions_success(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test successfully revoking all user sessions."""
        # Create active sessions
        async with transaction_manager.transaction() as conn:
            await register_admin_scopes(conn)
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            # Create multiple sessions
            for _ in range(3):
                await token_service.create_token_pair(user=test_regular_user, scope="openid profile")

            # Verify sessions exist
            active_before = await token_repo.count_active_sessions(test_regular_user.id)
            assert active_before > 0

        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}/sessions",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()
        assert data["user_id"] == str(test_regular_user.id)
        assert data["username"] == test_regular_user.username
        assert data["revoked_sessions"] > 0
        assert data["active_sessions_remaining"] == 0
        assert "Successfully revoked" in data["message"]

        # Verify sessions are actually revoked
        async with transaction_manager.transaction() as conn:
            token_repo = TokenRepository(conn)
            active_after = await token_repo.count_active_sessions(test_regular_user.id)
            assert active_after == 0

    @pytest.mark.asyncio
    async def test_revoke_specific_user_session_success(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test successfully revoking a specific user session."""
        # Create active sessions
        session_id = None
        async with transaction_manager.transaction() as conn:
            await register_admin_scopes(conn)
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            # Create a session
            await token_service.create_token_pair(user=test_regular_user, scope="openid profile")

            # Get the session ID
            sessions = await token_repo.get_user_sessions(test_regular_user.id, include_inactive=False)
            assert len(sessions) > 0
            session_id = sessions[0].id

        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}/sessions/{session_id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()
        assert data["user_id"] == str(test_regular_user.id)
        assert data["username"] == test_regular_user.username
        assert data["session_id"] == str(session_id)
        assert "token_jti" in data
        assert "token_type" in data
        assert data["message"] == "Session successfully revoked."

    @pytest.mark.asyncio
    async def test_revoke_specific_session_not_found(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test revoking a non-existent session."""
        fake_session_id = uuid4()
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}/sessions/{fake_session_id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = await response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_revoke_session_wrong_user(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test revoking a session that belongs to a different user."""
        # Create a session for the admin user
        session_id = None
        async with transaction_manager.transaction() as conn:
            await register_admin_scopes(conn)
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            # Create a session for the admin user
            await token_service.create_token_pair(user=test_admin_user, scope="openid profile")

            # Get the session ID
            sessions = await token_repo.get_user_sessions(test_admin_user.id, include_inactive=False)
            assert len(sessions) > 0
            session_id = sessions[0].id

        # Try to revoke the admin's session using the regular user's ID
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}/sessions/{session_id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert "does not belong to the specified user" in data["detail"]

    @pytest.mark.asyncio
    async def test_revoke_already_invalidated_session(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test revoking an already invalidated session."""
        # Create and then invalidate a session
        session_id = None
        async with transaction_manager.transaction() as conn:
            await register_admin_scopes(conn)
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            # Create a session
            await token_service.create_token_pair(user=test_regular_user, scope="openid profile")

            # Get the session ID
            sessions = await token_repo.get_user_sessions(test_regular_user.id, include_inactive=False)
            assert len(sessions) > 0
            session_id = sessions[0].id

            # Invalidate the session
            await token_repo.invalidate_token(sessions[0].token_jti)

        # Try to revoke the already invalidated session
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}/sessions/{session_id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert "already invalidated" in data["detail"]

    @pytest.mark.asyncio
    async def test_session_management_user_not_found(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test session management endpoints with non-existent user."""
        fake_user_id = uuid4()

        # Test GET sessions
        response = await test_server.client.get(
            f"/admin/users/{fake_user_id}/sessions",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

        # Test DELETE all sessions
        response = await test_server.client.delete(
            f"/admin/users/{fake_user_id}/sessions",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

        # Test DELETE specific session
        fake_session_id = uuid4()
        response = await test_server.client.delete(
            f"/admin/users/{fake_user_id}/sessions/{fake_session_id}",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_session_management_insufficient_permissions(
        self,
        test_server,
        test_regular_user: UserModel,
        admin_read_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test session management with insufficient permissions."""
        # Test DELETE operations with read-only token (should fail)
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}/sessions",
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        fake_session_id = uuid4()
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}/sessions/{fake_session_id}",
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_session_management_unauthorized(
        self,
        test_server,
        test_regular_user: UserModel,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test session management without authentication."""
        # Test without any token
        response = await test_server.client.get(f"/admin/users/{test_regular_user.id}/sessions")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        response = await test_server.client.delete(f"/admin/users/{test_regular_user.id}/sessions")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        fake_session_id = uuid4()
        response = await test_server.client.delete(f"/admin/users/{test_regular_user.id}/sessions/{fake_session_id}")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_session_management_regular_user_cannot_access(
        self,
        test_server,
        test_regular_user: UserModel,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test that regular users cannot access admin session management endpoints."""
        # Create a regular user token
        async with transaction_manager.transaction() as conn:
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            token_pair = await token_service.create_token_pair(user=test_regular_user, scope="openid profile")
            regular_token = token_pair.access_token

        target_user_id = uuid4()

        # Test all endpoints
        response = await test_server.client.get(
            f"/admin/users/{target_user_id}/sessions",
            headers={"Authorization": f"Bearer {regular_token}"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        response = await test_server.client.delete(
            f"/admin/users/{target_user_id}/sessions",
            headers={"Authorization": f"Bearer {regular_token}"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        fake_session_id = uuid4()
        response = await test_server.client.delete(
            f"/admin/users/{target_user_id}/sessions/{fake_session_id}",
            headers={"Authorization": f"Bearer {regular_token}"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_session_management_invalid_uuid_format(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test session management with invalid UUID formats."""
        # Test invalid user ID
        response = await test_server.client.get(
            "/admin/users/not-a-uuid/sessions",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Test invalid session ID
        response = await test_server.client.delete(
            f"/admin/users/{uuid4()}/sessions/not-a-uuid",
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
