"""
Tests for GET /admin/users/{user_id} endpoint.

This module tests the admin user details endpoint with comprehensive scenarios
including permissions, field visibility, and active session counting.
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
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, OAuthClientModel
from authly.tokens.models import TokenModel, TokenType
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
async def test_target_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a target user with OIDC fields."""
    async with transaction_manager.transaction() as conn:
        target_user = UserModel(
            id=uuid4(),
            username=f"targetuser_{uuid4().hex[:8]}",
            email=f"targetuser_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("UserTest123!"),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=True,
            is_admin=False,
            # OIDC fields
            given_name="John",
            family_name="Doe",
            locale="en-US",
            zoneinfo="America/New_York",
            phone_number="+1-555-123-4567",
            phone_number_verified=True,
        )

        user_repo = UserRepository(conn)
        return await user_repo.create(target_user)


@pytest.fixture()
async def admin_token(
    initialize_authly: AuthlyResourceManager, test_admin_user: UserModel, transaction_manager: TransactionManager
) -> str:
    """Create admin token with user read scope."""
    async with transaction_manager.transaction() as conn:
        await register_admin_scopes(conn)

        config = initialize_authly.get_config()
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo, config, None)

        token_pair = await token_service.create_token_pair(user=test_admin_user, scope="admin:users:read")

        return token_pair.access_token


class TestAdminUserDetails:
    """Test GET /admin/users/{user_id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_user_details_basic(
        self,
        test_server,
        test_admin_user: UserModel,
        test_target_user: UserModel,
        admin_token: str,
        transaction_manager: TransactionManager,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test basic user details retrieval."""

        # Create some active sessions for the target user
        async with transaction_manager.transaction() as conn:
            # Create a test client
            client_repo = ClientRepository(conn)
            test_client_model = OAuthClientModel(
                id=uuid4(),
                client_id=f"test-client-{uuid4().hex[:8]}",
                client_secret_hash="secret_hash",
                client_name="Test Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            oauth_client = await client_repo.create(test_client_model)

            # Create active tokens
            token_repo = TokenRepository(conn)
            for i in range(2):
                active_token = TokenModel(
                    id=uuid4(),
                    user_id=test_target_user.id,
                    client_id=oauth_client.id,
                    token_type=TokenType.ACCESS,
                    token_jti=f"test-jti-{uuid4().hex}",
                    token_value=f"test-token-{i}",
                    scope="openid profile",
                    expires_at=datetime.now(UTC).replace(day=30),  # Valid future date
                    invalidated=False,
                    created_at=datetime.now(UTC),
                )
                await token_repo.create(active_token)

        # Get user details
        response = await test_server.client.get(
            f"/admin/users/{test_target_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()
        assert data["id"] == str(test_target_user.id)
        assert data["username"] == test_target_user.username
        assert data["email"] == test_target_user.email

        # Admin fields should be visible
        assert "is_admin" in data
        assert "is_active" in data
        assert "is_verified" in data

        # OIDC fields
        assert data["given_name"] == "John"
        assert data["family_name"] == "Doe"
        assert data["locale"] == "en-US"
        assert data["zoneinfo"] == "America/New_York"

        # Active sessions count
        assert data["active_sessions"] == 2

    @pytest.mark.asyncio
    async def test_get_user_details_not_found(
        self,
        test_server,
        admin_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test 404 when user does not exist."""

        non_existent_id = uuid4()
        response = await test_server.client.get(
            f"/admin/users/{non_existent_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

        data = await response.json()
        assert "User not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_get_user_details_unauthorized(
        self,
        test_server,
        test_target_user: UserModel,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test 401 when no authentication provided."""

        response = await test_server.client.get(
            f"/admin/users/{test_target_user.id}",
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
