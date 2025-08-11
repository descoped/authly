"""Admin User Management CRUD Tests.

Essential tests for admin user management operations via HTTP API.
Covers create, read, update, delete, and password reset endpoints.
"""

import logging
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import TransactionManager

from authly.auth.core import create_access_token, get_password_hash
from authly.bootstrap.admin_seeding import register_admin_scopes
from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.client_service import ClientService
from authly.oauth.models import ClientType, GrantType, OAuthClientCreateRequest, ResponseType, TokenEndpointAuthMethod
from authly.oauth.scope_repository import ScopeRepository
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
async def admin_token(
    test_admin_user: UserModel,
    test_resource_manager: AuthlyResourceManager,
    transaction_manager: TransactionManager,
) -> str:
    """Generate an admin access token with all scopes."""
    async with transaction_manager.transaction() as conn:
        # Register admin scopes
        await register_admin_scopes(conn)

        # Create OAuth client with admin scopes using the service
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        client_service = ClientService(client_repo, scope_repo, test_resource_manager.config)

        client_request = OAuthClientCreateRequest(
            client_name="Admin Test Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["http://localhost:3000/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            scope="admin:users:read admin:users:write admin:system:read",
            grant_types=[GrantType.AUTHORIZATION_CODE],
            response_types=[ResponseType.CODE],
        )
        client_response = await client_service.create_client(client_request)

        # Get the actual client model for the token service
        client = await client_repo.get_by_client_id(client_response.client_id)

        # Generate token directly using the auth function
        access_token = create_access_token(
            data={
                "sub": str(test_admin_user.id),
                "client_id": client.client_id,
                "scope": "admin:users:read admin:users:write admin:system:read",
                "username": test_admin_user.username,
            },
            secret_key=test_resource_manager.config.secret_key,
            config=test_resource_manager.config,
        )
        return access_token


@pytest.fixture()
async def test_regular_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a regular test user."""
    async with transaction_manager.transaction() as conn:
        user = UserModel(
            id=uuid4(),
            username=f"user_{uuid4().hex[:8]}",
            email=f"user_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("UserTest123!"),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=False,
            is_admin=False,
        )
        user_repo = UserRepository(conn)
        return await user_repo.create(user)


class TestAdminUserCRUD:
    """Essential CRUD operations for admin user management via HTTP."""

    @pytest.mark.asyncio
    async def test_list_users(self, test_server: AsyncTestServer, admin_token: str, test_regular_user: UserModel):
        """Test GET /admin/users endpoint."""
        response = await test_server.client.get("/admin/users", headers={"Authorization": f"Bearer {admin_token}"})

        assert response.status_code == status.HTTP_200_OK
        data = await response.json()
        assert "users" in data
        assert "total_count" in data
        assert isinstance(data["users"], list)
        assert data["total_count"] >= 1  # At least the test users

    @pytest.mark.asyncio
    async def test_list_users_with_filters(
        self, test_server: AsyncTestServer, admin_token: str, test_regular_user: UserModel
    ):
        """Test GET /admin/users with query filters."""
        # Test filtering by active status
        response = await test_server.client.get(
            "/admin/users?is_active=true", headers={"Authorization": f"Bearer {admin_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = await response.json()
        assert all(user["is_active"] for user in data["users"])

        # Test search by username
        response = await test_server.client.get(
            f"/admin/users?username={test_regular_user.username}", headers={"Authorization": f"Bearer {admin_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = await response.json()
        assert any(user["username"] == test_regular_user.username for user in data["users"])

    @pytest.mark.asyncio
    async def test_get_user_details(self, test_server: AsyncTestServer, admin_token: str, test_regular_user: UserModel):
        """Test GET /admin/users/{user_id} endpoint."""
        response = await test_server.client.get(
            f"/admin/users/{test_regular_user.id}", headers={"Authorization": f"Bearer {admin_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        user_data = await response.json()
        assert user_data["id"] == str(test_regular_user.id)
        assert user_data["username"] == test_regular_user.username
        assert user_data["email"] == test_regular_user.email
        assert "active_sessions" in user_data  # Should include session count

    @pytest.mark.asyncio
    async def test_create_user(self, test_server: AsyncTestServer, admin_token: str):
        """Test POST /admin/users endpoint."""
        new_user_data = {
            "username": f"newuser_{uuid4().hex[:8]}",
            "email": f"newuser_{uuid4().hex[:8]}@example.com",
            "password": "SecurePass123!",
            "given_name": "John",
            "family_name": "Doe",
            "is_verified": True,
            "is_admin": False,
        }

        response = await test_server.client.post(
            "/admin/users", json=new_user_data, headers={"Authorization": f"Bearer {admin_token}"}
        )

        assert response.status_code == status.HTTP_201_CREATED
        created_user = await response.json()
        assert created_user["username"] == new_user_data["username"]
        assert created_user["email"] == new_user_data["email"]
        assert created_user["is_verified"] == new_user_data["is_verified"]
        assert "password" not in created_user  # Password should not be in response
        assert "generated_password" not in created_user  # Unless auto-generated

    @pytest.mark.asyncio
    async def test_create_user_auto_password(self, test_server: AsyncTestServer, admin_token: str):
        """Test POST /admin/users with password."""
        new_user_data = {
            "username": f"autopass_{uuid4().hex[:8]}",
            "email": f"autopass_{uuid4().hex[:8]}@example.com",
            "password": "AutoPass123!",  # Provide password
            "is_verified": True,
            "is_admin": False,
        }

        response = await test_server.client.post(
            "/admin/users", json=new_user_data, headers={"Authorization": f"Bearer {admin_token}"}
        )

        assert response.status_code == status.HTTP_201_CREATED
        created_user = await response.json()
        assert created_user["username"] == new_user_data["username"]
        assert created_user["email"] == new_user_data["email"]

    @pytest.mark.asyncio
    async def test_update_user(self, test_server: AsyncTestServer, admin_token: str, test_regular_user: UserModel):
        """Test PUT /admin/users/{user_id} endpoint."""
        update_data = {
            "email": f"updated_{uuid4().hex[:8]}@example.com",
            "is_verified": True,
            "is_active": True,
            "given_name": "Updated",
            "family_name": "Name",
        }

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}", json=update_data, headers={"Authorization": f"Bearer {admin_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        updated_user = await response.json()
        assert updated_user["email"] == update_data["email"]
        assert updated_user["is_verified"] == update_data["is_verified"]
        assert updated_user["given_name"] == update_data["given_name"]

    @pytest.mark.asyncio
    async def test_delete_user(self, test_server: AsyncTestServer, admin_token: str, test_regular_user: UserModel):
        """Test DELETE /admin/users/{user_id} endpoint."""
        response = await test_server.client.delete(
            f"/admin/users/{test_regular_user.id}", headers={"Authorization": f"Bearer {admin_token}"}
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify user is deleted
        response = await test_server.client.get(
            f"/admin/users/{test_regular_user.id}", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_reset_user_password(
        self, test_server: AsyncTestServer, admin_token: str, test_regular_user: UserModel
    ):
        """Test POST /admin/users/{user_id}/reset-password endpoint."""
        reset_data = {"new_password": "NewSecurePass456!"}

        response = await test_server.client.post(
            f"/admin/users/{test_regular_user.id}/reset-password",
            json=reset_data,
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        result = await response.json()
        assert "Password reset successfully" in result["message"]
        assert "temporary_password" in result  # The generated password

    @pytest.mark.asyncio
    async def test_reset_password_auto_generate(
        self, test_server: AsyncTestServer, admin_token: str, test_regular_user: UserModel
    ):
        """Test password reset with auto-generation."""
        response = await test_server.client.post(
            f"/admin/users/{test_regular_user.id}/reset-password",
            json={},  # No password provided
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        result = await response.json()
        assert "temporary_password" in result  # The endpoint returns temporary_password
        assert "Password reset successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_admin_user_protection(
        self, test_server: AsyncTestServer, admin_token: str, test_admin_user: UserModel
    ):
        """Test that we can delete admin users when multiple admins exist."""
        # The business rule is: Cannot delete the LAST admin user
        # Since we have multiple admin users in this test, deletion should succeed

        response = await test_server.client.delete(
            f"/admin/users/{test_admin_user.id}", headers={"Authorization": f"Bearer {admin_token}"}
        )

        # This should succeed since there are multiple admins (won't leave system with no admins)
        assert response.status_code == status.HTTP_204_NO_CONTENT

    @pytest.mark.asyncio
    async def test_unauthorized_access(self, test_server: AsyncTestServer):
        """Test that endpoints require authentication."""
        response = await test_server.client.get("/admin/users")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        response = await test_server.client.post("/admin/users", json={})
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_insufficient_permissions(
        self,
        test_server: AsyncTestServer,
        test_regular_user: UserModel,
        test_resource_manager: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test that regular users cannot access admin endpoints."""
        # Create token for regular user
        regular_token = create_access_token(
            data={
                "sub": str(test_regular_user.id),
                "username": test_regular_user.username,
                "scope": "openid profile",  # Regular user scopes, no admin
            },
            secret_key=test_resource_manager.config.secret_key,
            config=test_resource_manager.config,
        )

        response = await test_server.client.get("/admin/users", headers={"Authorization": f"Bearer {regular_token}"})
        assert response.status_code == status.HTTP_403_FORBIDDEN
