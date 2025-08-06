"""
Tests for PUT /admin/users/{user_id} endpoint.

This module tests the admin user update endpoint with comprehensive scenarios
including business rule validation, permissions, and field updates.
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
            locale="en-US",
        )

        user_repo = UserRepository(conn)
        return await user_repo.create(regular_user)


@pytest.fixture()
async def admin_write_token(
    initialize_authly: AuthlyResourceManager, test_admin_user: UserModel, transaction_manager: TransactionManager
) -> str:
    """Create admin token with user write scope."""
    async with transaction_manager.transaction() as conn:
        await register_admin_scopes(conn)

        config = initialize_authly.get_config()
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo, config, None)

        token_pair = await token_service.create_token_pair(user=test_admin_user, scope="admin:users:write")

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


class TestAdminUserUpdate:
    """Test PUT /admin/users/{user_id} endpoint."""

    @pytest.mark.asyncio
    async def test_update_user_basic_fields(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test updating basic user fields."""
        # Use unique values with UUID to avoid conflicts with other tests
        unique_id = uuid4().hex[:8]
        update_data = {
            "username": f"updated_username_{unique_id}",
            "email": f"updated_{unique_id}@example.com",
            "given_name": "Updated",
            "family_name": "User",
            "locale": "fr-FR",
        }

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()
        assert data["username"] == f"updated_username_{unique_id}"
        assert data["email"] == f"updated_{unique_id}@example.com"
        assert data["given_name"] == "Updated"
        assert data["family_name"] == "User"
        assert data["locale"] == "fr-FR"
        assert "active_sessions" in data

    @pytest.mark.asyncio
    async def test_update_admin_fields(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test updating admin-only fields."""
        update_data = {
            "is_admin": True,
            "is_verified": True,
            "requires_password_change": True,
        }

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()
        assert data["is_admin"] is True
        assert data["is_verified"] is True
        assert data["requires_password_change"] is True

    @pytest.mark.asyncio
    async def test_update_password(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test updating user password."""
        update_data = {
            "password": "NewSecurePassword123!",
            "requires_password_change": False,
        }

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()
        assert data["requires_password_change"] is False
        # Password should not be returned in response
        assert "password" not in data
        assert "password_hash" not in data

    @pytest.mark.asyncio
    async def test_cannot_remove_own_admin_privileges(
        self,
        test_server,
        test_admin_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test that admin cannot remove their own admin privileges."""
        update_data = {
            "is_admin": False,
        }

        response = await test_server.client.put(
            f"/admin/users/{test_admin_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        data = await response.json()
        assert "cannot revoke their own admin privileges" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_cannot_deactivate_last_admin(
        self,
        test_server,
        test_admin_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test that cannot deactivate the last admin user."""
        # Try to remove admin privileges from the only admin
        update_data = {
            "is_admin": False,
        }

        response = await test_server.client.put(
            f"/admin/users/{test_admin_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        # Should fail because they can't remove their own admin privileges
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_username_uniqueness_validation(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test username uniqueness validation."""
        # Try to update user with existing admin's username
        update_data = {
            "username": test_admin_user.username,
        }

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        data = await response.json()
        assert "already exists" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_email_uniqueness_validation(
        self,
        test_server,
        test_admin_user: UserModel,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test email uniqueness validation."""
        # Try to update user with existing admin's email
        update_data = {
            "email": test_admin_user.email,
        }

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        data = await response.json()
        assert "already exists" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_update_nonexistent_user(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test updating a non-existent user."""
        non_existent_id = uuid4()
        update_data = {
            "given_name": "NonExistent",
        }

        response = await test_server.client.put(
            f"/admin/users/{non_existent_id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

        data = await response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_update_with_no_fields(
        self,
        test_server,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test updating with no fields provided."""
        update_data = {}

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        data = await response.json()
        assert "no fields provided" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_update_with_read_only_scope(
        self,
        test_server,
        test_regular_user: UserModel,
        admin_read_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test that read-only scope cannot update users."""
        update_data = {
            "given_name": "Should Fail",
        }

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

        data = await response.json()
        assert "admin:users:write" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_unauthorized(
        self,
        test_server,
        test_regular_user: UserModel,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test updating without authentication."""
        update_data = {
            "given_name": "Should Fail",
        }

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}",
            json=update_data,
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_update_all_oidc_fields(
        self,
        test_server,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test updating all OIDC profile fields."""
        update_data = {
            "given_name": "UpdatedJohn",
            "family_name": "UpdatedDoe",
            "middle_name": "UpdatedMiddle",
            "nickname": "UpdatedNick",
            "preferred_username": "updated_john",
            "profile": "https://updated.example.com/john",
            "picture": "https://updated.example.com/john.jpg",
            "website": "https://updated-john.com",
            "gender": "updated",
            "birthdate": "1995-05-05",
            "zoneinfo": "Europe/London",
            "locale": "en-GB",
            "phone_number": "+44-123-456-7890",
            "phone_number_verified": True,
            "address": {
                "formatted": "456 Updated St\nUpdated City, UP 67890",
                "street_address": "456 Updated St",
                "locality": "Updated City",
                "region": "UP",
                "postal_code": "67890",
                "country": "UK",
            },
        }

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()

        # Verify all OIDC fields were updated
        assert data["given_name"] == "UpdatedJohn"
        assert data["family_name"] == "UpdatedDoe"
        assert data["middle_name"] == "UpdatedMiddle"
        assert data["nickname"] == "UpdatedNick"
        assert data["preferred_username"] == "updated_john"
        assert data["profile"] == "https://updated.example.com/john"
        assert data["picture"] == "https://updated.example.com/john.jpg"
        assert data["website"] == "https://updated-john.com"
        assert data["gender"] == "updated"
        assert data["birthdate"] == "1995-05-05"
        assert data["zoneinfo"] == "Europe/London"
        assert data["locale"] == "en-GB"
        assert data["phone_number"] == "+44-123-456-7890"
        assert data["phone_number_verified"] is True
        assert data["address"]["street_address"] == "456 Updated St"
        assert data["address"]["locality"] == "Updated City"
        assert data["address"]["region"] == "UP"
        assert data["address"]["postal_code"] == "67890"
        assert data["address"]["country"] == "UK"

    @pytest.mark.asyncio
    async def test_update_preserves_other_fields(
        self,
        test_server,
        test_regular_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test that updating one field preserves other fields."""
        # Update only one field
        update_data = {
            "given_name": "OnlyUpdatedField",
        }

        response = await test_server.client.put(
            f"/admin/users/{test_regular_user.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_200_OK

        data = await response.json()

        # Verify the updated field
        assert data["given_name"] == "OnlyUpdatedField"

        # Verify other fields are preserved
        assert data["username"] == test_regular_user.username
        assert data["email"] == test_regular_user.email
        assert data["family_name"] == test_regular_user.family_name
        assert data["locale"] == test_regular_user.locale
        assert data["is_active"] == test_regular_user.is_active
        assert data["is_verified"] == test_regular_user.is_verified
        assert data["is_admin"] == test_regular_user.is_admin
