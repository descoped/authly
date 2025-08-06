"""
Tests for POST /admin/users endpoint.

This module tests the admin user creation endpoint with comprehensive scenarios
including validation, permissions, temporary password generation, and OIDC field support.
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


class TestAdminUserCreate:
    """Test POST /admin/users endpoint."""

    @pytest.mark.asyncio
    async def test_create_user_basic(
        self,
        test_server,
        test_admin_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test basic user creation."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"newuser_{unique_id}",
            "email": f"newuser_{unique_id}@example.com",
            "password": "NewUser123!",
            "is_active": True,
            "is_verified": False,
            "is_admin": False,
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_201_CREATED

        data = await response.json()
        assert data["username"] == create_data["username"]
        assert data["email"] == create_data["email"]
        assert data["is_active"] == create_data["is_active"]
        assert data["is_verified"] == create_data["is_verified"]
        assert data["is_admin"] == create_data["is_admin"]
        assert data["requires_password_change"] is False
        assert data["active_sessions"] == 0
        assert "temporary_password" not in data or data["temporary_password"] is None

    @pytest.mark.asyncio
    async def test_create_admin_user(
        self,
        test_server,
        test_admin_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating an admin user."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"newadmin_{unique_id}",
            "email": f"newadmin_{unique_id}@example.com",
            "password": "NewAdmin123!",
            "is_active": True,
            "is_verified": True,
            "is_admin": True,
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_201_CREATED

        data = await response.json()
        assert data["username"] == create_data["username"]
        assert data["email"] == create_data["email"]
        assert data["is_admin"] is True
        assert data["is_verified"] is True

    @pytest.mark.asyncio
    async def test_create_user_with_temp_password(
        self,
        test_server,
        test_admin_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user with temporary password generation."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"tempuser_{unique_id}",
            "email": f"tempuser_{unique_id}@example.com",
            "generate_temp_password": True,
            "is_active": True,
            "is_verified": False,
            "is_admin": False,
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_201_CREATED

        data = await response.json()
        assert data["username"] == create_data["username"]
        assert data["email"] == create_data["email"]
        assert data["requires_password_change"] is True
        assert "temporary_password" in data
        assert data["temporary_password"] is not None
        assert len(data["temporary_password"]) >= 8

        # Verify password complexity
        temp_password = data["temporary_password"]
        assert any(c.isupper() for c in temp_password)  # Uppercase
        assert any(c.islower() for c in temp_password)  # Lowercase
        assert any(c.isdigit() for c in temp_password)  # Digit
        assert any(c in "!@#$%^&*" for c in temp_password)  # Special char

    @pytest.mark.asyncio
    async def test_create_user_with_oidc_fields(
        self,
        test_server,
        test_admin_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user with comprehensive OIDC profile fields."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"oidcuser_{unique_id}",
            "email": f"oidcuser_{unique_id}@example.com",
            "password": "OidcUser123!",
            "is_active": True,
            "is_verified": True,
            "is_admin": False,
            # OIDC profile fields
            "given_name": "Jane",
            "family_name": "Doe",
            "middle_name": "Marie",
            "nickname": "Janie",
            "preferred_username": "jane_doe",
            "profile": "https://example.com/jane",
            "picture": "https://example.com/jane.jpg",
            "website": "https://janedoe.com",
            "gender": "female",
            "birthdate": "1985-03-15",
            "zoneinfo": "America/New_York",
            "locale": "en-US",
            "phone_number": "+1-555-987-6543",
            "phone_number_verified": True,
            "address": {
                "formatted": "456 Oak St\nSpringfield, IL 62704\nUSA",
                "street_address": "456 Oak St",
                "locality": "Springfield",
                "region": "IL",
                "postal_code": "62704",
                "country": "USA",
            },
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_201_CREATED

        data = await response.json()
        assert data["username"] == create_data["username"]
        assert data["given_name"] == create_data["given_name"]
        assert data["family_name"] == create_data["family_name"]
        assert data["middle_name"] == create_data["middle_name"]
        assert data["nickname"] == create_data["nickname"]
        assert data["locale"] == create_data["locale"]
        assert data["zoneinfo"] == create_data["zoneinfo"]
        assert data["phone_number"] == create_data["phone_number"]
        assert data["phone_number_verified"] == create_data["phone_number_verified"]
        assert data["address"] == create_data["address"]

    @pytest.mark.asyncio
    async def test_create_user_missing_username(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user without username fails."""
        create_data = {
            "email": "nouser@example.com",
            "password": "NoUser123!",
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_user_missing_email(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user without email fails."""
        create_data = {
            "username": "nomail",
            "password": "NoMail123!",
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_user_missing_password_and_temp_flag(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user without password or temp password flag fails."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"nopass_{unique_id}",
            "email": f"nopass_{unique_id}@example.com",
            "generate_temp_password": False,
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert "Either password must be provided or generate_temp_password must be true" in data["detail"]

    @pytest.mark.asyncio
    async def test_create_user_both_password_and_temp_flag(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user with both password and temp flag fails."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"bothpass_{unique_id}",
            "email": f"bothpass_{unique_id}@example.com",
            "password": "BothPass123!",
            "generate_temp_password": True,
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert "Cannot specify both password and generate_temp_password" in data["detail"]

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(
        self,
        test_server,
        test_admin_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user with duplicate username fails."""
        create_data = {
            "username": test_admin_user.username,  # Use existing username
            "email": "duplicate@example.com",
            "password": "Duplicate123!",
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert "already exists" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(
        self,
        test_server,
        test_admin_user: UserModel,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user with duplicate email fails."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"dupemail_{unique_id}",
            "email": test_admin_user.email,  # Use existing email
            "password": "DupeMail123!",
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert "already exists" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_user_weak_password(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user with weak password fails."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"weakpass_{unique_id}",
            "email": f"weakpass_{unique_id}@example.com",
            "password": "weak",  # Too short, missing requirements
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        data = await response.json()
        # FastAPI validation error format
        assert data["detail"][0]["msg"] is not None

    @pytest.mark.asyncio
    async def test_create_user_invalid_username_format(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user with invalid username format fails."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"invalid-username-{unique_id}@",  # Invalid characters
            "email": f"invaliduser_{unique_id}@example.com",
            "password": "InvalidUser123!",
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert "letters, numbers, and underscores" in data["detail"]

    @pytest.mark.asyncio
    async def test_create_user_invalid_email_format(
        self,
        test_server,
        admin_write_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user with invalid email format fails."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"invalidemail_{unique_id}",
            "email": "not-an-email",  # Invalid email format
            "password": "InvalidEmail123!",
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_write_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert "Invalid email format" in data["detail"]

    @pytest.mark.asyncio
    async def test_create_user_with_read_only_scope(
        self,
        test_server,
        admin_read_token: str,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test that read-only scope cannot create users."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"readonly_{unique_id}",
            "email": f"readonly_{unique_id}@example.com",
            "password": "ReadOnly123!",
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {admin_read_token}"},
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        data = await response.json()
        assert "admin:users:write" in data["detail"]

    @pytest.mark.asyncio
    async def test_create_user_unauthorized(
        self,
        test_server,
        initialize_authly: AuthlyResourceManager,
    ):
        """Test creating user without authentication."""
        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"unauth_{unique_id}",
            "email": f"unauth_{unique_id}@example.com",
            "password": "Unauth123!",
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_regular_user_cannot_create(
        self,
        test_server,
        test_regular_user: UserModel,
        initialize_authly: AuthlyResourceManager,
        transaction_manager: TransactionManager,
    ):
        """Test that regular users cannot use the admin create endpoint."""
        # Create a regular user token
        async with transaction_manager.transaction() as conn:
            config = initialize_authly.get_config()
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo, config, None)

            token_pair = await token_service.create_token_pair(user=test_regular_user, scope="openid profile")
            regular_token = token_pair.access_token

        unique_id = uuid4().hex[:8]
        create_data = {
            "username": f"regularuser_{unique_id}",
            "email": f"regularuser_{unique_id}@example.com",
            "password": "RegularUser123!",
        }

        response = await test_server.client.post(
            "/admin/users",
            json=create_data,
            headers={"Authorization": f"Bearer {regular_token}"},
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        data = await response.json()
        assert "admin" in data["detail"].lower()
