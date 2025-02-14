import logging
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi_testing import TestServer
from psycopg_toolkit import TransactionManager

from authly import Authly
from authly.api import users_router, auth_router
from authly.auth import get_password_hash, create_access_token, verify_password
from authly.config import AuthlyConfig
from authly.users import UserModel
from authly.users import UserRepository

logger = logging.getLogger(__name__)


@pytest.fixture
async def test_user_data(initialize_authly: Authly):
    unique = uuid4().hex[:8]
    password_hash = get_password_hash("SecurePass123!")
    return {
        "username": f"testuser_{unique}",
        "email": f"test_{unique}@example.com",
        "password_hash": password_hash
    }


@pytest.fixture
async def test_user(
        initialize_authly: Authly,
        test_user_data: dict,
        transaction_manager: TransactionManager
) -> UserModel:
    """Create a test user in the database"""
    async with transaction_manager.transaction() as conn:
        user_repo = UserRepository(conn)
        user = UserModel(
            id=uuid4(),
            username=test_user_data["username"],
            email=test_user_data["email"],
            password_hash=test_user_data["password_hash"],  # Use password_hash directly
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=False,
            is_admin=False
        )
        return await user_repo.create(user)


@pytest.fixture
async def test_user_token(
        test_config: AuthlyConfig,
        test_user: UserModel,
) -> str:
    return create_access_token(
        data={"sub": str(test_user.id)},
        secret_key=test_config.secret_key,
        algorithm=test_config.algorithm,
        expires_delta=60  # Set explicit expiration in minutes
    )


@pytest.mark.asyncio
async def test_password_hashing():
    """Test password hashing functionality"""
    password = "SecurePass123!"
    hashed = get_password_hash(password)
    assert verify_password(password, hashed)
    assert not verify_password("wrong_password", hashed)


class TestUserAPI:
    @pytest.mark.asyncio
    async def test_create_user(self, test_server: TestServer):
        """Test user creation endpoint"""
        # Register the router with the API prefix
        test_server.app.include_router(users_router, prefix="/api/v1")

        new_user = {
            "username": "newuser",
            "email": "new@example.com",
            "password": "SecurePass123!"
        }

        response = await test_server.client.post(
            "/api/v1/users/",
            json=new_user
        )

        await response.expect_status(201)
        data = await response.json()

        assert data["username"] == new_user["username"]
        assert data["email"] == new_user["email"]
        assert "password" not in data
        assert "id" in data
        assert data["is_active"] is True
        assert data["is_verified"] is False
        assert data["is_admin"] is False

    @pytest.mark.asyncio
    async def test_get_current_user(
            self,
            test_server: TestServer,
            test_user: UserModel,
            test_user_token: str
    ):
        """Test getting current user information"""
        test_server.app.include_router(auth_router, prefix="/api/v1")
        test_server.app.include_router(users_router, prefix="/api/v1")

        headers = {"Authorization": f"Bearer {test_user_token}"}
        response = await test_server.client.get(
            "/api/v1/users/me",
            headers=headers
        )
        await response.expect_status(200)
        data = await response.json()

        assert data["id"] == str(test_user.id)
        assert data["username"] == test_user.username

    @pytest.mark.asyncio
    async def test_update_user(
            self,
            test_server: TestServer,
            test_user: UserModel,
            test_user_token: str
    ):
        """Test updating user information"""
        test_server.app.include_router(users_router, prefix="/api/v1")

        update_data = {
            "username": "updateduser",
            "email": "updated@example.com"
        }

        headers = {"Authorization": f"Bearer {test_user_token}"}
        response = await test_server.client.put(
            f"/api/v1/users/{test_user.id}",
            json=update_data,
            headers=headers
        )
        await response.expect_status(200)
        data = await response.json()

        assert data["username"] == update_data["username"]
        assert data["email"] == update_data["email"]
        assert "password" not in data

    @pytest.mark.asyncio
    async def test_delete_user(
            self,
            test_server: TestServer,
            test_user: UserModel,
            test_user_token: str
    ):
        """Test user deletion"""
        test_server.app.include_router(users_router, prefix="/api/v1")

        headers = {"Authorization": f"Bearer {test_user_token}"}
        response = await test_server.client.delete(
            f"/api/v1/users/{test_user.id}",
            headers=headers
        )
        await response.expect_status(204)

        response = await test_server.client.get(
            f"/api/v1/users/{test_user.id}",
            headers=headers  # Include auth headers
        )
        await response.expect_status(404)

    @pytest.mark.asyncio
    async def test_duplicate_username(
            self,
            test_server: TestServer,
            test_user: UserModel
    ):
        """Test creating user with duplicate username"""
        test_server.app.include_router(users_router, prefix="/api/v1")

        new_user = {
            "username": test_user.username,  # Use existing username
            "email": "different@example.com",
            "password": "SecurePass123!"
        }

        response = await test_server.client.post(
            "/api/v1/users",
            json=new_user
        )
        await response.expect_status(400)
        data = await response.json()
        assert "username already registered" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_get_users_pagination(
            self,
            test_server: TestServer,
            test_user: UserModel,
            test_user_token: str,
            transaction_manager
    ):
        """Test user listing with pagination"""
        test_server.app.include_router(users_router, prefix="/api/v1")

        # Create additional test users
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            for i in range(5):
                await user_repo.create(UserModel(
                    id=uuid4(),
                    username=f"testuser{i}",
                    email=f"test{i}@example.com",
                    password_hash="hashed_password",
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                    is_active=True,
                    is_verified=False,
                    is_admin=False
                ))

        headers = {"Authorization": f"Bearer {test_user_token}"}

        # Test first page
        response = await test_server.client.get(
            "/api/v1/users?skip=0&limit=3",
            headers=headers
        )
        await response.expect_status(200)
        data = await response.json()
        assert len(data) == 3

        # Test second page
        response = await test_server.client.get(
            "/api/v1/users?skip=3&limit=3",
            headers=headers
        )
        await response.expect_status(200)
        data = await response.json()
        assert len(data) == 3
