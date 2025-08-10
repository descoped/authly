"""
Authentication test fixtures.

Provides fixtures for authentication tests that require committed data
to be visible to HTTP endpoints.
"""

from uuid import uuid4

import pytest

from authly.core.resource_manager import AuthlyResourceManager
from authly.users import UserRepository
from authly.users.service import UserService


@pytest.fixture
async def test_user_committed(initialize_authly: AuthlyResourceManager):
    """Create a test user with committed data visible to HTTP endpoints."""
    # Use the resource manager's pool directly with autocommit
    pool = initialize_authly.get_pool()

    async with pool.connection() as conn:
        # Enable autocommit so data is immediately visible
        await conn.set_autocommit(True)

        user_repo = UserRepository(conn)
        user_service = UserService(user_repo)

        # Create test user
        username = f"testuser_{uuid4().hex[:8]}"
        password = "TestPassword123!"
        email = f"{username}@example.com"

        created_user = await user_service.create_user(
            username=username, email=email, password=password, is_active=True, is_verified=True
        )

        # Return both the user and the plain password for login tests
        yield {"user": created_user, "username": username, "password": password, "email": email}

        # Cleanup: delete the user after test
        try:
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM users WHERE id = $1", created_user.id)
        except Exception:
            pass  # Ignore cleanup errors


@pytest.fixture
async def multiple_test_users_committed(initialize_authly: AuthlyResourceManager):
    """Create multiple test users with committed data."""
    pool = initialize_authly.get_pool()
    users = []

    async with pool.connection() as conn:
        await conn.set_autocommit(True)

        user_repo = UserRepository(conn)
        user_service = UserService(user_repo)

        # Create 3 test users
        for i in range(3):
            username = f"testuser_{i}_{uuid4().hex[:8]}"
            password = f"TestPassword{i}123!"
            email = f"{username}@example.com"

            created_user = await user_service.create_user(
                username=username, email=email, password=password, is_active=True, is_verified=True
            )
            users.append({"user": created_user, "username": username, "password": password, "email": email})

        yield users

        # Cleanup
        try:
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                for user_info in users:
                    await cleanup_conn.execute("DELETE FROM users WHERE id = $1", user_info["user"].id)
        except Exception:
            pass
