"""
Helper fixtures for test data with proper transaction isolation.

This module provides committed test data fixtures that are visible to HTTP endpoints,
solving transaction isolation issues in integration tests.
"""

from uuid import uuid4

import pytest

from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, TokenEndpointAuthMethod
from authly.users import UserRepository
from authly.users.service import UserService


@pytest.fixture
async def committed_test_user(initialize_authly: AuthlyResourceManager):
    """Create a test user with committed data visible to HTTP endpoints."""
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

        yield {
            "user": created_user,
            "username": username,
            "password": password,
            "email": email,
            "user_id": str(created_user.id),
        }

        # Cleanup
        try:
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM users WHERE id = $1", created_user.id)
        except Exception:
            pass


@pytest.fixture
async def committed_oauth_client(initialize_authly: AuthlyResourceManager):
    """Create an OAuth client with committed data visible to HTTP endpoints."""
    pool = initialize_authly.get_pool()

    async with pool.connection() as conn:
        # Enable autocommit so data is immediately visible
        await conn.set_autocommit(True)

        client_repo = ClientRepository(conn)

        # Create OAuth client
        client_id = f"test_client_{uuid4().hex[:8]}"
        client_secret = f"test_secret_{uuid4().hex}"

        client = await client_repo.create_client(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "client_name": "Test Client",
                "client_type": ClientType.CONFIDENTIAL,
                "redirect_uris": ["http://localhost:8000/callback", "http://localhost/callback"],
                "allowed_scopes": ["openid", "profile", "email", "offline_access"],
                "require_pkce": True,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
        )

        yield {"client": client, "client_id": client_id, "client_secret": client_secret}

        # Cleanup
        try:
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", client_id)
        except Exception:
            pass


@pytest.fixture
async def committed_public_oauth_client(initialize_authly: AuthlyResourceManager):
    """Create a public OAuth client with committed data visible to HTTP endpoints."""
    pool = initialize_authly.get_pool()

    async with pool.connection() as conn:
        # Enable autocommit so data is immediately visible
        await conn.set_autocommit(True)

        client_repo = ClientRepository(conn)

        # Create public OAuth client
        client_id = f"public_client_{uuid4().hex[:8]}"

        client = await client_repo.create_client(
            {
                "client_id": client_id,
                "client_name": "Test Public Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["http://localhost:8000/callback", "http://localhost/callback"],
                "allowed_scopes": ["openid", "profile", "email"],
                "require_pkce": True,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
        )

        yield {"client": client, "client_id": client_id, "client_secret": None}

        # Cleanup
        try:
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", client_id)
        except Exception:
            pass


@pytest.fixture
async def committed_test_user_and_client(initialize_authly: AuthlyResourceManager):
    """Create both a test user and OAuth client with committed data."""
    pool = initialize_authly.get_pool()

    async with pool.connection() as conn:
        # Enable autocommit so data is immediately visible
        await conn.set_autocommit(True)

        # Create user
        user_repo = UserRepository(conn)
        user_service = UserService(user_repo)

        username = f"testuser_{uuid4().hex[:8]}"
        password = "TestPassword123!"
        email = f"{username}@example.com"

        created_user = await user_service.create_user(
            username=username, email=email, password=password, is_active=True, is_verified=True
        )

        # Create OAuth client
        client_repo = ClientRepository(conn)

        client_id = f"test_client_{uuid4().hex[:8]}"
        client_secret = f"test_secret_{uuid4().hex}"

        client = await client_repo.create_client(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "client_name": "Test Client",
                "client_type": ClientType.CONFIDENTIAL,
                "redirect_uris": ["http://localhost:8000/callback", "http://localhost/callback"],
                "allowed_scopes": ["openid", "profile", "email", "offline_access"],
                "require_pkce": True,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
        )

        result = {
            "user": created_user,
            "username": username,
            "password": password,
            "email": email,
            "user_id": str(created_user.id),
            "client": client,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        yield result

        # Cleanup
        try:
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", client_id)
                await cleanup_conn.execute("DELETE FROM users WHERE id = $1", created_user.id)
        except Exception:
            pass
