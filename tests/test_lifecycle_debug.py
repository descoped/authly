"""
Test to debug application lifecycle and database visibility issues.
"""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI
from psycopg_pool import AsyncConnectionPool

from authly import Authly, authly_db_connection, get_config
from authly.auth.core import get_password_hash
from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, OAuthClientModel, TokenEndpointAuthMethod
from authly.users import UserModel, UserRepository


class TestLifecycleDebug:
    """Debug test application lifecycle and database visibility."""

    @pytest.fixture
    async def test_data(self, db_pool: AsyncConnectionPool):
        """Create test data using the shared database pool."""
        # Create test user
        async with db_pool.connection() as conn:
            user_repo = UserRepository(conn)
            user = await user_repo.create(
                UserModel(
                    id=uuid4(),
                    username=f"debug_user_{uuid4().hex[:8]}",
                    email=f"debug_{uuid4().hex[:8]}@test.com",
                    password_hash=get_password_hash("Test123!"),
                    is_verified=True,
                    is_admin=False,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
            )

            # Create test client
            client_repo = ClientRepository(conn)
            client = await client_repo.create(
                OAuthClientModel(
                    id=uuid4(),
                    client_id=f"debug_client_{uuid4().hex[:8]}",
                    client_name="Debug Test Client",
                    client_secret_hash=get_password_hash("debug_secret"),
                    client_type=ClientType.CONFIDENTIAL,
                    redirect_uris=["https://example.com/callback"],
                    token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
                    require_pkce=True,
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
            )

        return {"user": user, "client": client}

    @pytest.fixture
    async def debug_app(self, test_config, initialize_authly):
        """Create a debug FastAPI app to test database visibility."""
        app = FastAPI(title="Debug Lifecycle Test")

        @app.get("/check-user/{username}")
        async def check_user(username: str):
            """Check if user exists using authly_db_connection."""
            async for conn in authly_db_connection():
                user_repo = UserRepository(conn)
                user = await user_repo.get_by_username(username)
                return {
                    "found": user is not None,
                    "username": user.username if user else None,
                    "connection_info": str(conn),
                }

        @app.get("/check-client/{client_id}")
        async def check_client(client_id: str):
            """Check if client exists using authly_db_connection."""
            async for conn in authly_db_connection():
                client_repo = ClientRepository(conn)
                client = await client_repo.get_by_client_id(client_id)
                return {
                    "found": client is not None,
                    "client_id": client.client_id if client else None,
                    "connection_info": str(conn),
                }

        @app.post("/create-auth-code")
        async def create_auth_code(code: str, client_id: str, user_id: str):
            """Create an authorization code."""
            async for conn in authly_db_connection():
                auth_repo = AuthorizationCodeRepository(conn)

                # First verify client exists
                client_repo = ClientRepository(conn)
                client = await client_repo.get_by_client_id(client_id)
                if not client:
                    return {"error": f"Client {client_id} not found"}

                # Create auth code
                auth_code = await auth_repo.create_authorization_code(
                    {
                        "code": code,
                        "client_id": client.id,
                        "user_id": user_id,
                        "redirect_uri": "https://example.com/callback",
                        "scope": "openid",
                        "expires_at": datetime.now(timezone.utc),
                        "code_challenge": "test_challenge",
                        "code_challenge_method": "S256",
                        "is_used": False,
                    }
                )

                return {
                    "created": auth_code is not None,
                    "code": auth_code.code if auth_code else None,
                    "connection_info": str(conn),
                }

        @app.get("/check-auth-code/{code}")
        async def check_auth_code(code: str):
            """Check if authorization code exists."""
            async for conn in authly_db_connection():
                auth_repo = AuthorizationCodeRepository(conn)
                auth_code = await auth_repo.get_by_code(code)
                return {
                    "found": auth_code is not None,
                    "code": auth_code.code if auth_code else None,
                    "connection_info": str(conn),
                }

        # Add config override
        app.dependency_overrides[get_config] = lambda: test_config

        return app

    @pytest.mark.asyncio
    async def test_lifecycle_and_visibility(self, debug_app, test_data, test_config, initialize_authly):
        """Test application lifecycle and database visibility."""
        # Create test server with debug app properly
        from fastapi_testing import AsyncTestServer

        server = AsyncTestServer()
        server.app = debug_app

        await server.start()
        try:
            user = test_data["user"]
            client = test_data["client"]

            print(f"\n=== Test Data Created ===")
            print(f"User: {user.username} (ID: {user.id})")
            print(f"Client: {client.client_id} (ID: {client.id})")

            # Test 1: Check if user is visible
            print(f"\n=== Checking User Visibility ===")
            user_check = await server.client.get(f"/check-user/{user.username}")
            user_result = await user_check.json()
            print(f"User check result: {user_result}")
            assert user_result["found"] is True, f"User {user.username} not found!"

            # Test 2: Check if client is visible
            print(f"\n=== Checking Client Visibility ===")
            client_check = await server.client.get(f"/check-client/{client.client_id}")
            client_result = await client_check.json()
            print(f"Client check result: {client_result}")
            assert client_result["found"] is True, f"Client {client.client_id} not found!"

            # Test 3: Create authorization code
            test_code = f"debug_code_{uuid4().hex[:8]}"
            print(f"\n=== Creating Authorization Code ===")
            print(f"Code: {test_code}")

            create_response = await server.client.post(
                "/create-auth-code", params={"code": test_code, "client_id": client.client_id, "user_id": str(user.id)}
            )
            create_result = await create_response.json()
            print(f"Create result: {create_result}")

            if "error" in create_result:
                pytest.fail(f"Failed to create auth code: {create_result['error']}")

            assert create_result["created"] is True

            # Small delay
            await asyncio.sleep(0.1)

            # Test 4: Check if authorization code is visible
            print(f"\n=== Checking Authorization Code Visibility ===")
            code_check = await server.client.get(f"/check-auth-code/{test_code}")
            code_result = await code_check.json()
            print(f"Code check result: {code_result}")

            # This is the key test - is the code visible?
            assert code_result["found"] is True, f"Authorization code {test_code} not found!"

            print("\n✅ All visibility tests passed!")
        finally:
            await server.stop()
