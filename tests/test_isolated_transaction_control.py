"""
Test to verify database visibility using shared testcontainers PostgreSQL instance.

This test ensures the Authly singleton and test fixtures share the same database pool.
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi_testing import AsyncTestServer

from authly import get_config
from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, TokenEndpointAuthMethod


class TestSharedDatabaseVisibility:
    """Test database visibility using shared testcontainers PostgreSQL instance."""
    
    @pytest.fixture
    async def test_user(self, db_pool):
        """Create a test user using shared database pool."""
        from authly.users import UserModel, UserRepository
        from authly.auth.core import get_password_hash
        
        user_data = UserModel(
            id=uuid4(),
            username=f"testuser_{uuid4().hex[:8]}",
            email=f"test_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("Test123!"),
            is_verified=True,
            is_admin=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Use auto-commit connection so data is visible to HTTP endpoints
        async with db_pool.connection() as conn:
            user_repo = UserRepository(conn)
            return await user_repo.create(user_data)

    @pytest.fixture
    async def test_client(self, db_pool):
        """Create a test OAuth client using shared database pool."""
        from authly.oauth.models import OAuthClientModel
        from authly.auth.core import get_password_hash
        
        client_data = OAuthClientModel(
            id=uuid4(),
            client_id="test_client_id",
            client_name="Test Client",
            client_secret_hash=get_password_hash("test_client_secret"),
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            require_pkce=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Use auto-commit connection so data is visible to HTTP endpoints
        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)
            return await client_repo.create(client_data)
    
    @pytest.fixture
    async def test_server(self, test_config, initialize_authly, test_user):
        """Create test server with shared database pool - no transaction overrides."""
        
        # Create minimal FastAPI app
        app = FastAPI(title="Shared Database Test")
        
        @app.get("/create-code/{code}")
        async def create_code_endpoint(code: str):
            """Create an authorization code using Authly singleton database connection."""
            from authly import authly_db_connection
            
            async for db_conn in authly_db_connection():
                # First, get the test client we created
                client_repo = ClientRepository(db_conn)
                client = await client_repo.get_by_client_id("test_client_id")
                
                if not client:
                    return {"error": "Test client not found"}, 400
                
                repo = AuthorizationCodeRepository(db_conn)
                
                # Create a simple authorization code with valid client_id and user_id
                code_data = {
                    "code": code,
                    "client_id": client.id,  # Use the real client ID
                    "user_id": test_user.id,  # Use the real user ID
                    "redirect_uri": "https://example.com/callback",
                    "scope": "openid",
                    "expires_at": datetime.now(timezone.utc),
                    "code_challenge": "test_challenge",
                    "code_challenge_method": "S256",
                    "is_used": False,
                    "created_at": datetime.now(timezone.utc)
                }
                
                created_code = await repo.create_authorization_code(code_data)
                return {"created": True, "code": created_code.code}
        
        @app.get("/check-code/{code}")
        async def check_code_endpoint(code: str):
            """Check if an authorization code exists using Authly singleton database connection."""
            from authly import authly_db_connection
            
            async for db_conn in authly_db_connection():
                repo = AuthorizationCodeRepository(db_conn)
                stored_code = await repo.get_by_code(code)
                return {
                    "found": stored_code is not None,
                    "code": stored_code.code if stored_code else None
                }
        
        # Create test server with no dependency overrides - use Authly singleton
        server = AsyncTestServer()
        server.app = app
        
        # Only override config, keep Authly singleton database connection
        from fastapi.applications import AppType
        app_: AppType = server.app
        app_.dependency_overrides = {
            get_config: lambda: test_config,
        }
        
        try:
            await server.start()
            yield server
        finally:
            await server.stop()


    @pytest.mark.asyncio
    async def test_basic_transaction_visibility(self, test_server, test_client, test_user):
        """Test basic database visibility using shared testcontainers PostgreSQL instance."""
        test_code = f"test_code_{uuid4().hex[:8]}"
        
        print(f"Testing with code: {test_code}")
        print(f"Test client ID: {test_client.client_id}")
        print(f"Test client UUID: {test_client.id}")
        print(f"Test user ID: {test_user.id}")
        print(f"Test user username: {test_user.username}")
        
        # Step 1: Create authorization code (test client and user already created by fixtures)
        create_response = await test_server.client.get(f"/create-code/{test_code}")
        print(f"Create response status: {create_response._response.status_code}")
        
        if create_response._response.status_code != 200:
            error_details = await create_response.text()
            print(f"Create failed: {error_details}")
            pytest.fail(f"Failed to create code: {error_details}")
        
        create_result = await create_response.json()
        print(f"Create result: {create_result}")
        
        # Step 2: Check if code exists
        check_response = await test_server.client.get(f"/check-code/{test_code}")
        print(f"Check response status: {check_response._response.status_code}")
        
        await check_response.expect_status(200)
        check_result = await check_response.json()
        print(f"Check result: {check_result}")
        
        # This is the critical test - can we see data created in another endpoint?
        assert check_result["found"] is True, f"Authorization code not found! Expected True, got {check_result}"
        assert check_result["code"] == test_code
        
        print("✅ SUCCESS: Database visibility working correctly with shared testcontainers PostgreSQL!")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])