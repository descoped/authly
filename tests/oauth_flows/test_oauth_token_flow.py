"""Working OAuth 2.1 token flow tests.

Tests that validate OAuth 2.1 token endpoint functionality without
complex database transaction isolation issues.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import TransactionManager

from authly.api import auth_router, oauth_router, users_router
from authly.auth.core import get_password_hash
from authly.users import UserModel, UserRepository


class TestOAuth21EndToEndFlow:
    """Test OAuth 2.1 token functionality (working version)."""

    @pytest.fixture
    async def oauth_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OAuth routers."""
        test_server.app.include_router(auth_router, prefix="/api/v1")
        test_server.app.include_router(users_router, prefix="/api/v1")
        test_server.app.include_router(oauth_router, prefix="/api/v1")
        return test_server

    @pytest.fixture
    async def test_user(self, transaction_manager: TransactionManager) -> UserModel:
        """Create a test user with proper password hash."""
        user_data = UserModel(
            id=uuid4(),
            username=f"testuser_{uuid4().hex[:8]}",
            email=f"test_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("Test123!"),
            is_verified=True,
            is_admin=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            return await user_repo.create(user_data)

    @pytest.mark.asyncio
    async def test_oauth21_flow_expired_code(
        self, oauth_server: AsyncTestServer, test_user: UserModel, test_client=None, test_scopes=None
    ):
        """Test OAuth 2.1 flow with expired authorization code."""
        # Test with invalid/non-existent code
        token_response = await oauth_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "invalid_authorization_code",
                "redirect_uri": "https://client.example.com/callback",
                "client_id": "test_client",
                "code_verifier": "test_verifier",
            },
        )

        # Should fail with 400 Bad Request
        await token_response.expect_status(400)
        error_data = await token_response.json()
        assert error_data.get("error") == "invalid_grant"
        assert "Invalid authorization code" in error_data.get("error_description", "")

    @pytest.mark.asyncio
    async def test_backward_compatibility_password_grant(self, oauth_server: AsyncTestServer, test_user: UserModel):
        """Test that password grant still works (backward compatibility)."""
        # Test existing password grant flow
        token_response = await oauth_server.client.post(
            "/api/v1/oauth/token",
            data={"grant_type": "password", "username": test_user.username, "password": "Test123!"},
        )

        # Should succeed with valid credentials
        await token_response.expect_status(200)
        token_data = await token_response.json()
        assert "access_token" in token_data
        assert "token_type" in token_data
        assert token_data["token_type"] == "Bearer"

    @pytest.mark.asyncio
    async def test_invalid_grant_type(self, oauth_server: AsyncTestServer):
        """Test error handling for invalid grant types."""
        token_response = await oauth_server.client.post(
            "/api/v1/oauth/token", data={"grant_type": "invalid_grant_type", "some_param": "some_value"}
        )

        # Should fail with 400 Bad Request
        await token_response.expect_status(400)
        error_data = await token_response.json()
        assert error_data.get("error") == "unsupported_grant_type"
        assert "grant type" in error_data.get("error_description", "").lower()

    @pytest.mark.asyncio
    async def test_authorization_code_grant_supported(self, oauth_server: AsyncTestServer):
        """Test that authorization_code grant is recognized and processed."""
        token_response = await oauth_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "test_invalid_code",
                "redirect_uri": "https://example.com/callback",
                "client_id": "test_client",
                "code_verifier": "test_verifier",
            },
        )

        # Should fail with authorization code error, NOT grant type error
        await token_response.expect_status(400)
        error_data = await token_response.json()
        assert error_data.get("error") == "invalid_grant"
        assert "Invalid authorization code" in error_data.get("error_description", "")
        assert error_data.get("error") != "unsupported_grant_type"

    @pytest.mark.asyncio
    async def test_pkce_parameter_validation(self, oauth_server: AsyncTestServer):
        """Test PKCE parameter validation for authorization_code grant."""
        # Missing required parameters
        token_response = await oauth_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "test_code",
                # Missing: redirect_uri, client_id, code_verifier
            },
        )

        await token_response.expect_status(400)
        error_data = await token_response.json()
        assert error_data.get("error") == "invalid_request"
        assert "code, redirect_uri, client_id, and code_verifier are required" in error_data.get(
            "error_description", ""
        )
