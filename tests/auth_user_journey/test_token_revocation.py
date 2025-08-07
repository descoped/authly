"""Tests for OAuth 2.0 Token Revocation (RFC 7009).

Comprehensive tests for the /oauth/revoke endpoint including:
- Access token revocation
- Refresh token revocation
- Invalid token handling
- RFC 7009 compliance (always return 200)
- Security considerations
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import TransactionManager

from authly.api import auth_router, users_router
from authly.auth.core import get_password_hash
from authly.users import UserModel, UserRepository


class TestTokenRevocation:
    """Test OAuth 2.0 Token Revocation endpoint."""

    @pytest.fixture
    async def auth_server(self, test_server) -> AsyncTestServer:
        """Configure test server with auth routers."""
        test_server.app.include_router(auth_router, prefix="/api/v1")
        test_server.app.include_router(users_router, prefix="/api/v1")
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

    @pytest.fixture
    async def valid_tokens(self, auth_server: AsyncTestServer, test_user: UserModel):
        """Get valid access and refresh tokens for testing."""
        response = await auth_server.client.post(
            "/api/v1/oauth/token",
            data={"grant_type": "password", "username": test_user.username, "password": "Test123!"},
        )
        await response.expect_status(200)
        return await response.json()

    @pytest.mark.asyncio
    async def test_revoke_access_token_success(self, auth_server: AsyncTestServer, valid_tokens: dict):
        """Test successful access token revocation."""
        access_token = valid_tokens["access_token"]

        # Revoke the access token
        response = await auth_server.client.post(
            "/api/v1/oauth/revoke", json={"token": access_token, "token_type_hint": "access_token"}
        )

        # Should always return 200 per RFC 7009
        await response.expect_status(200)
        data = await response.json()
        assert "message" in data
        assert "successfully" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_revoke_refresh_token_success(self, auth_server: AsyncTestServer, valid_tokens: dict):
        """Test successful refresh token revocation."""
        refresh_token = valid_tokens["refresh_token"]

        # Revoke the refresh token
        response = await auth_server.client.post(
            "/api/v1/oauth/revoke", json={"token": refresh_token, "token_type_hint": "refresh_token"}
        )

        # Should always return 200 per RFC 7009
        await response.expect_status(200)
        data = await response.json()
        assert "message" in data
        assert "successfully" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_revoke_token_without_hint(self, auth_server: AsyncTestServer, valid_tokens: dict):
        """Test token revocation without token_type_hint."""
        access_token = valid_tokens["access_token"]

        # Revoke without hint
        response = await auth_server.client.post("/api/v1/oauth/revoke", json={"token": access_token})

        # Should work fine without hint
        await response.expect_status(200)
        data = await response.json()
        assert "message" in data

    @pytest.mark.asyncio
    async def test_revoke_invalid_token_returns_200(self, auth_server: AsyncTestServer):
        """Test that invalid tokens still return 200 per RFC 7009."""
        # Try to revoke completely invalid token
        response = await auth_server.client.post(
            "/api/v1/oauth/revoke", json={"token": "invalid.jwt.token", "token_type_hint": "access_token"}
        )

        # Must return 200 even for invalid tokens (RFC 7009 requirement)
        await response.expect_status(200)
        data = await response.json()
        assert "message" in data

    @pytest.mark.asyncio
    async def test_revoke_empty_token_returns_200(self, auth_server: AsyncTestServer):
        """Test that empty tokens still return 200."""
        response = await auth_server.client.post(
            "/api/v1/oauth/revoke", json={"token": "", "token_type_hint": "access_token"}
        )

        # Must return 200 even for empty tokens
        await response.expect_status(200)
        data = await response.json()
        assert "message" in data

    @pytest.mark.asyncio
    async def test_revoke_already_revoked_token(self, auth_server: AsyncTestServer, valid_tokens: dict):
        """Test revoking a token that's already been revoked."""
        access_token = valid_tokens["access_token"]

        # Revoke the token first time
        response1 = await auth_server.client.post(
            "/api/v1/oauth/revoke", json={"token": access_token, "token_type_hint": "access_token"}
        )
        await response1.expect_status(200)

        # Revoke the same token again
        response2 = await auth_server.client.post(
            "/api/v1/oauth/revoke", json={"token": access_token, "token_type_hint": "access_token"}
        )

        # Should still return 200 (idempotent operation)
        await response2.expect_status(200)
        data = await response2.json()
        assert "message" in data

    @pytest.mark.asyncio
    async def test_revoked_token_cannot_access_protected_resource(
        self, auth_server: AsyncTestServer, valid_tokens: dict
    ):
        """Test that revoked tokens cannot access protected resources."""
        access_token = valid_tokens["access_token"]

        # Verify token works initially
        response = await auth_server.client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {access_token}"})
        await response.expect_status(200)

        # Revoke the token
        revoke_response = await auth_server.client.post(
            "/api/v1/oauth/revoke", json={"token": access_token, "token_type_hint": "access_token"}
        )
        await revoke_response.expect_status(200)

        # Try to use revoked token
        protected_response = await auth_server.client.get(
            "/api/v1/users/me", headers={"Authorization": f"Bearer {access_token}"}
        )

        # Should fail with 401 Unauthorized
        await protected_response.expect_status(401)

    @pytest.mark.asyncio
    async def test_revoked_refresh_token_cannot_refresh(self, auth_server: AsyncTestServer, valid_tokens: dict):
        """Test that revoked refresh tokens cannot be used to get new tokens."""
        refresh_token = valid_tokens["refresh_token"]

        # Verify refresh works initially
        response = await auth_server.client.post(
            "/api/v1/oauth/refresh", json={"refresh_token": refresh_token, "grant_type": "refresh_token"}
        )
        await response.expect_status(200)

        # Get the new refresh token from the response
        new_tokens = await response.json()
        new_refresh_token = new_tokens["refresh_token"]

        # Revoke the new refresh token
        revoke_response = await auth_server.client.post(
            "/api/v1/oauth/revoke", json={"token": new_refresh_token, "token_type_hint": "refresh_token"}
        )
        await revoke_response.expect_status(200)

        # Try to use revoked refresh token
        refresh_response = await auth_server.client.post(
            "/api/v1/oauth/refresh", json={"refresh_token": new_refresh_token, "grant_type": "refresh_token"}
        )

        # Should fail with 400 Bad Request (OAuth 2.0 returns 400 for invalid grant)
        await refresh_response.expect_status(400)
        error_data = await refresh_response.json()
        assert error_data.get("error") == "invalid_grant"
        assert "invalid or expired" in error_data.get("error_description", "").lower()

    @pytest.mark.asyncio
    async def test_invalid_token_type_hint(self, auth_server: AsyncTestServer, valid_tokens: dict):
        """Test revocation with invalid token_type_hint."""
        access_token = valid_tokens["access_token"]

        # Use invalid hint
        response = await auth_server.client.post(
            "/api/v1/oauth/revoke", json={"token": access_token, "token_type_hint": "invalid_hint"}
        )

        # Should still work (hint is optional and just for optimization)
        await response.expect_status(200)
        data = await response.json()
        assert "message" in data

    @pytest.mark.asyncio
    async def test_missing_token_parameter(self, auth_server: AsyncTestServer):
        """Test revocation request missing required token parameter."""
        response = await auth_server.client.post(
            "/api/v1/oauth/revoke",
            json={
                "token_type_hint": "access_token"
                # Missing required 'token' parameter
            },
        )

        # Should return 422 for missing required parameter
        await response.expect_status(422)

    @pytest.mark.asyncio
    async def test_wrong_token_type_hint(self, auth_server: AsyncTestServer, valid_tokens: dict):
        """Test providing wrong token_type_hint (access token with refresh hint)."""
        access_token = valid_tokens["access_token"]

        # Provide wrong hint (access token with refresh_token hint)
        response = await auth_server.client.post(
            "/api/v1/oauth/revoke",
            json={
                "token": access_token,
                "token_type_hint": "refresh_token",  # Wrong hint
            },
        )

        # Should still work (implementation should try both types)
        await response.expect_status(200)
        data = await response.json()
        assert "message" in data
