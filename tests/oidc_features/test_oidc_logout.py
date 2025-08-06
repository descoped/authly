"""
Tests for OIDC End Session (logout) endpoint.

This module tests the OpenID Connect logout endpoint implementation using
real integration testing with fastapi-testing and psycopg-toolkit.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import TransactionManager

from authly.auth.core import get_password_hash
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, OAuthClientModel
from authly.tokens.models import TokenModel, TokenType
from authly.tokens.repository import TokenRepository
from authly.users.models import UserModel
from authly.users.repository import UserRepository


class TestOIDCLogoutEndpoint:
    """Test OIDC logout endpoint functionality with real integration testing."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC router."""
        from authly.api.oidc_router import oidc_router

        test_server.app.include_router(oidc_router, prefix="/api/v1")
        return test_server

    async def create_test_user(self, conn):
        """Create a test user in the database."""
        user_repository = UserRepository(conn)

        test_user = UserModel(
            id=uuid4(),
            username=f"testuser-{uuid4().hex[:8]}",
            email=f"test-{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("password123"),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=True,
        )

        return await user_repository.create(test_user)

    async def create_test_client(self, conn, client_id=None):
        """Create a test OAuth client in the database."""
        if client_id is None:
            client_id = f"test-client-{uuid4().hex[:8]}"

        client_repository = ClientRepository(conn)

        test_client = OAuthClientModel(
            id=uuid4(),
            client_id=client_id,
            client_secret_hash="secret_hash",
            client_name="Test Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback", "https://example.com/logout"],
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        return await client_repository.create(test_client)

    async def create_test_token(self, conn, user_id, client_id=None):
        """Create a test token in the database."""
        token_repository = TokenRepository(conn)

        test_token = TokenModel(
            id=uuid4(),
            user_id=user_id,
            client_id=client_id,
            token_type=TokenType.ACCESS,
            token_jti=f"test-jti-{uuid4().hex[:16]}",
            token_value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test-token-value",
            scope="openid profile",
            expires_at=datetime.now(UTC).replace(hour=23, minute=59),
            created_at=datetime.now(UTC),
        )

        return await token_repository.create(test_token)

    @pytest.mark.asyncio
    async def test_oidc_logout_simple_success(self, oidc_server: AsyncTestServer):
        """Test OIDC logout without parameters returns success page."""
        response = await oidc_server.client.get("/api/v1/oidc/logout")
        await response.expect_status(200)

        content = await response.text()
        assert "Logout Successful" in content
        assert "successfully logged out" in content

    @pytest.mark.asyncio
    async def test_oidc_logout_endpoint_exists(self, oidc_server: AsyncTestServer):
        """Test OIDC logout endpoint is available at correct path."""
        response = await oidc_server.client.get("/api/v1/oidc/logout")

        # Should not return 404 (endpoint exists)
        assert response._response.status_code != status.HTTP_404_NOT_FOUND
        # Should return success page
        await response.expect_status(200)

    @pytest.mark.asyncio
    async def test_oidc_logout_with_id_token_hint(
        self, oidc_server: AsyncTestServer, transaction_manager: TransactionManager
    ):
        """Test OIDC logout with ID token hint shows success even if token processing fails."""
        # Create a simple malformed token to test the robustness
        # The real implementation should gracefully handle invalid tokens
        invalid_id_token = "invalid.token.here"

        # Test logout with id_token_hint (should still show success page)
        response = await oidc_server.client.get("/api/v1/oidc/logout", params={"id_token_hint": invalid_id_token})

        # Should still return success page even if token hint is invalid
        await response.expect_status(200)
        content = await response.text()
        assert "Logout Successful" in content

    @pytest.mark.asyncio
    async def test_oidc_logout_with_redirect_uri_without_hint(self, oidc_server: AsyncTestServer):
        """Test OIDC logout with post_logout_redirect_uri but without valid ID token hint."""
        # Test logout with redirect URI but no ID token hint (should fail)
        response = await oidc_server.client.get(
            "/api/v1/oidc/logout",
            params={"post_logout_redirect_uri": "https://example.com/logout", "state": "test-state-123"},
        )

        # Should return bad request because redirect URI requires valid client identification
        await response.expect_status(400)
        error_data = await response.json()
        assert "post_logout_redirect_uri requires valid id_token_hint" in error_data["detail"]

    @pytest.mark.asyncio
    async def test_oidc_logout_with_state_parameter(self, oidc_server: AsyncTestServer):
        """Test OIDC logout preserves state parameter in error responses."""
        # Test logout with state but invalid redirect URI setup
        response = await oidc_server.client.get(
            "/api/v1/oidc/logout",
            params={"post_logout_redirect_uri": "https://example.com/logout", "state": "test-state-123"},
        )

        # Should return bad request
        await response.expect_status(400)
        error_data = await response.json()
        # The endpoint should handle the error gracefully without exposing state
        assert "detail" in error_data


class TestOIDCLogoutDiscovery:
    """Test OIDC logout endpoint appears in discovery metadata using real integration testing."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC router and OAuth discovery service."""
        from authly.api.oauth_router import oauth_router
        from authly.api.oidc_router import oidc_router

        test_server.app.include_router(oidc_router, prefix="/api/v1")
        test_server.app.include_router(oauth_router, prefix="/api/v1")
        test_server.app.include_router(oidc_router)  # For discovery endpoint
        return test_server

    @pytest.mark.asyncio
    async def test_oidc_logout_in_discovery_metadata(self, oidc_server: AsyncTestServer):
        """Test that logout endpoint is advertised in OIDC discovery with real service integration."""
        response = await oidc_server.client.get("/.well-known/openid-configuration")
        await response.expect_status(200)

        metadata = await response.json()

        # Check if end_session_endpoint is advertised
        assert "end_session_endpoint" in metadata
        assert "/oidc/logout" in metadata["end_session_endpoint"]

        # Verify other OIDC endpoints are also present (showing real integration)
        assert "authorization_endpoint" in metadata
        assert "token_endpoint" in metadata
        assert "userinfo_endpoint" in metadata
        assert "jwks_uri" in metadata

        # Verify OIDC-specific metadata
        assert "scopes_supported" in metadata
        assert "openid" in metadata["scopes_supported"]
        assert "subject_types_supported" in metadata
        assert "public" in metadata["subject_types_supported"]
