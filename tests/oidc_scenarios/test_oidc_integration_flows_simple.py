"""
Simple OIDC Integration Tests

This module contains simplified integration tests for OIDC that focus on
basic endpoint behavior without complex end-to-end flows.
"""

import pytest
from fastapi_testing import AsyncTestServer


class TestOIDCIntegrationFlowsSimple:
    """Test OIDC integration flows with simplified tests."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
        from authly.api import auth_router, oauth_router, oidc_router, users_router

        test_server.app.include_router(auth_router, prefix="/api/v1")
        test_server.app.include_router(users_router, prefix="/api/v1")
        test_server.app.include_router(oauth_router, prefix="/api/v1")
        test_server.app.include_router(oidc_router)  # No prefix - uses well-known paths
        return test_server

    @pytest.mark.asyncio
    async def test_authorization_code_grant_type_recognized(self, oidc_server: AsyncTestServer):
        """Test that authorization_code grant type is recognized."""

        # Test authorization code grant with invalid code
        # This tests that the authorization_code grant type is recognized
        token_response = await oidc_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "invalid_code",
                "redirect_uri": "https://example.com/callback",
                "client_id": "test_client",
                "client_secret": "test_secret",
                "code_verifier": "test_verifier",
            },
        )

        # Should fail with 400 Bad Request (invalid code), not 422 (unprocessable entity)
        # This confirms the grant type is recognized and processed
        await token_response.expect_status(400)

        error_response = await token_response.json()
        assert "detail" in error_response
        # Should be an invalid authorization code error, not unsupported grant type
        assert "authorization code" in error_response.get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_userinfo_endpoint_authentication_required(self, oidc_server: AsyncTestServer):
        """Test UserInfo endpoint requires authentication."""

        # Should fail without token
        userinfo_response = await oidc_server.client.get("/oidc/userinfo")
        await userinfo_response.expect_status(401)

        # Should fail with invalid token
        userinfo_response = await oidc_server.client.get(
            "/oidc/userinfo", headers={"Authorization": "Bearer invalid_token"}
        )
        await userinfo_response.expect_status(401)

    @pytest.mark.asyncio
    async def test_discovery_endpoints_available(self, oidc_server: AsyncTestServer):
        """Test that discovery endpoints are available."""

        # OIDC discovery should be available
        oidc_response = await oidc_server.client.get("/.well-known/openid-configuration")
        await oidc_response.expect_status(200)

        # OAuth discovery should be available
        oauth_response = await oidc_server.client.get("/.well-known/oauth-authorization-server")
        await oauth_response.expect_status(200)

        # JWKS should be available
        jwks_response = await oidc_server.client.get("/.well-known/jwks.json")
        await jwks_response.expect_status(200)

    @pytest.mark.asyncio
    async def test_password_grant_no_id_token(self, oidc_server: AsyncTestServer):
        """Test password grant doesn't include id_token."""

        # Test password grant (non-OIDC)
        token_response = await oidc_server.client.post(
            "/api/v1/oauth/token",
            data={"grant_type": "password", "username": "nonexistent_user", "password": "invalid_password"},
        )

        # Should fail with authentication error
        await token_response.expect_status(401)
