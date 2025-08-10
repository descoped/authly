"""
Basic OIDC Integration Tests

This module contains simplified integration tests for the OpenID Connect implementation
focusing on the core functionality without complex setup.
"""

import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer


class TestOIDCBasicIntegration:
    """Test basic OIDC integration functionality."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with all routers."""
        # The test_server fixture already includes all routers including oidc_router
        return test_server

    @pytest.mark.asyncio
    async def test_oidc_discovery_endpoint_compliance(self, oidc_server: AsyncTestServer):
        """Test that OIDC discovery endpoint shows only supported flows."""

        # Get OIDC discovery metadata
        discovery_response = await oidc_server.client.get("/.well-known/openid-configuration")
        await discovery_response.expect_status(200)

        discovery_data = await discovery_response.json()

        # Verify only supported response types are advertised
        assert "code" in discovery_data["response_types_supported"]
        assert "id_token" not in discovery_data["response_types_supported"]
        assert "code id_token" not in discovery_data["response_types_supported"]

        # Verify only supported response modes are advertised
        assert "query" in discovery_data["response_modes_supported"]
        assert "fragment" not in discovery_data["response_modes_supported"]

        # Verify required OIDC scopes are supported
        assert "openid" in discovery_data["scopes_supported"]
        assert "profile" in discovery_data["scopes_supported"]
        assert "email" in discovery_data["scopes_supported"]

        # Verify OIDC endpoints are present
        assert discovery_data["userinfo_endpoint"].endswith("/oidc/userinfo")
        assert discovery_data["jwks_uri"].endswith("/.well-known/jwks.json")

        # Verify OAuth 2.1 compliance
        assert discovery_data["require_pkce"] is True
        assert "S256" in discovery_data["code_challenge_methods_supported"]

    @pytest.mark.asyncio
    async def test_jwks_endpoint_provides_keys(self, oidc_server: AsyncTestServer):
        """Test JWKS endpoint provides RSA keys for ID token verification."""

        # Get JWKS
        jwks_response = await oidc_server.client.get("/.well-known/jwks.json")
        await jwks_response.expect_status(200)

        jwks_data = await jwks_response.json()

        # Should have keys array
        assert "keys" in jwks_data
        assert len(jwks_data["keys"]) > 0

        # Each key should have required JWK fields
        for key in jwks_data["keys"]:
            assert "kty" in key  # Key type (RSA)
            assert "use" in key  # Key use (sig)
            assert "alg" in key  # Algorithm (RS256)
            assert "kid" in key  # Key ID
            assert "n" in key  # RSA modulus
            assert "e" in key  # RSA exponent
            assert key["kty"] == "RSA"
            assert key["use"] == "sig"
            assert key["alg"] in ["RS256", "HS256"]

    @pytest.mark.asyncio
    async def test_userinfo_endpoint_authentication_required(self, oidc_server: AsyncTestServer):
        """Test UserInfo endpoint requires proper authentication."""

        # Should fail without token
        userinfo_response = await oidc_server.client.get("/oidc/userinfo")
        await userinfo_response.expect_status(401)

        # Should fail with invalid token
        userinfo_response = await oidc_server.client.get(
            "/oidc/userinfo", headers={"Authorization": "Bearer invalid_token"}
        )
        await userinfo_response.expect_status(401)

    @pytest.mark.asyncio
    async def test_oauth_discovery_endpoint_consistency(self, oidc_server: AsyncTestServer):
        """Test OAuth discovery endpoint matches OIDC discovery."""

        # Get OAuth discovery metadata
        oauth_discovery_response = await oidc_server.client.get("/.well-known/oauth-authorization-server")
        await oauth_discovery_response.expect_status(200)

        oauth_data = await oauth_discovery_response.json()

        # Get OIDC discovery metadata
        oidc_discovery_response = await oidc_server.client.get("/.well-known/openid-configuration")
        await oidc_discovery_response.expect_status(200)

        oidc_data = await oidc_discovery_response.json()

        # Both should advertise same response types
        assert oauth_data["response_types_supported"] == oidc_data["response_types_supported"]
        assert oauth_data["response_modes_supported"] == oidc_data["response_modes_supported"]

        # Both should have same base OAuth endpoints
        assert oauth_data["authorization_endpoint"] == oidc_data["authorization_endpoint"]
        assert oauth_data["token_endpoint"] == oidc_data["token_endpoint"]
        assert oauth_data["revocation_endpoint"] == oidc_data["revocation_endpoint"]

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_authorization_endpoint_accepts_oidc_params(self, oidc_server: AsyncTestServer):
        """Test authorization endpoint accepts OIDC parameters."""

        # Test authorization request with OIDC parameters
        auth_params = {
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "scope": "openid profile email",
            "state": "test_state",
            "nonce": "test_nonce",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "S256",
            "max_age": "3600",
            "display": "page",
            "prompt": "consent",
        }

        # Should not fail with OIDC parameters (may fail for other reasons like invalid client)
        auth_response = await oidc_server.client.get("/api/v1/oauth/authorize", params=auth_params)

        # Should not be a server error (500) - parameter validation should work
        # It's okay to get 401 (client doesn't exist) but not 500 (server error)
        assert auth_response.status_code != 500

    @pytest.mark.asyncio
    async def test_token_endpoint_password_grant_behavior(self, oidc_server: AsyncTestServer):
        """Test token endpoint behavior for password grant."""

        # Test password grant (non-OIDC)
        token_response = await oidc_server.client.post(
            "/api/v1/oauth/token",
            data={"grant_type": "password", "username": "nonexistent_user", "password": "invalid_password"},
        )

        # Should fail with authentication error (not server error)
        # OAuth 2.0 returns 401 or 400 for invalid credentials
        assert token_response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_unsupported_response_types_rejected(self, oidc_server: AsyncTestServer):
        """Test that unsupported response types are properly rejected."""

        # Test implicit flow (not supported)
        auth_params = {
            "response_type": "id_token",
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "scope": "openid profile",
            "state": "test_state",
            "nonce": "test_nonce",
        }

        auth_response = await oidc_server.client.get("/api/v1/oauth/authorize", params=auth_params)

        # Should be rejected with 400 (OAuth compliant error)
        await auth_response.expect_status(400)

        # Test hybrid flow (not supported)
        auth_params["response_type"] = "code id_token"

        auth_response = await oidc_server.client.get("/api/v1/oauth/authorize", params=auth_params)

        # Should be rejected with 400 (OAuth compliant error)
        await auth_response.expect_status(400)

    @pytest.mark.asyncio
    async def test_authorization_code_grant_recognized(self, oidc_server: AsyncTestServer):
        """Test that authorization_code grant type is recognized."""

        # Test authorization code grant (should be recognized even if it fails)
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

        # Should not be "unsupported grant type" error - should be 400 (Bad Request) for invalid authorization code
        await token_response.expect_status(400)

        # Should fail with OAuth error format
        error_data = await token_response.json()
        assert error_data.get("error") in ["invalid_grant", "invalid_request"]
        assert "error_description" in error_data

    @pytest.mark.asyncio
    async def test_endpoint_integration_consistency(self, oidc_server: AsyncTestServer):
        """Test that all OIDC endpoints are consistently integrated."""

        # Test that all well-known endpoints are accessible
        endpoints_to_test = [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/jwks.json",
        ]

        for endpoint in endpoints_to_test:
            response = await oidc_server.client.get(endpoint)
            await response.expect_status(200)

        # Test that OIDC API endpoints exist (even if they require auth)
        api_endpoints_to_test = ["/oidc/userinfo", "/api/v1/oauth/authorize", "/api/v1/oauth/token"]

        for endpoint in api_endpoints_to_test:
            response = await oidc_server.client.get(endpoint)
            # Should not be 404 (may be 400/401 due to missing params/auth)
            assert response.status_code != 404, f"API endpoint {endpoint} should exist"
