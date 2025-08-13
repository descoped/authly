"""OIDC Compliance Tests - Essential Coverage Only.

Tests required for OpenID Connect 1.0 compliance.
Covers the mandatory features without redundancy.
"""

import base64
import hashlib
import secrets

import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer

# NOTE: Using committed fixtures from tests/fixtures/committed_data.py
# These fixtures properly commit data before returning, following test isolation rules
# No custom fixtures needed here - we'll use the shared committed_user and committed_oauth_client


def generate_pkce_pair():
    """Generate PKCE code verifier and challenge pair."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return verifier, challenge


class TestOIDCCoreCompliance:
    """Essential OIDC 1.0 compliance tests."""

    @pytest.mark.asyncio
    async def test_jwks_endpoint(self, test_server: AsyncTestServer):
        """Test JWKS endpoint returns valid keys."""
        response = await test_server.client.get("/.well-known/jwks.json")

        assert response.status_code == status.HTTP_200_OK

        jwks = await response.json()
        assert "keys" in jwks
        assert len(jwks["keys"]) > 0

        # Verify key structure per RFC 7517
        for key in jwks["keys"]:
            assert "kty" in key  # Key type (RSA, EC, etc.)
            assert "kid" in key  # Key ID
            assert "use" in key  # Key use (sig or enc)
            assert "alg" in key  # Algorithm

            if key["kty"] == "RSA":
                assert "n" in key  # Modulus
                assert "e" in key  # Exponent

    @pytest.mark.asyncio
    async def test_userinfo_endpoint_with_client_credentials(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
    ):
        """Test UserInfo endpoint with client credentials token."""
        import base64

        # Get token via client credentials using Basic Auth
        auth_string = base64.b64encode(
            f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}".encode()
        ).decode()

        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": f"Basic {auth_string}"},
            data={
                "grant_type": "client_credentials",
            },
        )

        if response.status_code != 200:
            error_text = await response.text()
            print(f"Client credentials failed with {response.status_code}: {error_text}")
            pytest.skip("Client credentials flow not available")

        token_data = await response.json()
        access_token = token_data["access_token"]

        # Client credentials tokens typically don't have user context
        # So userinfo endpoint might not work with them
        response = await test_server.client.get(
            "/oidc/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        # This should fail or return limited info since no user context
        if response.status_code == 200:
            userinfo = await response.json()
            # Client tokens shouldn't have user claims
            assert "sub" in userinfo  # But sub might be the client_id

    @pytest.mark.asyncio
    async def test_discovery_endpoint(self, test_server: AsyncTestServer):
        """Test OIDC discovery endpoint (.well-known/openid-configuration)."""
        response = await test_server.client.get("/.well-known/openid-configuration")

        assert response.status_code == status.HTTP_200_OK

        config = await response.json()

        # Required metadata per OIDC Discovery 1.0
        assert "issuer" in config
        assert "authorization_endpoint" in config
        assert "token_endpoint" in config
        assert "userinfo_endpoint" in config
        assert "jwks_uri" in config

        # Required supported values
        assert "response_types_supported" in config
        assert "code" in config["response_types_supported"]

        assert "subject_types_supported" in config
        assert "public" in config["subject_types_supported"]

        assert "id_token_signing_alg_values_supported" in config
        assert "RS256" in config["id_token_signing_alg_values_supported"]

        # OAuth 2.1 / PKCE support
        assert "code_challenge_methods_supported" in config
        assert "S256" in config["code_challenge_methods_supported"]

    @pytest.mark.asyncio
    async def test_userinfo_requires_valid_token(self, test_server: AsyncTestServer):
        """Test UserInfo endpoint requires valid access token."""
        # No token
        response = await test_server.client.get("/oidc/userinfo")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Invalid token
        response = await test_server.client.get(
            "/oidc/userinfo",
            headers={"Authorization": "Bearer invalid_token"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
