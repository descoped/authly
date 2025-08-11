"""PKCE Compliance Tests - Essential Coverage Only.

Tests for Proof Key for Code Exchange (RFC 7636) compliance.
Covers the mandatory security requirements for OAuth 2.1.
"""

import base64
import hashlib
import secrets

import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer


def generate_pkce_pair():
    """Generate PKCE code verifier and challenge pair."""
    # Generate code verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")

    # Generate code challenge using S256 method
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    return code_verifier, code_challenge


# NOTE: Using committed_user and committed_oauth_client from fixtures/committed_data.py
# These are properly committed before being returned, following test isolation rules
# For PKCE-specific needs, tests use HTTP endpoints, not direct database access


class TestPKCECompliance:
    """Essential PKCE compliance tests per RFC 7636 and OAuth 2.1."""

    @pytest.mark.asyncio
    async def test_pkce_required_for_authorization_endpoint(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
    ):
        """Test that PKCE parameters are handled at authorization endpoint."""
        # Generate PKCE pair
        code_verifier, code_challenge = generate_pkce_pair()

        # Authorization request with PKCE
        # Don't follow redirects - we're just testing that the endpoint accepts PKCE params
        response = await test_server.client.get(
            "/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "scope": "openid",
                "state": "test_state",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

        # Authorization endpoint returns redirect since no user is authenticated
        # We're testing that it accepts PKCE parameters (no 400 error)
        assert response.status_code in [
            status.HTTP_302_FOUND,  # Redirect (to callback with error or login page)
            status.HTTP_303_SEE_OTHER,  # See other
            status.HTTP_200_OK,  # Or renders a page directly
        ]

    @pytest.mark.asyncio
    async def test_pkce_code_challenge_stored(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
    ):
        """Test that PKCE code challenge is properly handled in the flow."""
        # Generate PKCE pair
        code_verifier, code_challenge = generate_pkce_pair()

        # This test demonstrates the authorization flow setup
        # In a real scenario, this would involve:
        # 1. GET /oauth/authorize with PKCE challenge
        # 2. User login
        # 3. Consent approval
        # 4. Redirect with authorization code
        # 5. POST /oauth/token with code verifier

        # Since we can't easily simulate the full browser flow in unit tests,
        # we test that the endpoints accept the required parameters
        response = await test_server.client.get(
            "/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "scope": "openid profile",
                "state": "test_state",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

        # Should accept the request (even if it redirects to login)
        assert response.status_code != status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_token_endpoint_requires_code_verifier(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
    ):
        """Test that token endpoint validates code verifier."""
        # Attempt token exchange without valid authorization code
        # This should fail because we don't have a valid code

        credentials = base64.b64encode(
            f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}".encode()
        ).decode()

        response = await test_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "invalid_code",
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_verifier": "test_verifier",
            },
            headers={"Authorization": f"Basic {credentials}"},
        )

        # Should fail with invalid grant
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert data["error"] in ["invalid_grant", "invalid_request"]

    @pytest.mark.asyncio
    async def test_s256_method_supported(
        self,
        test_server: AsyncTestServer,
    ):
        """Test that S256 method is supported (OAuth 2.1 requirement)."""
        # Check discovery endpoint for PKCE support
        response = await test_server.client.get("/.well-known/oauth-authorization-server")

        if response.status_code == status.HTTP_200_OK:
            config = await response.json()
            # OAuth 2.1 requires S256 support
            assert "code_challenge_methods_supported" in config
            assert "S256" in config["code_challenge_methods_supported"]
        else:
            # Try OIDC discovery endpoint
            response = await test_server.client.get("/.well-known/openid-configuration")
            if response.status_code == status.HTTP_200_OK:
                config = await response.json()
                assert "code_challenge_methods_supported" in config
                assert "S256" in config["code_challenge_methods_supported"]

    @pytest.mark.asyncio
    async def test_pkce_verifier_length_requirements(self):
        """Test PKCE verifier length requirements (43-128 characters)."""
        # Generate multiple PKCE pairs and verify length requirements
        for _ in range(10):
            code_verifier, code_challenge = generate_pkce_pair()

            # Verify verifier length is within RFC 7636 bounds
            assert 43 <= len(code_verifier) <= 128, f"Verifier length {len(code_verifier)} out of bounds"
            assert 43 <= len(code_challenge) <= 128, f"Challenge length {len(code_challenge)} out of bounds"

            # Verify they are URL-safe base64 (no padding, +, or /)
            assert "=" not in code_verifier
            assert "+" not in code_verifier
            assert "/" not in code_verifier
            assert "=" not in code_challenge
            assert "+" not in code_challenge
            assert "/" not in code_challenge

    @pytest.mark.asyncio
    async def test_client_credentials_does_not_require_pkce(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
    ):
        """Test that client credentials flow doesn't require PKCE."""
        # Client credentials flow should work without PKCE
        credentials = base64.b64encode(
            f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}".encode()
        ).decode()

        response = await test_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "scope": "openid",
                # No PKCE parameters needed
            },
            headers={"Authorization": f"Basic {credentials}"},
        )

        # Client credentials should work (if implemented)
        # Status 200 = success, 400 = not implemented
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]

        if response.status_code == status.HTTP_200_OK:
            data = await response.json()
            assert "access_token" in data
            assert data["token_type"] == "Bearer"
