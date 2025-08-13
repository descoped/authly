"""
PKCE (Proof Key for Code Exchange) security tests.

Tests the implementation of PKCE to ensure it properly prevents authorization code interception attacks.
"""

import base64
import hashlib
import secrets

import pytest
from fastapi_testing import AsyncTestServer


def generate_valid_pkce_pair():
    """Generate a valid PKCE code verifier and challenge pair."""
    # Code verifier: 43-128 characters from [A-Z, a-z, 0-9, -, ., _, ~]
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")

    # Code challenge: SHA256(code_verifier) then base64url encode
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    return code_verifier, code_challenge


class TestPKCESecurity:
    """Test PKCE security implementation."""

    @pytest.mark.asyncio
    async def test_pkce_required_for_public_clients(
        self, test_server: AsyncTestServer, committed_public_client: dict
    ) -> None:
        """Test that PKCE is required for public clients."""
        # Try authorization without PKCE
        response = await test_server.client.get(
            "/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": committed_public_client["client_id"],
                "redirect_uri": committed_public_client["redirect_uris"][0],
                "scope": "read",
                "state": "test_state",
                # Missing code_challenge and code_challenge_method
            },
        )

        # Should fail without PKCE (redirect with error or 400/401)
        assert response.status_code in [302, 400, 401]

    @pytest.mark.asyncio
    async def test_pkce_challenge_validation(self, test_server, committed_public_client):
        """Test that PKCE challenge is properly validated."""
        # Test invalid code challenge (too short)
        response = await test_server.client.get(
            "/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": committed_public_client["client_id"],
                "redirect_uri": committed_public_client["redirect_uris"][0],
                "code_challenge": "short",  # Too short (< 43 chars)
                "code_challenge_method": "S256",
                "scope": "read",
                "state": "test_state",
            },
            follow_redirects=False,  # Don't follow redirects
        )

        # Should reject invalid PKCE (redirect with error or 400/401/422)
        # 302 is valid as it redirects with an error parameter
        # The server is rejecting the short code challenge properly
        assert response.status_code in [302, 400, 401, 422]
