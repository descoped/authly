"""Tests for OAuth 2.1 state parameter enforcement (CSRF protection).

OAuth 2.1 requires the state parameter to prevent CSRF attacks.
"""

import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer


class TestStateParameter:
    """Test that state parameter is properly enforced for CSRF protection."""

    @pytest.mark.asyncio
    async def test_state_parameter_required(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
    ):
        """Test that state parameter is required in authorization requests."""
        # Try authorization request without state parameter
        response = await test_server.client.get(
            "/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "scope": "openid",
                # NO state parameter - this should fail
                "code_challenge": "test_challenge",
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

        # Should reject request without state parameter
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert data["error"] == "invalid_request"
        assert "state" in data["error_description"].lower()

    @pytest.mark.asyncio
    async def test_state_parameter_preserved_in_redirect(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
    ):
        """Test that state parameter is preserved in authentication error redirects."""
        test_state = "random_csrf_protection_value_12345"

        # Generate valid PKCE challenge
        import base64
        import hashlib
        import secrets

        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

        # Make authorization request without authentication (should redirect with login_required)
        response = await test_server.client.get(
            "/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "scope": "openid",
                "state": test_state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
            # No Authorization header - user not authenticated
        )

        # Should redirect with login_required error AND preserve state
        assert response.status_code == status.HTTP_302_FOUND
        headers = response._response.headers if hasattr(response, "_response") else response.headers
        location = headers["location"]

        # Parse query parameters from redirect
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(location)
        query_params = parse_qs(parsed.query)

        # State should be preserved in error redirect
        assert "state" in query_params
        assert query_params["state"][0] == test_state
        assert "error" in query_params
        assert query_params["error"][0] == "login_required"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Password grant removed for OAuth 2.1 compliance")
    async def test_state_parameter_preserved_in_success_flow(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
        committed_user,
    ):
        """Test that state parameter is preserved through the entire OAuth flow."""
        test_state = "test_state_value_67890"

        # First, authenticate the user to get an access token
        login_response = await test_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "password",
                "username": committed_user.username,
                "password": "TestPassword123!",
            },
        )
        assert login_response.status_code == 200
        access_token = (await login_response.json())["access_token"]

        # Generate PKCE challenge
        import base64
        import hashlib
        import secrets

        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

        # Make authorization request with state
        response = await test_server.client.get(
            "/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "scope": "openid",
                "state": test_state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            headers={"Authorization": f"Bearer {access_token}"},
            follow_redirects=False,
        )

        # Should either show consent form (200) or redirect with code (302)
        # Both are valid responses when authenticated
        if response.status_code == status.HTTP_302_FOUND:
            # If it redirects directly (auto-consent), state should be preserved
            location = response.headers["location"]
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(location)
            query_params = parse_qs(parsed.query)

            assert "state" in query_params
            assert query_params["state"][0] == test_state
            assert "code" in query_params  # Should have authorization code

        elif response.status_code == status.HTTP_200_OK:
            # If it shows consent form, state should be in the form
            content = await response.text()
            assert test_state in content  # State should be preserved in form
        else:
            pytest.fail(f"Unexpected status code: {response.status_code}")

    @pytest.mark.asyncio
    async def test_empty_state_parameter_rejected(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
    ):
        """Test that empty state parameter is rejected."""
        # Try authorization request with empty state
        response = await test_server.client.get(
            "/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "scope": "openid",
                "state": "",  # Empty state should be rejected
                "code_challenge": "test_challenge",
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

        # Should reject empty state parameter
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert data["error"] == "invalid_request"
        assert "state" in data["error_description"].lower()

    @pytest.mark.asyncio
    async def test_state_parameter_length_limit(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
    ):
        """Test that state parameter has reasonable length limits."""
        # Create a very long state value (over 2000 chars)
        long_state = "x" * 2001

        response = await test_server.client.get(
            "/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "scope": "openid",
                "state": long_state,
                "code_challenge": "test_challenge",
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

        # Should reject excessively long state parameter
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = await response.json()
        assert data["error"] == "invalid_request"
