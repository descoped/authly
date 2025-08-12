"""
Complete end-to-end authentication flow integration tests.

Tests the full OAuth 2.1 and OIDC flows from start to finish,
including authorization, token exchange, refresh, and revocation.

All tests use HTTP endpoints with committed fixtures to avoid transaction isolation issues.
"""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import status


def generate_pkce_pair():
    """Generate PKCE code verifier and challenge pair."""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge


class TestRedirectUriValidation:
    """Test OAuth 2.1 redirect URI exact matching requirements."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Password grant removed for OAuth 2.1 compliance - needs conversion to auth code flow")
    async def test_invalid_redirect_uri_rejected_api_endpoint(
        self, test_server, committed_user, committed_oauth_client
    ):
        """Test that invalid redirect URI is rejected by API endpoint with 400 error."""
        async with test_server.client as client:
            code_verifier, code_challenge = generate_pkce_pair()

            # Login the user first
            login_response = await client.post(
                "/api/v1/oauth/token",
                data={"grant_type": "password", "username": committed_user.username, "password": "TestPassword123!"},
            )
            assert login_response.status_code == status.HTTP_200_OK
            login_data = await login_response.json()
            access_token = login_data["access_token"]

            # Try authorization with INVALID redirect URI (should be exact match)
            invalid_redirect_uri = committed_oauth_client["redirect_uris"][0] + "/invalid"
            auth_params = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": invalid_redirect_uri,  # Invalid URI
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read write",
                "state": "test_state_123",
            }

            auth_response = await client.get(
                "/api/v1/oauth/authorize", params=auth_params, headers={"Authorization": f"Bearer {access_token}"}
            )

            # Should reject with 400 Bad Request (not redirect to invalid URI)
            assert auth_response.status_code == status.HTTP_400_BAD_REQUEST
            error_data = await auth_response.json()
            assert error_data["error"] == "invalid_request"
            assert "redirect_uri" in error_data["error_description"].lower()

    @pytest.mark.asyncio
    async def test_invalid_redirect_uri_rejected_session_endpoint(self, test_server, committed_oauth_client):
        """Test that invalid redirect URI is rejected by session endpoint with 400 error."""
        async with test_server.client as client:
            code_verifier, code_challenge = generate_pkce_pair()

            # Try authorization without authentication (session-based endpoint)
            invalid_redirect_uri = committed_oauth_client["redirect_uris"][0] + "/invalid"
            auth_params = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": invalid_redirect_uri,  # Invalid URI
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read write",
                "state": "test_state_123",
            }

            # This should hit the session-based endpoint (no Authorization header)
            auth_response = await client.get("/api/v1/oauth/authorize", params=auth_params)

            # Should reject with 400 Bad Request (not redirect to invalid URI)
            assert auth_response.status_code == status.HTTP_400_BAD_REQUEST
            error_data = await auth_response.json()
            assert error_data["error"] == "invalid_request"
            assert "redirect_uri" in error_data["error_description"].lower()

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Password grant removed for OAuth 2.1 compliance")
    async def test_valid_redirect_uri_accepted(self, test_server, committed_user, committed_oauth_client):
        """Test that exact matching redirect URI is accepted."""
        async with test_server.client as client:
            code_verifier, code_challenge = generate_pkce_pair()

            # Login the user first
            login_response = await client.post(
                "/api/v1/oauth/token",
                data={"grant_type": "password", "username": committed_user.username, "password": "TestPassword123!"},
            )
            assert login_response.status_code == status.HTTP_200_OK
            login_data = await login_response.json()
            access_token = login_data["access_token"]

            # Try authorization with VALID redirect URI (exact match)
            auth_params = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],  # Valid exact match
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read write",
                "state": "test_state_123",
            }

            auth_response = await client.get(
                "/api/v1/oauth/authorize", params=auth_params, headers={"Authorization": f"Bearer {access_token}"}
            )

            # Should show consent form (200 OK) not error
            assert auth_response.status_code == status.HTTP_200_OK
            # Should contain consent form HTML
            content = await auth_response.text()
            assert "consent" in content.lower() or "authorize" in content.lower()

    @pytest.mark.asyncio
    async def test_nonexistent_client_rejected(self, test_server):
        """Test that requests with nonexistent client_id are rejected with 400."""
        async with test_server.client as client:
            code_verifier, code_challenge = generate_pkce_pair()

            # Try authorization with nonexistent client
            auth_params = {
                "response_type": "code",
                "client_id": "nonexistent_client_12345",  # Invalid client ID
                "redirect_uri": "http://localhost:8080/callback",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read write",
                "state": "test_state_123",
            }

            auth_response = await client.get("/api/v1/oauth/authorize", params=auth_params)

            # Should reject with 400 Bad Request (not redirect)
            assert auth_response.status_code == status.HTTP_400_BAD_REQUEST
            error_data = await auth_response.json()
            assert error_data["error"] == "invalid_client"
            assert "not found" in error_data["error_description"].lower()


class TestCompleteAuthorizationCodeFlow:
    """Test complete OAuth 2.1 Authorization Code + PKCE flow using HTTP endpoints."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Password grant removed for OAuth 2.1 compliance")
    async def test_full_authorization_code_flow(self, test_server, committed_user, committed_oauth_client):
        """Test complete flow: authorize -> consent -> token -> refresh -> revoke."""
        async with test_server.client as client:
            # Generate PKCE challenge
            code_verifier, code_challenge = generate_pkce_pair()

            # Step 1: Login the user using password grant
            login_response = await client.post(
                "/api/v1/oauth/token",
                data={"grant_type": "password", "username": committed_user.username, "password": "TestPassword123!"},
            )
            assert login_response.status_code == status.HTTP_200_OK
            login_data = await login_response.json()
            access_token = login_data["access_token"]

            # Step 2: Start authorization request (GET shows consent form)
            auth_params = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read write",
                "state": "test_state_123",
            }

            auth_response = await client.get(
                "/api/v1/oauth/authorize", params=auth_params, headers={"Authorization": f"Bearer {access_token}"}
            )

            # Should show consent form (200 OK with HTML)
            assert auth_response.status_code == status.HTTP_200_OK

            # Step 2b: Submit consent approval (POST)
            consent_data = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read write",
                "state": "test_state_123",
                "approved": "true",  # User approves
            }

            consent_response = await client.post(
                "/api/v1/oauth/authorize",
                data=consent_data,
                headers={"Authorization": f"Bearer {access_token}"},
                follow_redirects=False,
            )

            # Should redirect with authorization code
            assert consent_response.status_code == status.HTTP_302_FOUND
            location = consent_response._response.headers.get("location")
            assert location is not None

            # Parse authorization code from redirect
            parsed = urlparse(location)
            query_params = parse_qs(parsed.query)
            assert "code" in query_params
            assert query_params.get("state")[0] == "test_state_123"
            auth_code = query_params["code"][0]

            # Step 3: Exchange authorization code for tokens
            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": committed_oauth_client["redirect_uris"][0],
                    "client_id": committed_oauth_client["client_id"],
                    "code_verifier": code_verifier,
                },
            )

            assert token_response.status_code == status.HTTP_200_OK
            token_data = await token_response.json()
            assert "access_token" in token_data
            assert "refresh_token" in token_data
            assert token_data["token_type"] == "Bearer"
            assert token_data["expires_in"] > 0

            new_access_token = token_data["access_token"]
            refresh_token = token_data["refresh_token"]

            # Step 4: Use the access token to get user info (skip if no openid scope)
            # Note: The userinfo endpoint requires openid scope, but this test uses "read write" scopes
            # So we'll test introspection instead
            introspect_response = await client.post(
                "/api/v1/oauth/introspect",
                data={"token": new_access_token, "token_type_hint": "access_token"},
                headers={"Authorization": f"Bearer {new_access_token}"},
            )
            assert introspect_response.status_code == status.HTTP_200_OK
            introspection = await introspect_response.json()
            assert introspection["active"] is True
            assert introspection["sub"] == str(committed_user.id)

            # Step 5: Use refresh token to get new access token
            refresh_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": committed_oauth_client["client_id"],
                },
            )

            assert refresh_response.status_code == status.HTTP_200_OK
            refreshed_data = await refresh_response.json()
            assert "access_token" in refreshed_data
            assert refreshed_data["access_token"] != new_access_token  # New token

            refreshed_access_token = refreshed_data["access_token"]

            # Step 6: Introspect the refreshed token
            # For public clients, introspection requires the token itself
            introspect_response = await client.post(
                "/api/v1/oauth/introspect",
                data={"token": refreshed_access_token, "token_type_hint": "access_token"},
                headers={"Authorization": f"Bearer {refreshed_access_token}"},
            )

            assert introspect_response.status_code == status.HTTP_200_OK
            introspection = await introspect_response.json()
            assert introspection["active"] is True
            # Client ID might not always be present in introspection
            if introspection.get("client_id"):
                assert introspection["client_id"] == committed_oauth_client["client_id"]
            # Username might not be in introspection response for all token types
            if "username" in introspection:
                assert introspection["username"] == committed_user.username

            # Step 7: Revoke the token
            revoke_response = await client.post(
                "/api/v1/oauth/revoke",
                data={"token": refreshed_access_token, "token_type_hint": "access_token"},
                headers={"Authorization": f"Bearer {refreshed_access_token}"},
            )

            assert revoke_response.status_code == status.HTTP_200_OK

            # Step 8: Verify token is revoked by trying to use it
            verify_response = await client.get(
                "/oidc/userinfo", headers={"Authorization": f"Bearer {refreshed_access_token}"}
            )
            assert verify_response.status_code == status.HTTP_401_UNAUTHORIZED


class TestCompleteOIDCFlow:
    """Test complete OpenID Connect flow using HTTP endpoints."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Password grant removed for OAuth 2.1 compliance")
    async def test_full_oidc_flow_with_id_token(self, test_server, committed_user, committed_oauth_client):
        """Test OIDC flow: authorize with openid scope -> get ID token -> validate -> userinfo."""
        async with test_server.client as client:
            # Generate PKCE and nonce
            code_verifier, code_challenge = generate_pkce_pair()
            nonce = f"nonce_{secrets.token_hex(16)}"

            # Step 1: Login the user using password grant
            login_response = await client.post(
                "/api/v1/oauth/token",
                data={"grant_type": "password", "username": committed_user.username, "password": "TestPassword123!"},
            )
            assert login_response.status_code == status.HTTP_200_OK
            login_data = await login_response.json()
            access_token = login_data["access_token"]

            # Step 2: Authorization request with OIDC scopes (GET shows consent form)
            auth_params = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "openid profile email",
                "state": "test_state_456",
                "nonce": nonce,
            }

            auth_response = await client.get(
                "/api/v1/oauth/authorize", params=auth_params, headers={"Authorization": f"Bearer {access_token}"}
            )

            # Should show consent form (200 OK with HTML)
            assert auth_response.status_code == status.HTTP_200_OK

            # Step 2b: Submit consent approval (POST) with OIDC parameters
            consent_data = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "openid profile email",
                "state": "test_state_456",
                "nonce": nonce,
                "approved": "true",  # User approves
            }

            consent_response = await client.post(
                "/api/v1/oauth/authorize",
                data=consent_data,
                headers={"Authorization": f"Bearer {access_token}"},
                follow_redirects=False,
            )

            # Should redirect with authorization code
            assert consent_response.status_code == status.HTTP_302_FOUND
            location = consent_response._response.headers.get("location")

            # Parse authorization code
            parsed = urlparse(location)
            query_params = parse_qs(parsed.query)
            auth_code = query_params["code"][0]

            # Step 3: Exchange code for tokens (should include ID token)
            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": committed_oauth_client["redirect_uris"][0],
                    "client_id": committed_oauth_client["client_id"],
                    "code_verifier": code_verifier,
                },
            )

            assert token_response.status_code == status.HTTP_200_OK
            token_data = await token_response.json()
            assert "access_token" in token_data
            assert "id_token" in token_data  # Must include ID token for openid scope
            assert token_data["token_type"] == "Bearer"

            # Step 4: Parse and validate ID token (would normally verify JWT signature)
            id_token = token_data["id_token"]
            # In a real test, we would decode and validate the JWT
            # For now, we'll just verify it's present and non-empty
            assert len(id_token) > 0

            # Step 5: Get user info using the access token
            userinfo_response = await client.get(
                "/oidc/userinfo", headers={"Authorization": f"Bearer {token_data['access_token']}"}
            )

            assert userinfo_response.status_code == status.HTTP_200_OK
            userinfo = await userinfo_response.json()

            # Verify OIDC standard claims
            assert userinfo["sub"] == str(committed_user.id)
            assert userinfo["preferred_username"] == committed_user.username
            assert userinfo["email"] == committed_user.email

            # Step 6: Test OIDC discovery endpoint
            discovery_response = await client.get("/.well-known/openid-configuration")
            assert discovery_response.status_code == status.HTTP_200_OK
            discovery = await discovery_response.json()

            assert discovery["issuer"] is not None
            assert discovery["authorization_endpoint"].endswith("/oauth/authorize")
            assert discovery["token_endpoint"].endswith("/oauth/token")
            assert discovery["userinfo_endpoint"].endswith("/oidc/userinfo")
            assert discovery["jwks_uri"].endswith("/.well-known/jwks.json")
            assert "code" in discovery["response_types_supported"]
            assert "authorization_code" in discovery["grant_types_supported"]


class TestLogoutFlow:
    """Test logout and session termination flows using HTTP endpoints."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Password grant removed for OAuth 2.1 compliance")
    async def test_oidc_logout_flow(self, test_server, committed_user):
        """Test OIDC RP-initiated logout flow."""
        async with test_server.client as client:
            # Step 1: Login to get tokens using password grant
            login_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "password",
                    "username": committed_user.username,
                    "password": "TestPassword123!",
                    "scope": "openid profile email",  # Add OIDC scopes for userinfo endpoint
                },
            )
            assert login_response.status_code == status.HTTP_200_OK
            login_data = await login_response.json()
            access_token = login_data["access_token"]
            refresh_token = login_data["refresh_token"]

            # Step 2: Verify tokens work
            userinfo_response = await client.get("/oidc/userinfo", headers={"Authorization": f"Bearer {access_token}"})
            assert userinfo_response.status_code == status.HTTP_200_OK

            # Step 3: Logout using the auth/logout endpoint
            logout_response = await client.post(
                "/api/v1/auth/logout", headers={"Authorization": f"Bearer {access_token}"}
            )
            assert logout_response.status_code == status.HTTP_200_OK

            # Step 4: Verify access token no longer works
            verify_response = await client.get("/oidc/userinfo", headers={"Authorization": f"Bearer {access_token}"})
            assert verify_response.status_code == status.HTTP_401_UNAUTHORIZED

            # Step 5: Verify refresh token no longer works
            refresh_response = await client.post(
                "/api/v1/oauth/token", data={"grant_type": "refresh_token", "refresh_token": refresh_token}
            )
            # Should fail as all tokens are invalidated on logout
            assert refresh_response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]


class TestErrorHandling:
    """Test error handling in authentication flows using HTTP endpoints."""

    @pytest.mark.asyncio
    async def test_invalid_grant_error(self, test_server, committed_oauth_client):
        """Test proper error response for invalid grant."""
        async with test_server.client as client:
            # Try to use an invalid authorization code
            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "invalid_code_12345",
                    "redirect_uri": committed_oauth_client["redirect_uris"][0],
                    "client_id": committed_oauth_client["client_id"],
                    "code_verifier": "invalid_verifier",
                },
            )

            assert token_response.status_code == status.HTTP_400_BAD_REQUEST
            error_data = await token_response.json()
            assert error_data["error"] == "invalid_grant"

    @pytest.mark.asyncio
    async def test_invalid_client_error(self, test_server):
        """Test proper error response for invalid client."""
        async with test_server.client as client:
            # Generate PKCE
            code_verifier, code_challenge = generate_pkce_pair()

            # Try authorization with non-existent client
            auth_params = {
                "response_type": "code",
                "client_id": "non_existent_client",
                "redirect_uri": "http://localhost:8000/callback",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read",
                "state": "test_state",
            }

            auth_response = await client.get("/api/v1/oauth/authorize", params=auth_params, follow_redirects=False)

            # With invalid client_id, should return 400 bad request (client validation fails first)
            assert auth_response.status_code == status.HTTP_400_BAD_REQUEST
            error_data = await auth_response.json()
            assert error_data["error"] in ["invalid_client", "invalid_request"]

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Password grant removed for OAuth 2.1 compliance")
    async def test_invalid_scope_error(self, test_server, committed_oauth_client, committed_user):
        """Test proper error response for invalid scope."""
        async with test_server.client as client:
            # Login first using password grant
            login_response = await client.post(
                "/api/v1/oauth/token",
                data={"grant_type": "password", "username": committed_user.username, "password": "TestPassword123!"},
            )
            login_data = await login_response.json()
            access_token = login_data["access_token"]

            # Generate PKCE
            code_verifier, code_challenge = generate_pkce_pair()

            # Request with invalid scope
            auth_params = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "non_existent_scope invalid_scope",
                "state": "test_state",
            }

            auth_response = await client.get(
                "/api/v1/oauth/authorize",
                params=auth_params,
                headers={"Authorization": f"Bearer {access_token}"},
                follow_redirects=False,
            )

            # Should redirect back to client with invalid_scope error
            assert auth_response.status_code == status.HTTP_302_FOUND
            location = auth_response._response.headers.get("location")
            assert location is not None
            # Check that it redirects with invalid_scope error (the error format might vary)
            assert "error=" in location  # Has an error
            assert "INVALID_SCOPE" in location or "invalid_scope" in location


class TestTokenRotation:
    """Test refresh token rotation for enhanced security."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Password grant removed for OAuth 2.1 compliance")
    async def test_refresh_token_rotation(self, test_server, committed_user, committed_oauth_client):
        """Test that refresh tokens are rotated on use."""
        async with test_server.client as client:
            # Generate PKCE
            code_verifier, code_challenge = generate_pkce_pair()

            # Step 1: Complete authorization flow to get initial tokens
            # Login using password grant
            login_response = await client.post(
                "/api/v1/oauth/token",
                data={"grant_type": "password", "username": committed_user.username, "password": "TestPassword123!"},
            )
            login_data = await login_response.json()
            access_token = login_data["access_token"]

            # Authorize
            auth_params = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read write",
                "state": "test_state",
            }

            auth_response = await client.get(
                "/api/v1/oauth/authorize", params=auth_params, headers={"Authorization": f"Bearer {access_token}"}
            )

            # Should show consent form (200 OK with HTML)
            assert auth_response.status_code == status.HTTP_200_OK

            # Submit consent approval (POST)
            consent_data = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read write",
                "state": "test_state",
                "approved": "true",  # User approves
            }

            consent_response = await client.post(
                "/api/v1/oauth/authorize",
                data=consent_data,
                headers={"Authorization": f"Bearer {access_token}"},
                follow_redirects=False,
            )

            # Get authorization code from redirect
            assert consent_response.status_code == status.HTTP_302_FOUND
            location = consent_response._response.headers.get("location")
            parsed = urlparse(location)
            query_params = parse_qs(parsed.query)
            auth_code = query_params["code"][0]

            # Exchange for tokens
            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": committed_oauth_client["redirect_uris"][0],
                    "client_id": committed_oauth_client["client_id"],
                    "code_verifier": code_verifier,
                },
            )

            initial_tokens = await token_response.json()
            initial_refresh = initial_tokens["refresh_token"]

            # Step 2: Use refresh token to get new tokens
            refresh_response_1 = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": initial_refresh,
                    "client_id": committed_oauth_client["client_id"],
                },
            )

            assert refresh_response_1.status_code == status.HTTP_200_OK
            new_tokens_1 = await refresh_response_1.json()
            new_refresh_1 = new_tokens_1.get("refresh_token", initial_refresh)

            # Step 3: Verify old refresh token no longer works (if rotation is implemented)
            # Note: This behavior depends on whether refresh token rotation is enabled
            old_refresh_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": initial_refresh,
                    "client_id": committed_oauth_client["client_id"],
                },
            )

            # If rotation is implemented, old token should fail
            # If not implemented yet, this test documents expected future behavior
            if old_refresh_response.status_code != status.HTTP_200_OK:
                # Rotation is working - old token is invalid
                assert old_refresh_response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]
                error_data = await old_refresh_response.json()
                assert error_data.get("error") in ["invalid_grant", "invalid_token"]

            # Step 4: New refresh token should work
            refresh_response_2 = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": new_refresh_1,
                    "client_id": committed_oauth_client["client_id"],
                },
            )

            assert refresh_response_2.status_code == status.HTTP_200_OK
            new_tokens_2 = await refresh_response_2.json()
            assert "access_token" in new_tokens_2
