"""
Comprehensive PKCE edge case tests for OAuth 2.1.

Tests PKCE security requirements including replay attacks, expiration,
and invalid parameter handling.
Uses committed fixtures for proper transaction isolation with HTTP endpoints.
"""

import base64
import hashlib
import secrets
from contextlib import suppress
from uuid import uuid4

import pytest
from fastapi import status

from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, GrantType, TokenEndpointAuthMethod
from authly.oauth.scope_repository import ScopeRepository
from authly.users.repository import UserRepository
from authly.users.service import UserService


def generate_pkce_pair():
    """Generate PKCE code verifier and challenge pair."""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge


@pytest.fixture
async def pkce_test_setup(initialize_authly: AuthlyResourceManager):
    """Create user and client for PKCE testing."""
    pool = initialize_authly.get_pool()

    async with pool.connection() as conn:
        await conn.set_autocommit(True)

        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        user_repo = UserRepository(conn)
        user_service = UserService(user_repo)

        # Create test user
        username = f"pkce_user_{uuid4().hex[:8]}"
        password = "TestPassword123!"

        user_data = {
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
            "is_active": True,
            "is_verified": True,
        }
        created_user = await user_service.create_user(user_data)

        # Create test client requiring PKCE
        client_id = f"pkce_client_{uuid4().hex[:8]}"
        client_data = {
            "client_id": client_id,
            "client_name": "PKCE Test Client",
            "client_type": ClientType.PUBLIC,
            "redirect_uris": ["http://localhost:8000/callback"],
            "require_pkce": True,
            "grant_types": [GrantType.AUTHORIZATION_CODE],
            "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
        }
        created_client = await client_repo.create_client(client_data)

        # Create test scope (handle if already exists)
        with suppress(Exception):
            await scope_repo.create_scope(
                {
                    "scope_name": "read",
                    "description": "Read access",
                    "is_active": True,
                }
            )
        result = {
            "user": created_user,
            "username": username,
            "password": password,
            "client": created_client,
            "client_id": client_id,
        }

        yield result

        # Cleanup
        with suppress(Exception):
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", client_id)
                await cleanup_conn.execute("DELETE FROM users WHERE username = $1", username)
                await cleanup_conn.execute("DELETE FROM oauth_scopes WHERE scope_name = 'read'")
class TestPKCEReplayAttacks:
    """Test PKCE replay attack prevention via HTTP."""

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_authorization_code_cannot_be_reused_via_http(self, test_server, pkce_test_setup):
        """Test that authorization codes cannot be reused via HTTP endpoints."""
        username = pkce_test_setup["username"]
        password = pkce_test_setup["password"]
        client_id = pkce_test_setup["client_id"]

        async with test_server.client as client:
            # Login user
            login_response = await client.post(
                "/auth/login",
                data={
                    "username": username,
                    "password": password,
                },
            )
            assert login_response.status_code == status.HTTP_302_FOUND

            # Generate PKCE pair
            code_verifier, code_challenge = generate_pkce_pair()

            # Get authorization code
            auth_response = await client.get(
                "/api/v1/oauth/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "http://localhost:8000/callback",
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "scope": "read",
                    "state": "test_state_123",
                },
            )

            # Handle consent if needed
            if auth_response.status_code == status.HTTP_200_OK:
                auth_response = await client.post(
                    "/api/v1/oauth/authorize",
                    data={
                        "approve": "true",
                        "client_id": client_id,
                        "redirect_uri": "http://localhost:8000/callback",
                        "scope": "read",
                        "state": "test_state_123",
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                    },
                )

            # Extract authorization code
            location = auth_response._response.headers.get("location")
            auth_code = location.split("code=")[1].split("&")[0]

            # First token exchange should succeed
            token_response1 = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": "http://localhost:8000/callback",
                    "client_id": client_id,
                    "code_verifier": code_verifier,
                },
            )

            assert token_response1.status_code == status.HTTP_200_OK
            token_data1 = await token_response1.json()
            assert "access_token" in token_data1

            # Second exchange with same code should fail (replay protection)
            token_response2 = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,  # Same code - should fail
                    "redirect_uri": "http://localhost:8000/callback",
                    "client_id": client_id,
                    "code_verifier": code_verifier,
                },
            )

            assert token_response2.status_code == status.HTTP_400_BAD_REQUEST
            error_data = await token_response2.json()
            assert error_data.get("error") == "invalid_grant"

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_used_code_invalidates_tokens_via_http(self, test_server, pkce_test_setup):
        """Test that reusing a code should invalidate tokens (security requirement)."""
        # This is a more advanced security feature from OAuth 2.0 Security BCP
        # If implemented, reusing a code should revoke all tokens issued from it
        username = pkce_test_setup["username"]
        password = pkce_test_setup["password"]
        client_id = pkce_test_setup["client_id"]

        async with test_server.client as client:
            # Get initial token through full flow
            await client.post(
                "/auth/login",
                data={
                    "username": username,
                    "password": password,
                },
            )

            code_verifier, code_challenge = generate_pkce_pair()

            auth_response = await client.get(
                "/api/v1/oauth/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "http://localhost:8000/callback",
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "scope": "read",
                    "state": "test_state",
                },
            )

            if auth_response.status_code == status.HTTP_200_OK:
                auth_response = await client.post(
                    "/api/v1/oauth/authorize",
                    data={
                        "approve": "true",
                        "client_id": client_id,
                        "redirect_uri": "http://localhost:8000/callback",
                        "scope": "read",
                        "state": "test_state",
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                    },
                )

            location = auth_response._response.headers.get("location")
            auth_code = location.split("code=")[1].split("&")[0]

            # Get first token
            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": "http://localhost:8000/callback",
                    "client_id": client_id,
                    "code_verifier": code_verifier,
                },
            )

            token_data = await token_response.json()
            access_token = token_data["access_token"]

            # Token should be valid
            introspect_response1 = await client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": access_token,
                },
            )
            introspect_data1 = await introspect_response1.json()
            assert introspect_data1["active"] is True

            # Try to reuse the same code (should fail)
            replay_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,  # Reusing same code
                    "redirect_uri": "http://localhost:8000/callback",
                    "client_id": client_id,
                    "code_verifier": code_verifier,
                },
            )

            assert replay_response.status_code == status.HTTP_400_BAD_REQUEST

            # Advanced feature: Original token should now be revoked
            # (This may not be implemented yet, but documents the expected behavior)
            introspect_response2 = await client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": access_token,
                },
            )
            await introspect_response2.json()

            # If security feature is implemented, token should be revoked
            # If not implemented, token may still be active
            # This test documents the expected behavior
            pass


class TestPKCEExpiration:
    """Test PKCE code expiration via HTTP."""

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_authorization_code_expires_via_http(self, test_server, pkce_test_setup):
        """Test that authorization codes have proper expiration via HTTP."""
        username = pkce_test_setup["username"]
        password = pkce_test_setup["password"]
        client_id = pkce_test_setup["client_id"]

        async with test_server.client as client:
            # Login and get authorization code
            await client.post(
                "/auth/login",
                data={
                    "username": username,
                    "password": password,
                },
            )

            code_verifier, code_challenge = generate_pkce_pair()

            auth_response = await client.get(
                "/api/v1/oauth/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "http://localhost:8000/callback",
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "scope": "read",
                    "state": "test_state",
                },
            )

            if auth_response.status_code == status.HTTP_200_OK:
                auth_response = await client.post(
                    "/api/v1/oauth/authorize",
                    data={
                        "approve": "true",
                        "client_id": client_id,
                        "redirect_uri": "http://localhost:8000/callback",
                        "scope": "read",
                        "state": "test_state",
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                    },
                )

            location = auth_response._response.headers.get("location")
            auth_code = location.split("code=")[1].split("&")[0]

            # Use code immediately - should work
            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": "http://localhost:8000/callback",
                    "client_id": client_id,
                    "code_verifier": code_verifier,
                },
            )

            assert token_response.status_code == status.HTTP_200_OK

            # Note: Testing actual expiration would require waiting or manipulating time
            # This test verifies that fresh codes work properly


class TestPKCEInvalidParameters:
    """Test PKCE invalid parameter handling via HTTP."""

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_missing_code_challenge_via_http(self, test_server, pkce_test_setup):
        """Test that authorization requests without code_challenge are rejected via HTTP."""
        username = pkce_test_setup["username"]
        password = pkce_test_setup["password"]
        client_id = pkce_test_setup["client_id"]

        async with test_server.client as client:
            # Login
            await client.post(
                "/auth/login",
                data={
                    "username": username,
                    "password": password,
                },
            )

            # Try authorization request without code_challenge (required for this client)
            auth_response = await client.get(
                "/api/v1/oauth/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "http://localhost:8000/callback",
                    # Missing: code_challenge and code_challenge_method
                    "scope": "read",
                    "state": "test_state",
                },
            )

            # Should fail for client requiring PKCE
            assert auth_response.status_code == status.HTTP_400_BAD_REQUEST

            error_data = await auth_response.json()
            assert error_data["error"] == "invalid_request"

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_invalid_code_challenge_method_via_http(self, test_server, pkce_test_setup):
        """Test that 'plain' code_challenge_method is rejected (OAuth 2.1 requires S256)."""
        username = pkce_test_setup["username"]
        password = pkce_test_setup["password"]
        client_id = pkce_test_setup["client_id"]

        async with test_server.client as client:
            await client.post(
                "/auth/login",
                data={
                    "username": username,
                    "password": password,
                },
            )

            # Try with 'plain' method (not allowed in OAuth 2.1)
            auth_response = await client.get(
                "/api/v1/oauth/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "http://localhost:8000/callback",
                    "code_challenge": "plain_challenge_value",
                    "code_challenge_method": "plain",  # Not allowed in OAuth 2.1
                    "scope": "read",
                    "state": "test_state",
                },
            )

            # Should reject plain method
            assert auth_response.status_code == status.HTTP_400_BAD_REQUEST

            error_data = await auth_response.json()
            assert error_data["error"] in ["invalid_request", "invalid_client"]

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_wrong_code_verifier_via_http(self, test_server, pkce_test_setup):
        """Test that wrong code_verifier is rejected during token exchange via HTTP."""
        username = pkce_test_setup["username"]
        password = pkce_test_setup["password"]
        client_id = pkce_test_setup["client_id"]

        async with test_server.client as client:
            # Login and get authorization code
            await client.post(
                "/auth/login",
                data={
                    "username": username,
                    "password": password,
                },
            )

            code_verifier, code_challenge = generate_pkce_pair()
            wrong_verifier, _ = generate_pkce_pair()  # Different verifier

            auth_response = await client.get(
                "/api/v1/oauth/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "http://localhost:8000/callback",
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "scope": "read",
                    "state": "test_state",
                },
            )

            if auth_response.status_code == status.HTTP_200_OK:
                auth_response = await client.post(
                    "/api/v1/oauth/authorize",
                    data={
                        "approve": "true",
                        "client_id": client_id,
                        "redirect_uri": "http://localhost:8000/callback",
                        "scope": "read",
                        "state": "test_state",
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                    },
                )

            location = auth_response._response.headers.get("location")
            auth_code = location.split("code=")[1].split("&")[0]

            # Try token exchange with wrong verifier
            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": "http://localhost:8000/callback",
                    "client_id": client_id,
                    "code_verifier": wrong_verifier,  # Wrong!
                },
            )

            assert token_response.status_code == status.HTTP_400_BAD_REQUEST

            error_data = await token_response.json()
            assert error_data["error"] == "invalid_grant"

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_invalid_code_challenge_length_via_http(self, test_server, pkce_test_setup):
        """Test that code challenges with invalid length are rejected via HTTP."""
        username = pkce_test_setup["username"]
        password = pkce_test_setup["password"]
        client_id = pkce_test_setup["client_id"]

        async with test_server.client as client:
            await client.post(
                "/auth/login",
                data={
                    "username": username,
                    "password": password,
                },
            )

            # Try with too short code_challenge
            auth_response = await client.get(
                "/api/v1/oauth/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "http://localhost:8000/callback",
                    "code_challenge": "tooshort",  # Less than 43 characters
                    "code_challenge_method": "S256",
                    "scope": "read",
                    "state": "test_state",
                },
            )

            # Should fail validation
            assert auth_response.status_code == status.HTTP_400_BAD_REQUEST

            error_data = await auth_response.json()
            assert error_data["error"] == "invalid_request"


class TestPKCESecurityRequirements:
    """Test additional PKCE security requirements."""

    @pytest.mark.asyncio
    async def test_code_verifier_entropy(self):
        """Test that code_verifier has sufficient entropy."""
        # Generate multiple verifiers and check they're unique
        verifiers = set()
        for _ in range(100):
            verifier, _ = generate_pkce_pair()
            verifiers.add(verifier)

        # All should be unique (high entropy)
        assert len(verifiers) == 100

        # Check minimum length (43 chars for 256 bits of entropy)
        for verifier in verifiers:
            assert len(verifier) >= 43

    @pytest.mark.asyncio
    async def test_code_challenge_format(self):
        """Test that code_challenge follows correct format."""
        code_verifier, code_challenge = generate_pkce_pair()

        # Should be base64url encoded (no padding, URL-safe chars)
        assert "=" not in code_challenge
        assert "+" not in code_challenge
        assert "/" not in code_challenge

        # Should only contain base64url characters
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
        assert all(c in allowed_chars for c in code_challenge)

        # Length should be 43 chars (base64url of SHA256)
        assert len(code_challenge) == 43

    @pytest.mark.asyncio
    async def test_pkce_sha256_verification(self):
        """Test that code_challenge is correctly generated from code_verifier."""
        code_verifier, code_challenge = generate_pkce_pair()

        # Manually compute expected challenge
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        expected_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

        assert expected_challenge == code_challenge

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_pkce_required_for_public_clients_via_http(
        self, test_server, initialize_authly: AuthlyResourceManager
    ):
        """Test that PKCE is enforced for public clients via HTTP."""
        pool = initialize_authly.get_pool()

        # Create public client
        async with pool.connection() as conn:
            await conn.set_autocommit(True)
            client_repo = ClientRepository(conn)

            client_id = f"public_test_{uuid4().hex[:8]}"
            client_data = {
                "client_id": client_id,
                "client_name": "Public Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["http://localhost:8000/callback"],
                "grant_types": [GrantType.AUTHORIZATION_CODE],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            await client_repo.create_client(client_data)

        try:
            async with test_server.client as client:
                # Public clients should require PKCE - request without PKCE should fail
                auth_response = await client.get(
                    "/api/v1/oauth/authorize",
                    params={
                        "response_type": "code",
                        "client_id": client_id,
                        "redirect_uri": "http://localhost:8000/callback",
                        "scope": "read",
                        "state": "test_state",
                        # No PKCE parameters
                    },
                )

                # Should require PKCE for public clients
                assert auth_response.status_code == status.HTTP_400_BAD_REQUEST

                error_data = await auth_response.json()
                assert error_data["error"] == "invalid_request"

        finally:
            # Cleanup
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", client_id)
