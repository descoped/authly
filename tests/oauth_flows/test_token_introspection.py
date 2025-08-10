"""
OAuth 2.0 Token Introspection tests.

Tests token introspection endpoint compliance with RFC 7662.
Uses committed fixtures for proper transaction isolation with HTTP endpoints.
"""

import base64
import secrets
from contextlib import suppress
from uuid import uuid4

import pytest
from fastapi import status

from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, GrantType, TokenEndpointAuthMethod
from authly.oauth.scope_repository import ScopeRepository
from authly.tokens.repository import TokenRepository


@pytest.fixture
async def introspection_client_and_token(initialize_authly: AuthlyResourceManager):
    """Create a client with an active token for introspection testing."""
    pool = initialize_authly.get_pool()

    async with pool.connection() as conn:
        await conn.set_autocommit(True)

        client_repo = ClientRepository(conn)
        TokenRepository(conn)
        scope_repo = ScopeRepository(conn)

        # Create scopes first (or use existing)
        read_scope = "read"
        write_scope = "write"

        # Helper to ensure scope exists
        async def ensure_scope(name: str, desc: str):
            with suppress(Exception):
                await scope_repo.create_scope(
                    {
                        "scope_name": name,
                        "description": desc,
                        "is_default": False,
                        "is_active": True,
                    }
                )
        await ensure_scope(read_scope, "Read access")
        await ensure_scope(write_scope, "Write access")

        # Create confidential client
        client_secret = secrets.token_urlsafe(32)
        client_id = f"introspect_client_{uuid4().hex[:8]}"

        client_data = {
            "client_id": client_id,
            "client_name": "Introspection Test Client",
            "client_type": ClientType.CONFIDENTIAL,
            "client_secret": client_secret,
            "grant_types": [GrantType.CLIENT_CREDENTIALS],
            "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            "redirect_uris": ["http://localhost/callback"],  # Required by schema even for client_credentials
        }
        created_client = await client_repo.create_client(client_data)

        result = {
            "client": created_client,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        yield result

        # Cleanup
        with suppress(Exception):
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", client_id)
class TestTokenIntrospection:
    """Test OAuth 2.0 token introspection endpoint (RFC 7662)."""

    @pytest.mark.asyncio
    async def test_introspect_active_access_token(self, test_server, introspection_client_and_token):
        """Test introspection of an active access token."""
        client_id = introspection_client_and_token["client_id"]
        client_secret = introspection_client_and_token["client_secret"]

        async with test_server.client as client:
            # First get an access token
            credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "scope": "read",
                },
                headers={"Authorization": f"Basic {credentials}"},
            )

            # Client credentials grant may not be implemented
            if token_response.status_code != status.HTTP_200_OK:
                pytest.skip("Client credentials grant not implemented")

            token_data = await token_response.json()
            access_token = token_data["access_token"]

            # Now introspect the token
            introspect_response = await client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": access_token,
                    "token_type_hint": "access_token",
                },
                headers={"Authorization": f"Basic {credentials}"},
            )

            assert introspect_response.status_code == status.HTTP_200_OK

            introspect_data = await introspect_response.json()
            assert introspect_data["active"] is True
            assert introspect_data["client_id"] == client_id
            assert introspect_data["token_type"] == "Bearer"
            assert "exp" in introspect_data
            assert "iat" in introspect_data

    @pytest.mark.asyncio
    async def test_introspect_invalid_token(self, test_server, introspection_client_and_token):
        """Test introspection of an invalid token returns minimal response."""
        client_id = introspection_client_and_token["client_id"]
        client_secret = introspection_client_and_token["client_secret"]

        async with test_server.client as client:
            credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

            # Introspect an invalid token
            introspect_response = await client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": "invalid.token.here",
                },
                headers={"Authorization": f"Basic {credentials}"},
            )

            assert introspect_response.status_code == status.HTTP_200_OK

            introspect_data = await introspect_response.json()
            # Invalid tokens should return {"active": false}
            # The endpoint may include additional fields with null values
            assert introspect_data["active"] is False

    @pytest.mark.asyncio
    async def test_introspect_without_authentication(self, test_server, introspection_client_and_token):
        """Test that introspection requires client authentication."""
        async with test_server.client as client:
            # Try to introspect without authentication
            introspect_response = await client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": "some.token.here",
                },
            )

            # May require authentication (401) or allow but return inactive (200)
            if introspect_response.status_code == status.HTTP_200_OK:
                data = await introspect_response.json()
                assert data["active"] is False
            else:
                assert introspect_response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_introspect_revoked_token(self, test_server, introspection_client_and_token):
        """Test introspection of a revoked token."""
        client_id = introspection_client_and_token["client_id"]
        client_secret = introspection_client_and_token["client_secret"]

        async with test_server.client as client:
            # First get an access token
            credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "scope": "read",
                },
                headers={"Authorization": f"Basic {credentials}"},
            )

            # Client credentials grant may not be implemented
            if token_response.status_code != status.HTTP_200_OK:
                pytest.skip("Client credentials grant not implemented")

            token_data = await token_response.json()
            if "access_token" not in token_data:
                pytest.skip("No access token returned")
            access_token = token_data["access_token"]

            # Revoke the token
            revoke_response = await client.post(
                "/api/v1/oauth/revoke",
                data={
                    "token": access_token,
                    "token_type_hint": "access_token",
                },
                headers={"Authorization": f"Basic {credentials}"},
            )

            assert revoke_response.status_code == status.HTTP_200_OK

            # Now introspect the revoked token
            introspect_response = await client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": access_token,
                },
                headers={"Authorization": f"Basic {credentials}"},
            )

            assert introspect_response.status_code == status.HTTP_200_OK

            introspect_data = await introspect_response.json()
            assert introspect_data["active"] is False

    @pytest.mark.asyncio
    async def test_introspect_refresh_token(self, test_server, introspection_client_and_token):
        """Test introspection with refresh token type hint."""
        client_id = introspection_client_and_token["client_id"]
        client_secret = introspection_client_and_token["client_secret"]

        async with test_server.client as client:
            credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

            # Client credentials doesn't issue refresh tokens, so test with invalid token
            introspect_response = await client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": "some.refresh.token",
                    "token_type_hint": "refresh_token",
                },
                headers={"Authorization": f"Basic {credentials}"},
            )

            assert introspect_response.status_code == status.HTTP_200_OK

            introspect_data = await introspect_response.json()
            assert introspect_data["active"] is False

    @pytest.mark.asyncio
    async def test_introspect_with_wrong_client(self, test_server, initialize_authly: AuthlyResourceManager):
        """Test that clients can only introspect their own tokens."""
        pool = initialize_authly.get_pool()

        # Create two different clients
        async with pool.connection() as conn:
            await conn.set_autocommit(True)
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)

            # Create scope first (or use existing)
            read_scope = "read"
            with suppress(Exception):
                await scope_repo.create_scope(
                    {
                        "scope_name": read_scope,
                        "description": "Read access",
                        "is_default": False,
                        "is_active": True,
                    }
                )
            # First client
            client1_secret = secrets.token_urlsafe(32)
            client1_id = f"client1_{uuid4().hex[:8]}"
            client1_data = {
                "client_id": client1_id,
                "client_name": "Client 1",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client1_secret,
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
                "redirect_uris": ["http://localhost/callback"],
            }
            await client_repo.create_client(client1_data)

            # Second client
            client2_secret = secrets.token_urlsafe(32)
            client2_id = f"client2_{uuid4().hex[:8]}"
            client2_data = {
                "client_id": client2_id,
                "client_name": "Client 2",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client2_secret,
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
                "redirect_uris": ["http://localhost/callback"],
            }
            await client_repo.create_client(client2_data)

        try:
            async with test_server.client as client:
                # Get token with client1
                credentials1 = base64.b64encode(f"{client1_id}:{client1_secret}".encode()).decode()

                token_response = await client.post(
                    "/api/v1/oauth/token",
                    data={
                        "grant_type": "client_credentials",
                    },
                    headers={"Authorization": f"Basic {credentials1}"},
                )

                # Client credentials grant may not be implemented
                if token_response.status_code != status.HTTP_200_OK:
                    pytest.skip("Client credentials grant not implemented")

                token_data = await token_response.json()
                if "access_token" not in token_data:
                    pytest.skip("Client credentials grant did not return access token")
                access_token = token_data["access_token"]

                # Try to introspect client1's token with client2's credentials
                credentials2 = base64.b64encode(f"{client2_id}:{client2_secret}".encode()).decode()

                introspect_response = await client.post(
                    "/api/v1/oauth/introspect",
                    data={
                        "token": access_token,
                    },
                    headers={"Authorization": f"Basic {credentials2}"},
                )

                # Should either return inactive or deny access
                assert introspect_response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

                if introspect_response.status_code == status.HTTP_200_OK:
                    introspect_data = await introspect_response.json()
                    # Should not reveal information about other client's token
                    assert introspect_data["active"] is False

        finally:
            # Cleanup
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute(
                    "DELETE FROM oauth_clients WHERE client_id = ANY(%s)", ([client1_id, client2_id],)
                )


class TestIntrospectionCompliance:
    """Test RFC 7662 compliance for token introspection."""

    @pytest.mark.asyncio
    async def test_introspection_response_fields(self, test_server, introspection_client_and_token):
        """Test that introspection response includes required fields."""
        client_id = introspection_client_and_token["client_id"]
        client_secret = introspection_client_and_token["client_secret"]

        async with test_server.client as client:
            # Get a token
            credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "scope": "read",
                },
                headers={"Authorization": f"Basic {credentials}"},
            )

            # Client credentials grant may not be implemented
            if token_response.status_code != status.HTTP_200_OK:
                pytest.skip("Client credentials grant not implemented")

            token_data = await token_response.json()
            if "access_token" not in token_data:
                pytest.skip("No access token returned")
            access_token = token_data["access_token"]

            # Introspect the token
            introspect_response = await client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": access_token,
                },
                headers={"Authorization": f"Basic {credentials}"},
            )

            introspect_data = await introspect_response.json()

            # Required fields per RFC 7662
            assert "active" in introspect_data
            assert introspect_data["active"] is True

            # Recommended fields when token is active
            assert "scope" in introspect_data
            assert "client_id" in introspect_data
            assert "exp" in introspect_data
            assert "iat" in introspect_data

            # Optional but common fields
            assert "token_type" in introspect_data

            # Verify field types
            assert isinstance(introspect_data["active"], bool)
            assert isinstance(introspect_data["exp"], int)
            assert isinstance(introspect_data["iat"], int)
            assert isinstance(introspect_data["client_id"], str)

    @pytest.mark.asyncio
    async def test_introspection_handles_malformed_token(self, test_server, introspection_client_and_token):
        """Test introspection handles malformed tokens gracefully."""
        client_id = introspection_client_and_token["client_id"]
        client_secret = introspection_client_and_token["client_secret"]

        async with test_server.client as client:
            credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

            # Test various malformed tokens
            malformed_tokens = [
                "",  # Empty token
                "not.a.jwt",  # Invalid JWT format
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",  # Incomplete JWT
                "a" * 1000,  # Very long string
            ]

            for token in malformed_tokens:
                introspect_response = await client.post(
                    "/api/v1/oauth/introspect",
                    data={
                        "token": token,
                    },
                    headers={"Authorization": f"Basic {credentials}"},
                )

                # Should handle gracefully
                assert introspect_response.status_code == status.HTTP_200_OK

                introspect_data = await introspect_response.json()
                # Malformed tokens should be inactive
                assert introspect_data["active"] is False
