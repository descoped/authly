"""
Client Credentials Flow tests for OAuth 2.0.

Tests machine-to-machine authentication, scope validation, and token introspection.
Uses committed fixtures for proper transaction isolation with HTTP endpoints.
"""

import secrets
from uuid import uuid4

import pytest
from fastapi import status

from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import (
    ClientType,
    GrantType,
    TokenEndpointAuthMethod,
)
from authly.oauth.scope_repository import ScopeRepository


@pytest.fixture
async def committed_client_with_scopes(initialize_authly: AuthlyResourceManager):
    """Create a confidential OAuth client with scopes using committed data."""
    pool = initialize_authly.get_pool()

    async with pool.connection() as conn:
        await conn.set_autocommit(True)

        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)

        # Create unique scopes for this test first
        scope_id = uuid4().hex[:8]
        read_scope = f"api.read.{scope_id}"
        write_scope = f"api.write.{scope_id}"

        # Create confidential client
        client_secret = secrets.token_urlsafe(32)
        client_id = f"machine_client_{uuid4().hex[:8]}"

        client_data = {
            "client_id": client_id,
            "client_name": "Machine Client",
            "client_type": ClientType.CONFIDENTIAL,
            "client_secret": client_secret,
            "grant_types": [GrantType.CLIENT_CREDENTIALS],
            "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            "scope": f"{read_scope} {write_scope}",
            "redirect_uris": ["http://localhost/callback"],  # Dummy URI for client credentials
        }
        created_client = await client_repo.create_client(client_data)

        await scope_repo.create_scope(
            {
                "scope_name": read_scope,
                "description": "Read API access",
                "is_default": False,
                "is_active": True,
            }
        )

        await scope_repo.create_scope(
            {
                "scope_name": write_scope,
                "description": "Write API access",
                "is_default": False,
                "is_active": True,
            }
        )

        result = {
            "client": created_client,
            "client_id": client_id,
            "client_secret": client_secret,
            "read_scope": read_scope,
            "write_scope": write_scope,
        }

        yield result

        # Cleanup
        try:
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", client_id)
                await cleanup_conn.execute(
                    "DELETE FROM oauth_scopes WHERE scope_name IN ($1, $2)", read_scope, write_scope
                )
        except Exception:
            pass


@pytest.fixture
async def committed_public_client(initialize_authly: AuthlyResourceManager):
    """Create a public OAuth client using committed data."""
    pool = initialize_authly.get_pool()

    async with pool.connection() as conn:
        await conn.set_autocommit(True)

        client_repo = ClientRepository(conn)

        # Create public client
        client_id = f"public_client_{uuid4().hex[:8]}"

        client_data = {
            "client_id": client_id,
            "client_name": "Public Client",
            "client_type": ClientType.PUBLIC,
            "grant_types": [GrantType.AUTHORIZATION_CODE],
            "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            "redirect_uris": ["http://localhost/callback"],
        }
        created_client = await client_repo.create_client(client_data)

        result = {
            "client": created_client,
            "client_id": client_id,
            "client_secret": None,
        }

        yield result

        # Cleanup
        try:
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", client_id)
        except Exception:
            pass


class TestClientCredentialsGrant:
    """Test Client Credentials grant type for machine-to-machine auth."""

    @pytest.mark.asyncio
    async def test_client_credentials_grant_success(self, test_server, committed_client_with_scopes):
        """Test successful client credentials grant via HTTP."""
        client_id = committed_client_with_scopes["client_id"]
        client_secret = committed_client_with_scopes["client_secret"]
        read_scope = committed_client_with_scopes["read_scope"]

        async with test_server.client as client:
            # Use POST form authentication for client credentials
            response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": read_scope,
                },
            )

            if response.status_code != status.HTTP_200_OK:
                error_data = await response.json()
                print(f"Token request failed: {error_data}")

            assert response.status_code == status.HTTP_200_OK

            data = await response.json()
            assert "access_token" in data
            assert data["token_type"] == "Bearer"
            assert data["expires_in"] > 0
            assert read_scope in data.get("scope", "")

            # Client credentials should NOT issue refresh token
            assert data.get("refresh_token") is None

    @pytest.mark.asyncio
    async def test_client_credentials_requires_confidential_client(self, test_server, committed_public_client):
        """Test that client credentials grant requires confidential client."""
        client_id = committed_public_client["client_id"]

        async with test_server.client as client:
            response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": "dummy_secret",  # This should fail
                    "scope": "api.read",
                },
            )

            # Should fail because public clients can't use client credentials
            assert response.status_code == status.HTTP_400_BAD_REQUEST

            data = await response.json()
            # Either invalid_request (missing client_secret) or unauthorized_client are acceptable
            assert data["error"] in ["invalid_request", "unauthorized_client"]

    @pytest.mark.asyncio
    async def test_client_credentials_with_multiple_scopes(self, test_server, committed_client_with_scopes):
        """Test client credentials grant with multiple scopes."""
        client_id = committed_client_with_scopes["client_id"]
        client_secret = committed_client_with_scopes["client_secret"]
        read_scope = committed_client_with_scopes["read_scope"]
        write_scope = committed_client_with_scopes["write_scope"]

        async with test_server.client as client:
            response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": f"{read_scope} {write_scope}",
                },
            )

            assert response.status_code == status.HTTP_200_OK

            data = await response.json()
            assert "access_token" in data

            # Check both scopes are granted
            granted_scopes = data.get("scope", "").split()
            assert read_scope in granted_scopes
            assert write_scope in granted_scopes

    @pytest.mark.asyncio
    async def test_client_credentials_invalid_scope(self, test_server, committed_client_with_scopes):
        """Test client credentials grant with invalid scope."""
        client_id = committed_client_with_scopes["client_id"]
        client_secret = committed_client_with_scopes["client_secret"]

        async with test_server.client as client:
            response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "invalid.scope",
                },
            )

            # Debug: print what we got
            if response.status_code != status.HTTP_400_BAD_REQUEST:
                data = await response.json()
                print(f"Unexpected response: status={response.status_code}, data={data}")

            # Should fail with invalid scope
            assert response.status_code == status.HTTP_400_BAD_REQUEST

            data = await response.json()
            assert data["error"] == "invalid_scope"

    @pytest.mark.asyncio
    async def test_client_credentials_wrong_secret(self, test_server, committed_client_with_scopes):
        """Test client credentials grant with wrong client secret."""
        client_id = committed_client_with_scopes["client_id"]
        read_scope = committed_client_with_scopes["read_scope"]

        async with test_server.client as client:
            response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": "wrong_secret",
                    "scope": read_scope,
                },
            )

            # Debug: print what we got
            if response.status_code != status.HTTP_401_UNAUTHORIZED:
                data = await response.json()
                print(f"Wrong secret test - status={response.status_code}, data={data}")

            # Should fail with invalid client
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

            data = await response.json()
            assert data["error"] == "invalid_client"


class TestScopeValidation:
    """Test scope validation for client credentials flow."""

    @pytest.mark.asyncio
    async def test_scope_validation_for_client(self, test_server, committed_client_with_scopes):
        """Test that client can only request allowed scopes."""
        client_id = committed_client_with_scopes["client_id"]
        client_secret = committed_client_with_scopes["client_secret"]

        async with test_server.client as client:
            # Try to request a scope not allowed for this client
            response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "admin.access",  # Not in allowed_scopes
                },
            )

            # Should fail with invalid scope
            assert response.status_code == status.HTTP_400_BAD_REQUEST

            data = await response.json()
            assert data["error"] == "invalid_scope"

    @pytest.mark.asyncio
    async def test_default_scopes_when_none_requested(self, test_server, committed_client_with_scopes):
        """Test that default scopes are granted when none requested."""
        client_id = committed_client_with_scopes["client_id"]
        client_secret = committed_client_with_scopes["client_secret"]

        async with test_server.client as client:
            # Request token without specifying scopes
            response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    # No scope parameter
                },
            )

            assert response.status_code == status.HTTP_200_OK

            data = await response.json()
            assert "access_token" in data

            # Should have some default scopes or all allowed scopes
            # The exact behavior depends on the implementation
            scope = data.get("scope", "")
            assert len(scope) > 0  # Should have some scopes
