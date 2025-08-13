"""Tests for OAuth 2.1 FastAPI dependencies using real integration testing."""

import base64
import logging

import pytest
from fastapi import status

logger = logging.getLogger(__name__)


class TestParseBasicAuthHeader:
    """Test cases for Basic Auth header parsing via real HTTP endpoints."""

    @pytest.mark.asyncio
    async def test_valid_basic_auth_header(self, test_server, committed_oauth_client):
        """Test parsing valid Basic Auth header through introspection endpoint."""
        client_id = committed_oauth_client["client_id"]
        client_secret = committed_oauth_client["client_secret"]

        # Create Basic Auth header
        credentials = f"{client_id}:{client_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Test via introspection endpoint which uses get_current_client dependency
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={"token": "dummy_token"},
        )

        # Should get 200 (token inactive) not 401 for auth failure
        # This proves the Basic Auth was parsed correctly
        assert response.status_code == status.HTTP_200_OK
        result = await response.json()
        assert result["active"] is False  # Token is invalid but auth worked

    @pytest.mark.asyncio
    async def test_basic_auth_header_public_client(self, test_server, committed_public_client):
        """Test parsing Basic Auth header for public client (empty secret)."""
        client_id = committed_public_client["client_id"]

        # Create Basic Auth header with empty secret
        credentials = f"{client_id}:"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Test via token endpoint
        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "grant_type": "authorization_code",
                "code": "invalid_code",  # Will fail but tests auth parsing
                "redirect_uri": committed_public_client["redirect_uris"][0],
            },
        )

        # Should get 400 for invalid code, not 401 for auth failure
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data["error"] in ["invalid_grant", "invalid_request"]

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="client_credentials grant type removed in OAuth 2.1")
    async def test_invalid_auth_scheme(self, test_server):
        """Test invalid authorization scheme raises HTTPException."""
        # Use Bearer instead of Basic
        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": "Bearer some_token"},
            data={
                "grant_type": "client_credentials",
                "scope": "read",
            },
        )

        # OAuth endpoints return 400 with error format, not 401
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data.get("error") == "invalid_client"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="client_credentials grant type removed in OAuth 2.1")
    async def test_invalid_base64_encoding(self, test_server):
        """Test invalid base64 encoding raises HTTPException."""
        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": "Basic invalid_base64!!!"},
            data={
                "grant_type": "client_credentials",
                "scope": "read",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data.get("error") == "invalid_client"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="client_credentials grant type removed in OAuth 2.1")
    async def test_missing_colon_separator(self, test_server):
        """Test missing colon separator raises HTTPException."""
        credentials = "test_client_no_colon"
        encoded = base64.b64encode(credentials.encode()).decode()

        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "grant_type": "client_credentials",
                "scope": "read",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data.get("error") == "invalid_client"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="client_credentials grant type removed in OAuth 2.1")
    async def test_empty_client_id(self, test_server):
        """Test empty client ID raises HTTPException."""
        credentials = ":test_secret"  # Empty client_id
        encoded = base64.b64encode(credentials.encode()).decode()

        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "grant_type": "client_credentials",
                "scope": "read",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data.get("error") == "invalid_client"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="client_credentials grant type removed in OAuth 2.1")
    async def test_unicode_decode_error(self, test_server):
        """Test unicode decode error raises HTTPException."""
        # Create invalid UTF-8 bytes
        invalid_bytes = b"\xff\xfe"
        encoded = base64.b64encode(invalid_bytes).decode()

        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "grant_type": "client_credentials",
                "scope": "read",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data.get("error") == "invalid_client"


class TestGetCurrentClientDependency:
    """Test cases for get_current_client FastAPI dependency using real HTTP endpoints."""

    @pytest.mark.asyncio
    async def test_http_basic_auth_confidential_client(self, test_server, committed_oauth_client):
        """Test HTTP Basic Authentication with confidential client."""
        client_id = committed_oauth_client["client_id"]
        client_secret = committed_oauth_client["client_secret"]

        # Create Basic Auth header
        credentials = f"{client_id}:{client_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Test authentication via introspection endpoint (requires client auth)
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={"token": "dummy_token"},  # Token doesn't need to be valid for this test
        )

        # Should get 200 (token inactive) not 401 (auth failure)
        assert response.status_code == status.HTTP_200_OK
        result = await response.json()
        assert result["active"] is False  # Token is invalid but auth worked

    @pytest.mark.asyncio
    async def test_http_basic_auth_public_client(self, test_server, committed_public_client):
        """Test HTTP Basic Authentication with public client (no secret)."""
        client_id = committed_public_client["client_id"]

        # Create Basic Auth header with empty password
        credentials = f"{client_id}:"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Public clients can't use introspection endpoint
        # Test with token endpoint instead
        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "grant_type": "authorization_code",
                "code": "dummy_code",
                "redirect_uri": committed_public_client["redirect_uris"][0],
                "code_verifier": "dummy_verifier",  # PKCE required for public clients
            },
        )

        # Should get 400 (invalid code) not 401 (auth failure)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data["error"] in ["invalid_grant", "invalid_request"]

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="client_credentials grant type removed in OAuth 2.1")
    async def test_invalid_client_credentials(self, test_server):
        """Test authentication failure with invalid credentials."""
        # Use non-existent client
        credentials = "invalid_client:invalid_secret"
        encoded = base64.b64encode(credentials.encode()).decode()

        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "grant_type": "client_credentials",
                "scope": "read",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data.get("error") == "invalid_client"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="client_credentials grant type removed in OAuth 2.1")
    async def test_missing_client_credentials(self, test_server):
        """Test authentication failure with missing credentials."""
        # No Authorization header
        response = await test_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "scope": "read",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data.get("error") == "invalid_client"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="client_credentials grant type removed in OAuth 2.1")
    async def test_confidential_client_wrong_secret(self, test_server, committed_oauth_client):
        """Test confidential client with wrong secret fails authentication."""
        client_id = committed_oauth_client["client_id"]

        # Use wrong secret
        credentials = f"{client_id}:wrong_secret"
        encoded = base64.b64encode(credentials.encode()).decode()

        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "grant_type": "client_credentials",
                "scope": "read",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data.get("error") == "invalid_client"

    @pytest.mark.asyncio
    async def test_public_client_with_secret_fails(self, test_server, committed_public_client):
        """Test public client providing secret fails authentication."""
        client_id = committed_public_client["client_id"]

        # Public client shouldn't have a secret
        credentials = f"{client_id}:unexpected_secret"
        encoded = base64.b64encode(credentials.encode()).decode()

        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "grant_type": "authorization_code",
                "code": "dummy_code",
                "redirect_uri": committed_public_client["redirect_uris"][0],
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        # Public client with secret can return invalid_request or invalid_client
        assert error_data.get("error") in ["invalid_client", "invalid_request"]

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="client_credentials grant type removed in OAuth 2.1")
    async def test_inactive_client_fails(self, test_server, db_pool):
        """Test inactive client fails authentication."""
        from uuid import uuid4

        from authly.oauth.client_repository import ClientRepository
        from authly.oauth.models import ClientType, GrantType, TokenEndpointAuthMethod

        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)

            # Create a client
            client_id = f"inactive_client_{uuid4().hex[:8]}"
            client_secret = f"secret_{uuid4().hex[:8]}"

            client_data = {
                "client_id": client_id,
                "client_name": "Inactive Test Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
                "redirect_uris": ["https://example.com/callback"],
                "grant_types": [GrantType.AUTHORIZATION_CODE],  # Changed from CLIENT_CREDENTIALS
                "is_active": True,
            }

            # Create with autocommit
            await conn.set_autocommit(True)
            created_client = await client_repo.create_client(client_data)

            # Deactivate the client
            await client_repo.delete_client(created_client.id)

        # Try to authenticate with deactivated client
        credentials = f"{client_id}:{client_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()

        response = await test_server.client.post(
            "/api/v1/oauth/token",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "grant_type": "client_credentials",
                "scope": "read",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = await response.json()
        assert error_data.get("error") == "invalid_client"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="client_credentials grant type removed in OAuth 2.1")
    async def test_form_data_authentication(self, test_server, db_pool):
        """Test client authentication via form data (CLIENT_SECRET_POST)."""
        from uuid import uuid4

        from authly.oauth.client_repository import ClientRepository
        from authly.oauth.models import ClientType, GrantType, TokenEndpointAuthMethod

        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)

            # Create a client with CLIENT_SECRET_POST auth method
            client_id = f"post_client_{uuid4().hex[:8]}"
            client_secret = f"secret_{uuid4().hex[:8]}"

            client_data = {
                "client_id": client_id,
                "client_name": "POST Auth Test Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_POST,
                "redirect_uris": ["https://example.com/callback"],
                "grant_types": [GrantType.AUTHORIZATION_CODE],  # Changed from CLIENT_CREDENTIALS
                "is_active": True,
            }

            # Create with autocommit
            await conn.set_autocommit(True)
            await client_repo.create_client(client_data)

        # Test authentication via form data (no Authorization header)
        response = await test_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "read",
            },
        )

        # Should get 400 for missing scope, not 401 for auth failure
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]
        if response.status_code == status.HTTP_400_BAD_REQUEST:
            error_data = await response.json()
            # Should be scope error, not auth error
            assert "scope" in error_data.get("error_description", "").lower() or "invalid_scope" in error_data.get(
                "error", ""
            )
