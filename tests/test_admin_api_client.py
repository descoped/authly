"""
Tests for Admin API Client.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from authly.admin.api_client import AdminAPIClient, TokenInfo
from authly.oauth.models import ClientType, OAuthClientCreateRequest, OAuthClientModel


@pytest.fixture
def temp_token_file(tmp_path):
    """Create a temporary token file path."""
    return tmp_path / "tokens.json"


@pytest.fixture
def mock_httpx_client():
    """Create a mock httpx client."""
    client = AsyncMock(spec=httpx.AsyncClient)
    return client


@pytest.fixture
async def api_client(temp_token_file, mock_httpx_client):
    """Create an API client with mocked HTTP client."""
    client = AdminAPIClient(base_url="http://localhost:8000", token_file=temp_token_file)
    # Replace the HTTP client with our mock
    client.client = mock_httpx_client
    yield client
    await client.close()


class TestAdminAPIClient:
    """Test Admin API Client functionality."""

    async def test_initialization(self, temp_token_file):
        """Test client initialization."""
        client = AdminAPIClient(
            base_url="http://localhost:8000/", token_file=temp_token_file, timeout=60.0, verify_ssl=False
        )

        assert client.base_url == "http://localhost:8000"
        assert client.timeout == 60.0
        assert client.verify_ssl is False
        assert client.token_file == temp_token_file
        assert not client.is_authenticated

        await client.close()

    async def test_default_token_file(self):
        """Test default token file location."""
        client = AdminAPIClient(base_url="http://localhost:8000")

        expected_path = Path.home() / ".authly" / "tokens.json"
        assert client.token_file == expected_path

        await client.close()

    async def test_token_storage(self, api_client, temp_token_file):
        """Test token save and load functionality."""
        # Create token info
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        token_info = TokenInfo(
            access_token="test_access_token",
            refresh_token="test_refresh_token",
            expires_at=expires_at,
            token_type="Bearer",
            scope="admin:clients:read admin:clients:write",
        )

        # Save token
        api_client._token_info = token_info
        api_client._save_tokens()

        # Verify file exists with correct permissions
        assert temp_token_file.exists()
        assert oct(temp_token_file.stat().st_mode)[-3:] == "600"

        # Load tokens in new client
        new_client = AdminAPIClient(base_url="http://localhost:8000", token_file=temp_token_file)

        assert new_client._token_info is not None
        assert new_client._token_info.access_token == "test_access_token"
        assert new_client._token_info.refresh_token == "test_refresh_token"
        assert new_client._token_info.scope == "admin:clients:read admin:clients:write"

        await new_client.close()

    async def test_is_authenticated(self, api_client):
        """Test authentication status checking."""
        # Not authenticated initially
        assert not api_client.is_authenticated

        # Set expired token
        expired_token = TokenInfo(
            access_token="expired_token", expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        api_client._token_info = expired_token
        assert not api_client.is_authenticated

        # Set valid token
        valid_token = TokenInfo(access_token="valid_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        api_client._token_info = valid_token
        assert api_client.is_authenticated

    async def test_login(self, api_client, mock_httpx_client):
        """Test login functionality."""
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "admin:clients:read admin:clients:write",
        }
        mock_httpx_client.request.return_value = mock_response

        # Login
        token_info = await api_client.login(
            username="admin", password="password123", scope="admin:clients:read admin:clients:write"
        )

        # Verify request
        mock_httpx_client.request.assert_called_once_with(
            method="POST",
            url="http://localhost:8000/api/v1/auth/token",
            json={
                "grant_type": "password",
                "username": "admin",
                "password": "password123",
                "scope": "admin:clients:read admin:clients:write",
            },
            params=None,
            headers={},
        )

        # Verify token info
        assert token_info.access_token == "new_access_token"
        assert token_info.refresh_token == "new_refresh_token"
        assert api_client.is_authenticated

    async def test_logout(self, api_client, mock_httpx_client):
        """Test logout functionality."""
        # Set token
        api_client._token_info = TokenInfo(
            access_token="test_access_token",
            refresh_token="test_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        # Mock revoke responses
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_httpx_client.request.return_value = mock_response

        # Logout
        await api_client.logout()

        # Verify revoke calls
        assert mock_httpx_client.request.call_count == 2

        # Verify tokens cleared
        assert api_client._token_info is None
        assert not api_client.is_authenticated

    async def test_refresh_token(self, api_client, mock_httpx_client):
        """Test token refresh functionality."""
        # Set initial token
        api_client._token_info = TokenInfo(
            access_token="old_access_token",
            refresh_token="refresh_token",
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )

        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_httpx_client.request.return_value = mock_response

        # Refresh
        token_info = await api_client.refresh_token()

        # Verify request
        mock_httpx_client.request.assert_called_with(
            method="POST",
            url="http://localhost:8000/api/v1/auth/refresh",
            json={"grant_type": "refresh_token", "refresh_token": "refresh_token"},
            params=None,
            headers={},
        )

        # Verify new token
        assert token_info.access_token == "new_access_token"
        assert token_info.refresh_token == "refresh_token"  # Kept old refresh token
        assert api_client.is_authenticated

    async def test_ensure_authenticated(self, api_client):
        """Test ensure_authenticated functionality."""
        # Not authenticated
        with pytest.raises(ValueError, match="Not authenticated"):
            await api_client.ensure_authenticated()

        # Expired token without refresh
        api_client._token_info = TokenInfo(
            access_token="expired_token", expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )

        with pytest.raises(ValueError, match="Token expired"):
            await api_client.ensure_authenticated()

        # Valid token
        api_client._token_info = TokenInfo(
            access_token="valid_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )

        await api_client.ensure_authenticated()  # Should not raise

    async def test_list_clients(self, api_client, mock_httpx_client):
        """Test list clients functionality."""
        # Set valid token
        api_client._token_info = TokenInfo(
            access_token="valid_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )

        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "client_id": "test_client_1",
                "client_name": "Test Client 1",
                "client_type": "confidential",
                "redirect_uris": ["http://localhost:3000/callback"],
                "is_active": True,
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2025-01-01T00:00:00Z",
            }
        ]
        mock_httpx_client.request.return_value = mock_response

        # List clients
        clients = await api_client.list_clients(active_only=True, limit=10)

        # Verify request
        mock_httpx_client.request.assert_called_with(
            method="GET",
            url="http://localhost:8000/admin/clients",
            json=None,
            params={"active_only": True, "limit": 10, "offset": 0},
            headers={"Authorization": "Bearer valid_token"},
        )

        # Verify response
        assert len(clients) == 1
        assert clients[0].client_id == "test_client_1"
        assert clients[0].client_name == "Test Client 1"

    async def test_create_client(self, api_client, mock_httpx_client):
        """Test create client functionality."""
        # Set valid token
        api_client._token_info = TokenInfo(
            access_token="valid_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )

        # Mock responses for create_client workflow
        create_response = MagicMock()
        create_response.status_code = 200
        create_response.json.return_value = {
            "client_id": "new_client_id",
            "client_secret": "super_secret_value",
            "client_type": "confidential",
            "client_name": "New Client",
        }

        get_response = MagicMock()
        get_response.status_code = 200
        get_response.json.return_value = {
            "id": "550e8400-e29b-41d4-a716-446655440001",
            "client_id": "new_client_id",
            "client_name": "New Client",
            "client_type": "confidential",
            "redirect_uris": ["http://localhost:3000/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "is_active": True,
            "require_pkce": True,
            "token_endpoint_auth_method": "client_secret_basic",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }

        # Setup side_effect to return different responses for different calls
        mock_httpx_client.request.side_effect = [create_response, get_response]

        # Create request
        request = OAuthClientCreateRequest(
            client_name="New Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["http://localhost:3000/callback"],
        )

        # Create client
        client, secret = await api_client.create_client(request)

        # Verify both requests were made
        assert mock_httpx_client.request.call_count == 2

        # Check first call (POST to create)
        first_call = mock_httpx_client.request.call_args_list[0]
        assert first_call[1]["method"] == "POST"
        assert first_call[1]["url"] == "http://localhost:8000/admin/clients"
        assert first_call[1]["json"] == request.model_dump()

        # Check second call (GET to retrieve full client)
        second_call = mock_httpx_client.request.call_args_list[1]
        assert second_call[1]["method"] == "GET"
        assert second_call[1]["url"] == "http://localhost:8000/admin/clients/new_client_id"

        # Verify response
        assert client.client_id == "new_client_id"
        assert client.client_name == "New Client"
        assert secret == "super_secret_value"

    async def test_context_manager(self):
        """Test context manager functionality."""
        async with AdminAPIClient(base_url="http://localhost:8000") as client:
            assert isinstance(client, AdminAPIClient)
            assert client.client is not None

        # Client should be closed after context exit
        # (In real implementation, this would verify the HTTP client is closed)
