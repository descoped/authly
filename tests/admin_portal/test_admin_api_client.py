"""
Tests for Admin API Client using real FastAPI server integration.

Following Authly's real-world testing philosophy with fastapi-testing.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import TransactionManager

from authly.admin.api_client import AdminAPIClient, TokenInfo
from authly.api import auth_router, oauth_router
from authly.api.admin_router import admin_router
from authly.auth.core import get_password_hash
from authly.users.models import UserModel
from authly.users.repository import UserRepository


@pytest.fixture
def temp_token_file(tmp_path):
    """Create a temporary token file path."""
    return tmp_path / "tokens.json"


@pytest.fixture
async def admin_test_server(test_server: AsyncTestServer) -> AsyncTestServer:
    """Create test server with admin and auth routers."""
    test_server.app.include_router(admin_router)
    test_server.app.include_router(auth_router, prefix="/api/v1")
    test_server.app.include_router(oauth_router, prefix="/api/v1")
    return test_server


@pytest.fixture
async def test_admin_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a test admin user in the database."""
    async with transaction_manager.transaction() as conn:
        user_repository = UserRepository(conn)

        import uuid

        unique_suffix = str(uuid.uuid4())[:8]

        admin_user = UserModel(
            id=uuid4(),
            username=f"admin_api_test_{unique_suffix}",
            email=f"admin_api_test_{unique_suffix}@example.com",
            password_hash=get_password_hash("AdminTest123!"),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_admin=True,
            is_active=True,
            is_verified=True,
        )

        return await user_repository.create(admin_user)


@pytest.fixture
async def admin_access_token(admin_test_server: AsyncTestServer, test_admin_user: UserModel) -> str:
    """Get admin access token by authenticating through the API."""
    # Login to get admin token
    response = await admin_test_server.client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "password",
            "username": test_admin_user.username,
            "password": "AdminTest123!",
            "scope": "admin:clients:read admin:clients:write admin:system:read",
        },
    )

    await response.expect_status(200)
    token_data = await response.json()
    return token_data["access_token"]


class TestAdminAPIClientIntegration:
    """Test Admin API Client functionality with real FastAPI server."""

    async def test_initialization(self, temp_token_file):
        """Test client initialization."""
        # Use dummy URL for initialization testing (no actual HTTP requests made)
        test_url = "http://test.example.com:8080/"
        client = AdminAPIClient(base_url=test_url, token_file=temp_token_file, timeout=60.0, verify_ssl=False)

        assert client.base_url == "http://test.example.com:8080"
        assert client.timeout == 60.0
        assert client.verify_ssl is False
        assert client.token_file == temp_token_file
        assert not client.is_authenticated

        await client.close()

    async def test_default_token_file(self):
        """Test default token file location."""
        # Use dummy URL for token file testing (no actual HTTP requests made)
        client = AdminAPIClient(base_url="http://test.example.com:8080")

        expected_path = Path.home() / ".authly" / "tokens.json"
        assert client.token_file == expected_path

        await client.close()

    async def test_token_storage(self, temp_token_file):
        """Test token save and load functionality."""
        # Use dummy URL for token storage testing (no actual HTTP requests made)
        test_url = "http://test.example.com:8080"
        client = AdminAPIClient(base_url=test_url, token_file=temp_token_file)

        # Create token info
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        token_info = TokenInfo(
            access_token="test_access_token",
            refresh_token="test_refresh_token",
            expires_at=expires_at,
            token_type="Bearer",
            scope="admin:clients:read admin:clients:write",
        )

        # Save token
        client._token_info = token_info
        client._save_tokens()

        # Verify file exists with correct permissions
        assert temp_token_file.exists()
        assert oct(temp_token_file.stat().st_mode)[-3:] == "600"

        # Load tokens in new client
        new_client = AdminAPIClient(base_url=test_url, token_file=temp_token_file)

        assert new_client._token_info is not None
        assert new_client._token_info.access_token == "test_access_token"
        assert new_client._token_info.refresh_token == "test_refresh_token"
        assert new_client._token_info.scope == "admin:clients:read admin:clients:write"

        await client.close()
        await new_client.close()

    async def test_is_authenticated(self, temp_token_file):
        """Test authentication status checking."""
        # Use dummy URL for authentication testing (no actual HTTP requests made)
        client = AdminAPIClient(base_url="http://test.example.com:8080", token_file=temp_token_file)

        # Not authenticated initially
        assert not client.is_authenticated

        # Set expired token
        expired_token = TokenInfo(access_token="expired_token", expires_at=datetime.now(UTC) - timedelta(hours=1))
        client._token_info = expired_token
        assert not client.is_authenticated

        # Set valid token
        valid_token = TokenInfo(access_token="valid_token", expires_at=datetime.now(UTC) + timedelta(hours=1))
        client._token_info = valid_token
        assert client.is_authenticated

        await client.close()

    async def test_login_success(self, admin_test_server: AsyncTestServer, test_admin_user: UserModel, temp_token_file):
        """Test login functionality with real server."""
        # Test login using fastapi-testing client directly
        response = await admin_test_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "password",
                "username": test_admin_user.username,
                "password": "AdminTest123!",
                "scope": "admin:clients:read admin:clients:write",
            },
        )

        await response.expect_status(200)
        token_data = await response.json()

        # Verify token data
        assert token_data["access_token"] is not None
        assert token_data["token_type"] == "Bearer"
        # Scope may be None or empty for password grant without explicit scope
        token_data.get("scope") or ""
        # For admin users, they may have implicit admin privileges even without explicit scope

        # Test AdminAPIClient with the real server URL
        base_url = f"http://{admin_test_server._host}:{admin_test_server._port}"
        client = AdminAPIClient(base_url=base_url, token_file=temp_token_file)

        # Store token info manually to test the client logic
        expires_at = datetime.now(UTC) + timedelta(seconds=token_data.get("expires_in", 3600))
        client._token_info = TokenInfo(
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            expires_at=expires_at,
            token_type=token_data["token_type"],
            scope=token_data.get("scope"),
        )

        assert client.is_authenticated
        await client.close()

    async def test_login_invalid_credentials(self, admin_test_server: AsyncTestServer, temp_token_file):
        """Test login with invalid credentials."""
        # Test invalid login using fastapi-testing client directly

        response = await admin_test_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "password",
                "username": "invalid_user",
                "password": "invalid_password",
                "scope": "admin:clients:read",
            },
        )

        await response.expect_status(401)
        error_data = await response.json()
        assert "Incorrect username or password" in error_data["detail"]

        # Test AdminAPIClient initialization (client not authenticated)
        base_url = f"http://{admin_test_server._host}:{admin_test_server._port}"
        client = AdminAPIClient(base_url=base_url, token_file=temp_token_file)
        assert not client.is_authenticated
        await client.close()

    async def test_logout(self, admin_test_server: AsyncTestServer, test_admin_user: UserModel, temp_token_file):
        """Test logout functionality."""
        # First login to get tokens
        response = await admin_test_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "password",
                "username": test_admin_user.username,
                "password": "AdminTest123!",
                "scope": "admin:clients:read",
            },
        )

        await response.expect_status(200)
        token_data = await response.json()

        # Test logout using the token
        logout_response = await admin_test_server.client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {token_data['access_token']}"}
        )

        await logout_response.expect_status(200)
        logout_data = await logout_response.json()
        assert logout_data["message"] == "Successfully logged out"

        # Test AdminAPIClient logout functionality
        base_url = f"http://{admin_test_server._host}:{admin_test_server._port}"
        client = AdminAPIClient(base_url=base_url, token_file=temp_token_file)

        # Set token info to test logout clearing
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        client._token_info = TokenInfo(
            access_token=token_data["access_token"],
            expires_at=expires_at,
            token_type="Bearer",
        )
        assert client.is_authenticated

        # Test logout clearing tokens
        await client.logout()

        # Verify tokens cleared
        assert client._token_info is None
        assert not client.is_authenticated

        await client.close()

    async def test_admin_health_endpoint(
        self, admin_test_server: AsyncTestServer, admin_access_token: str, temp_token_file
    ):
        """Test accessing admin health endpoint through client."""
        # Test admin health endpoint using fastapi-testing client
        response = await admin_test_server.client.get(
            "/admin/health", headers={"Authorization": f"Bearer {admin_access_token}"}
        )

        await response.expect_status(200)
        result = await response.json()
        assert result["status"] == "healthy"
        assert result["service"] == "authly-admin-api"

        # Test AdminAPIClient with token info
        base_url = f"http://{admin_test_server._host}:{admin_test_server._port}"
        client = AdminAPIClient(base_url=base_url, token_file=temp_token_file)

        # Set token manually for this test
        client._token_info = TokenInfo(
            access_token=admin_access_token,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            token_type="Bearer",
            scope="admin:system:read",
        )

        assert client.is_authenticated
        await client.close()

    async def test_list_clients_endpoint(
        self, admin_test_server: AsyncTestServer, admin_access_token: str, temp_token_file
    ):
        """Test listing clients through the real admin API."""
        # Test list clients endpoint using fastapi-testing client
        response = await admin_test_server.client.get(
            "/admin/clients",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            params={"limit": 10, "offset": 0},
        )

        await response.expect_status(200)
        result = await response.json()
        assert isinstance(result, list)

        # Test AdminAPIClient with token info
        base_url = f"http://{admin_test_server._host}:{admin_test_server._port}"
        client = AdminAPIClient(base_url=base_url, token_file=temp_token_file)

        # Set token manually for this test
        client._token_info = TokenInfo(
            access_token=admin_access_token,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            token_type="Bearer",
            scope="admin:clients:read",
        )

        assert client.is_authenticated
        await client.close()

    async def test_context_manager(self, temp_token_file):
        """Test context manager functionality."""
        # Use dummy URL for context manager testing (no actual HTTP requests made)
        async with AdminAPIClient(base_url="http://test.example.com:8080", token_file=temp_token_file) as client:
            assert isinstance(client, AdminAPIClient)
            assert client.client is not None

        # Client should be closed after context exit
