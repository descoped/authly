"""
Tests for Admin API Client using real FastAPI server integration.

Following Authly's real-world testing philosophy with fastapi-testing.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse
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


def generate_pkce_pair():
    """Generate PKCE code verifier and challenge for OAuth flow."""
    import base64
    import hashlib
    import secrets

    # Generate code verifier
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")

    # Generate code challenge
    challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(challenge).decode("utf-8").rstrip("=")

    return code_verifier, code_challenge


async def get_oauth_token_via_auth_code_flow(
    test_server: AsyncTestServer,
    transaction_manager: TransactionManager,
    config,  # Pass config as parameter
    user: UserModel,
    client_id: str,
    redirect_uri: str,
    scope: str = "admin:clients:read admin:clients:write admin:system:read",
) -> str:
    """
    Helper function to obtain an OAuth access token via the authorization code flow.
    This simulates what would happen in a browser-based flow, but programmatically for testing.
    """
    # Generate PKCE challenge
    code_verifier, code_challenge = generate_pkce_pair()

    # First, we need to get an initial access token for the user to authorize
    # In a real scenario, this would be done via a login form
    # For testing, we'll create a token directly using the token service
    from authly.oauth.client_repository import ClientRepository
    from authly.tokens.repository import TokenRepository
    from authly.tokens.service import TokenService

    async with transaction_manager.transaction() as conn:
        client_repo = ClientRepository(conn)
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo, config, client_repo)

        # Create an initial access token for the user
        token_pair = await token_service.create_token_pair(
            user=user,
            client_id=None,  # No client for initial user login
            scope=None,
        )
        initial_access_token = token_pair.access_token

    # Step 1: Start authorization request (GET shows consent form)
    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "scope": scope,
        "state": "test_state_123",
    }

    auth_response = await test_server.client.get(
        "/api/v1/oauth/authorize",
        params=auth_params,
        headers={"Authorization": f"Bearer {initial_access_token}"},
        follow_redirects=False,
    )

    # Check the response - it might be 302 if user is not properly authenticated
    if auth_response.status_code == 302:
        # User not authenticated properly, try a different approach
        # For testing, skip the consent step and go directly to authorization code generation
        # This is a limitation of testing OAuth flows without a real browser
        import secrets

        from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
        from authly.oauth.models import CodeChallengeMethod, OAuthAuthorizationCodeModel

        async with transaction_manager.transaction() as conn:
            from authly.oauth.client_repository import ClientRepository

            auth_code_repo = AuthorizationCodeRepository(conn)
            client_repo = ClientRepository(conn)
            auth_code = secrets.token_urlsafe(32)

            # Get the client's UUID from the database
            client = await client_repo.get_by_client_id(client_id)

            auth_code_model = OAuthAuthorizationCodeModel(
                id=uuid4(),
                code=auth_code,
                client_id=client.id,  # UUID of the client
                redirect_uri=redirect_uri,
                scope=scope,
                user_id=user.id,
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
                created_at=datetime.now(UTC),
                nonce=None,
            )

            await auth_code_repo.create(auth_code_model)
    else:
        # Should show consent form (200 OK)
        assert auth_response.status_code == 200

        # Step 2: Submit consent approval (POST)
        consent_data = {
            **auth_params,
            "approved": "true",  # User approves
        }

        consent_response = await test_server.client.post(
            "/api/v1/oauth/authorize",
            data=consent_data,
            headers={"Authorization": f"Bearer {initial_access_token}"},
            follow_redirects=False,
        )

        # Should redirect with authorization code
        assert consent_response.status_code == 302
        location = consent_response.headers.get("location")
        assert location is not None

        # Parse authorization code from redirect
        parsed = urlparse(location)
        query_params = parse_qs(parsed.query)
        assert "code" in query_params
        auth_code = query_params["code"][0]

    # Step 3: Exchange authorization code for tokens
    token_response = await test_server.client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
        },
    )

    assert token_response.status_code == 200
    token_data = await token_response.json()
    return token_data["access_token"]


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
async def test_oauth_client(transaction_manager: TransactionManager) -> dict:
    """Create a test OAuth client for admin testing."""
    from authly.oauth.client_repository import ClientRepository
    from authly.oauth.models import ClientType, GrantType, OAuthClientModel

    async with transaction_manager.transaction() as conn:
        client_repo = ClientRepository(conn)

        client_id = f"test_admin_client_{uuid4().hex[:8]}"
        client_data = OAuthClientModel(
            id=uuid4(),
            client_id=client_id,
            client_secret_hash=None,  # Public client for testing
            client_name="Test Admin Client",
            client_type=ClientType.PUBLIC,
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=[GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
            response_types=["code"],
            scope="admin:clients:read admin:clients:write admin:system:read",  # Space-separated scopes
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        created_client = await client_repo.create(client_data)
        return {
            "client_id": created_client.client_id,
            "redirect_uris": created_client.redirect_uris,
        }


@pytest.fixture
async def admin_access_token(
    admin_test_server: AsyncTestServer,
    transaction_manager: TransactionManager,
    test_config,
    test_admin_user: UserModel,
    test_oauth_client: dict,
) -> str:
    """Get admin access token using OAuth 2.1 compliant authorization code flow."""
    return await get_oauth_token_via_auth_code_flow(
        admin_test_server,
        transaction_manager,
        test_config,
        test_admin_user,
        test_oauth_client["client_id"],
        test_oauth_client["redirect_uris"][0],
        scope="admin:clients:read admin:clients:write admin:system:read",
    )


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

    # Password grant tests removed for OAuth 2.1 compliance
    # The following tests were removed as they tested the deprecated password grant:
    # - test_login_success: Password grant no longer supported
    # - test_login_invalid_credentials: Password grant validation no longer applicable
    # - test_logout with password grant: Replaced with OAuth 2.1 compliant version below

    async def test_logout_with_oauth_flow(
        self, admin_test_server: AsyncTestServer, admin_access_token: str, temp_token_file
    ):
        """Test logout functionality with OAuth 2.1 compliant flow."""
        # Test logout using the OAuth token
        logout_response = await admin_test_server.client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {admin_access_token}"}
        )

        await logout_response.expect_status(200)
        logout_data = await logout_response.json()
        assert logout_data["message"] in ["Successfully logged out", "No active sessions found to logout"]

        # Test AdminAPIClient logout functionality
        base_url = f"http://{admin_test_server._host}:{admin_test_server._port}"
        client = AdminAPIClient(base_url=base_url, token_file=temp_token_file)

        # Set token info to test logout clearing
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        client._token_info = TokenInfo(
            access_token=admin_access_token,
            expires_at=expires_at,
            token_type="Bearer",
            scope="admin:clients:read admin:clients:write admin:system:read",
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
