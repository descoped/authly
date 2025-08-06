"""
Integration tests for Admin API Client with real server.
"""

import random
import string
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from psycopg_toolkit import TransactionManager

from authly.admin.api_client import AdminAPIClient, AdminAPIError
from authly.auth.core import get_password_hash
from authly.oauth.models import ClientType, OAuthClientCreateRequest
from authly.users.models import UserModel
from authly.users.repository import UserRepository


def generate_random_identifier(length: int = 10) -> str:
    """Generate a random string for testing."""
    return "".join(random.choices(string.ascii_lowercase, k=length))


@pytest.fixture()
async def test_admin_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a test admin user with proper privileges."""
    async with transaction_manager.transaction() as conn:
        identifier = generate_random_identifier()
        admin_user = UserModel(
            id=uuid4(),
            username=f"admin_{identifier}",
            email=f"admin_{identifier}@example.com",
            password_hash=get_password_hash("AdminTest123!"),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=True,
            is_admin=True,  # Critical: Admin privileges
        )

        user_repo = UserRepository(conn)
        created_user = await user_repo.create(admin_user)

        return created_user


@pytest.fixture()
async def admin_scopes_setup(transaction_manager: TransactionManager):
    """Ensure admin scopes are registered."""
    async with transaction_manager.transaction() as conn:
        from authly.bootstrap.admin_seeding import register_admin_scopes

        await register_admin_scopes(conn)


@pytest.fixture(autouse=True)
async def cleanup_tokens():
    """Clean up tokens between tests."""
    from pathlib import Path

    # Clean up before test
    token_file = Path.home() / ".authly" / "tokens.json"
    if token_file.exists():
        token_file.unlink()

    yield

    # Clean up after test
    if token_file.exists():
        token_file.unlink()


@pytest.mark.asyncio
class TestAdminAPIClientIntegration:
    """Integration tests for Admin API Client with real FastAPI server."""

    async def test_health_check(self, test_server):
        """Test health check endpoint."""
        async with AdminAPIClient(base_url=test_server.base_url) as client:
            health = await client.get_health()
            assert health["status"] == "healthy"

    async def test_authentication_flow(self, test_server, test_admin_user, admin_scopes_setup):
        """Test complete authentication flow."""
        async with AdminAPIClient(base_url=test_server.base_url) as client:
            # Initially not authenticated
            assert not client.is_authenticated

            # Login with admin user
            token_info = await client.login(
                username=test_admin_user.username,
                password="AdminTest123!",  # Default test password
                scope="admin:clients:read admin:clients:write admin:scopes:read admin:system:read",
            )

            assert token_info.access_token is not None
            assert client.is_authenticated

            # Get status (requires authentication)
            status = await client.get_status()
            assert "database" in status
            assert status["database"]["connected"] is True

            # Logout
            await client.logout()
            assert not client.is_authenticated

    async def test_client_operations(self, test_server, test_admin_user, admin_scopes_setup):
        """Test OAuth client CRUD operations."""
        async with AdminAPIClient(base_url=test_server.base_url) as client:
            # Login
            await client.login(
                username=test_admin_user.username,
                password="AdminTest123!",
                scope="admin:clients:read admin:clients:write",
            )

            # List clients (should be empty or contain test clients)
            clients = await client.list_clients()
            initial_count = len(clients)

            # Create a new client
            request = OAuthClientCreateRequest(
                client_name="Integration Test Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["http://localhost:3000/callback"],
                client_uri="https://example.com/test-client",
            )

            new_client, client_secret = await client.create_client(request)
            assert new_client.client_name == "Integration Test Client"
            assert new_client.client_type == ClientType.CONFIDENTIAL
            assert client_secret is not None  # Confidential client gets a secret

            # Get the specific client
            fetched_client = await client.get_client(new_client.client_id)
            assert fetched_client.client_id == new_client.client_id
            assert fetched_client.client_name == new_client.client_name

            # Update the client
            updated_client = await client.update_client(
                new_client.client_id,
                {
                    "client_uri": "https://example.com/updated-test-client",
                    "redirect_uris": ["http://localhost:3000/callback", "http://localhost:3000/auth"],
                },
            )
            assert updated_client.client_uri == "https://example.com/updated-test-client"
            assert len(updated_client.redirect_uris) == 2

            # List clients again
            clients = await client.list_clients()
            assert len(clients) == initial_count + 1

            # Delete the client
            result = await client.delete_client(new_client.client_id)
            assert "message" in result

    async def test_scope_operations(self, test_server, test_admin_user, admin_scopes_setup):
        """Test OAuth scope operations."""
        async with AdminAPIClient(base_url=test_server.base_url) as client:
            # Login
            await client.login(
                username=test_admin_user.username,
                password="AdminTest123!",
                scope="admin:scopes:read admin:scopes:write",
            )

            # List scopes
            scopes = await client.list_scopes()
            assert len(scopes) > 0  # Should have admin scopes from bootstrap

            # Get default scopes
            await client.get_default_scopes()
            # May or may not have defaults depending on test data

            # Create a new scope
            new_scope = await client.create_scope(
                name="test:integration", description="Integration test scope", is_default=False
            )
            assert new_scope.scope_name == "test:integration"
            assert new_scope.description == "Integration test scope"

            # Get the specific scope
            fetched_scope = await client.get_scope("test:integration")
            assert fetched_scope.scope_name == new_scope.scope_name

            # Update the scope
            updated_scope = await client.update_scope(
                "test:integration", description="Updated integration test scope", is_default=True
            )
            assert updated_scope.description == "Updated integration test scope"
            assert updated_scope.is_default is True

            # Delete the scope
            result = await client.delete_scope("test:integration")
            assert "message" in result

    async def test_token_refresh(self, test_server, test_admin_user, admin_scopes_setup):
        """Test token refresh functionality."""
        async with AdminAPIClient(base_url=test_server.base_url) as client:
            # Login to get initial tokens
            initial_token = await client.login(
                username=test_admin_user.username,
                password="AdminTest123!",
                scope="admin:clients:read admin:system:read",
            )

            assert initial_token.refresh_token is not None
            initial_access = initial_token.access_token

            # Refresh the token
            refreshed_token = await client.refresh_token()
            assert refreshed_token.access_token != initial_access
            assert client.is_authenticated

            # Verify we can still make API calls
            status = await client.get_status()
            assert status["database"]["connected"] is True

    async def test_unauthorized_access(self, test_server):
        """Test that unauthorized requests fail appropriately."""
        async with AdminAPIClient(base_url=test_server.base_url) as client:
            # Try to access protected endpoint without authentication
            with pytest.raises(ValueError, match="Not authenticated"):
                await client.get_status()

    async def test_invalid_credentials(self, test_server):
        """Test login with invalid credentials."""
        async with AdminAPIClient(base_url=test_server.base_url) as client:
            with pytest.raises(AdminAPIError) as exc_info:
                await client.login(username="invalid_user", password="wrong_password")

            # Verify it's an authentication error with user-friendly message
            assert exc_info.value.status_code == 401
            assert "Authentication failed" in exc_info.value.message
            assert "python -m authly admin login" in exc_info.value.message
