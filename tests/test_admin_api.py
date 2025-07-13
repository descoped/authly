"""
Tests for Admin API Router endpoints.

This module tests all admin API endpoints using real HTTP requests with
AsyncTestServer and real database integration with TransactionManager.
"""

import logging
import random
import string
from datetime import datetime, timezone
from typing import Dict, List
from uuid import uuid4

import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import TransactionManager

from authly import Authly
from authly.api.admin_middleware import setup_admin_middleware
from authly.api.admin_router import admin_router
from authly.auth.core import get_password_hash
from authly.bootstrap.admin_seeding import bootstrap_admin_system
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, OAuthClientCreateRequest, TokenEndpointAuthMethod
from authly.oauth.scope_repository import ScopeRepository
from authly.tokens import TokenRepository, TokenService
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


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
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=True,
            is_admin=True,  # Critical: Admin privileges
        )

        user_repo = UserRepository(conn)
        created_user = await user_repo.create(admin_user)

        return created_user


@pytest.fixture()
async def test_regular_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a test regular user without admin privileges."""
    async with transaction_manager.transaction() as conn:
        identifier = generate_random_identifier()
        regular_user = UserModel(
            id=uuid4(),
            username=f"user_{identifier}",
            email=f"user_{identifier}@example.com",
            password_hash=get_password_hash("UserTest123!"),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=True,
            is_admin=False,  # No admin privileges
        )

        user_repo = UserRepository(conn)
        created_user = await user_repo.create(regular_user)

        return created_user


@pytest.fixture()
async def admin_token_with_scopes(
    initialize_authly: Authly, test_admin_user: UserModel, transaction_manager: TransactionManager
) -> str:
    """Create admin token with all required admin scopes."""
    async with transaction_manager.transaction() as conn:
        # Only register admin scopes, don't create admin user (avoid conflict with bootstrap tests)
        from authly.bootstrap.admin_seeding import register_admin_scopes

        await register_admin_scopes(conn)

        # Create basic OAuth scopes that tests can use
        scope_repo = ScopeRepository(conn)
        from authly.oauth.scope_service import ScopeService

        scope_service = ScopeService(scope_repo)

        # Create basic scopes that tests might reference
        basic_scopes = [("read", "Read access", True, True), ("write", "Write access", False, True)]

        for scope_name, description, is_default, is_active in basic_scopes:
            try:
                await scope_service.create_scope(scope_name, description, is_default, is_active)
            except Exception:
                # Scope might already exist, ignore
                pass

        # Create token with admin scopes
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo)

        admin_scopes = [
            "admin:clients:read",
            "admin:clients:write",
            "admin:scopes:read",
            "admin:scopes:write",
            "admin:system:read",
        ]

        config = initialize_authly.get_config()
        # Create admin scopes as a single scope string
        admin_scope_string = " ".join(admin_scopes)
        token_pair = await token_service.create_token_pair(user=test_admin_user, scope=admin_scope_string)

        return token_pair.access_token


@pytest.fixture()
async def regular_user_token(
    initialize_authly: Authly, test_regular_user: UserModel, transaction_manager: TransactionManager
) -> str:
    """Create token for regular user without admin scopes."""
    async with transaction_manager.transaction() as conn:
        token_repo = TokenRepository(conn)
        token_service = TokenService(token_repo)

        token_pair = await token_service.create_token_pair(
            user=test_regular_user,
            scope="read write",  # Regular scopes, no admin scopes
        )

        return token_pair.access_token


@pytest.fixture()
async def test_oauth_client(transaction_manager: TransactionManager) -> Dict:
    """Create a test OAuth client in the database."""
    async with transaction_manager.transaction() as conn:
        client_repo = ClientRepository(conn)

        # Create basic scopes first
        scope_repo = ScopeRepository(conn)
        from authly.oauth.scope_service import ScopeService

        scope_service = ScopeService(scope_repo)

        # Create basic scopes that tests might reference
        basic_scopes = [("read", "Read access", True, True), ("write", "Write access", False, True)]

        for scope_name, description, is_default, is_active in basic_scopes:
            try:
                await scope_service.create_scope(scope_name, description, is_default, is_active)
            except Exception:
                # Scope might already exist, ignore
                pass

        client_request = OAuthClientCreateRequest(
            client_name="Test Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            scope="read write",
            require_pkce=True,
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        )

        # Create client using repository directly for test setup
        from authly.oauth.client_service import ClientService

        client_service = ClientService(client_repo, scope_repo)

        created_client = await client_service.create_client(client_request)
        return created_client.model_dump()


@pytest.fixture()
async def test_oauth_scope(transaction_manager: TransactionManager) -> Dict:
    """Create a test OAuth scope in the database."""
    async with transaction_manager.transaction() as conn:
        scope_repo = ScopeRepository(conn)

        from authly.oauth.models import OAuthScopeModel
        from authly.oauth.scope_service import ScopeService

        scope_service = ScopeService(scope_repo)

        scope_name = f"test_scope_{generate_random_identifier()}"
        description = "Test scope for API testing"
        is_default = False
        is_active = True

        created_scope = await scope_service.create_scope(scope_name, description, is_default, is_active)
        return created_scope.model_dump()


class TestAdminAPIHealthAndStatus:
    """Test admin API health and status endpoints."""

    @pytest.mark.asyncio
    async def test_admin_health_endpoint(self, test_server: AsyncTestServer):
        """Test admin health check endpoint."""
        # Test health endpoint (no auth required)
        response = await test_server.client.get("/admin/health")
        await response.expect_status(200)

        result = await response.json()
        assert result["status"] == "healthy"
        assert result["service"] == "authly-admin-api"

    @pytest.mark.asyncio
    async def test_admin_status_endpoint_with_auth(
        self, test_server: AsyncTestServer, admin_token_with_scopes: str, initialize_authly: Authly
    ):
        """Test admin status endpoint with proper authentication."""
        # Use the main app which has proper configuration

        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.get("/admin/status", headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert result["status"] == "operational"
        assert "database" in result
        assert "configuration" in result
        assert "statistics" in result

    @pytest.mark.asyncio
    async def test_admin_status_endpoint_without_auth(self, test_server: AsyncTestServer):
        """Test admin status endpoint without authentication."""

        response = await test_server.client.get("/admin/status")
        await response.expect_status(401)

    @pytest.mark.asyncio
    async def test_admin_status_endpoint_insufficient_permissions(
        self, test_server: AsyncTestServer, regular_user_token: str
    ):
        """Test admin status endpoint with regular user token."""

        headers = {"Authorization": f"Bearer {regular_user_token}"}
        response = await test_server.client.get("/admin/status", headers=headers)
        await response.expect_status(403)


class TestAdminAPIClientManagement:
    """Test admin API client management endpoints."""

    @pytest.mark.asyncio
    async def test_list_clients_success(
        self, test_server: AsyncTestServer, admin_token_with_scopes: str, test_oauth_client: Dict
    ):
        """Test listing OAuth clients with admin token."""

        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.get("/admin/clients", headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert isinstance(result, list)
        # Should include our test client
        client_ids = [client["client_id"] for client in result]
        assert test_oauth_client["client_id"] in client_ids

    @pytest.mark.asyncio
    async def test_list_clients_with_pagination(self, test_server: AsyncTestServer, admin_token_with_scopes: str):
        """Test listing OAuth clients with pagination parameters."""

        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.get("/admin/clients?limit=5&offset=0", headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert isinstance(result, list)
        assert len(result) <= 5  # Respects limit

    @pytest.mark.asyncio
    async def test_create_client_success(self, test_server: AsyncTestServer, admin_token_with_scopes: str):
        """Test creating new OAuth client."""

        client_data = {
            "client_name": "Test API Client",
            "client_type": "confidential",
            "redirect_uris": ["https://api.example.com/callback"],
            "scope": "read write",
            "require_pkce": True,
            "token_endpoint_auth_method": "client_secret_basic",
        }

        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.post("/admin/clients", json=client_data, headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert result["client_name"] == "Test API Client"
        assert result["client_type"] == "confidential"
        assert result["client_secret"] is not None  # Should have secret
        assert "client_id" in result

    @pytest.mark.asyncio
    async def test_create_public_client_success(self, test_server: AsyncTestServer, admin_token_with_scopes: str):
        """Test creating public OAuth client."""

        client_data = {
            "client_name": "Public Mobile App",
            "client_type": "public",
            "redirect_uris": ["com.example.app://callback"],
            "require_pkce": True,
            "token_endpoint_auth_method": "none",
        }

        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.post("/admin/clients", json=client_data, headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert result["client_name"] == "Public Mobile App"
        assert result["client_type"] == "public"
        assert result.get("client_secret") is None  # Public clients have no secret

    @pytest.mark.asyncio
    async def test_get_client_details(
        self, test_server: AsyncTestServer, admin_token_with_scopes: str, test_oauth_client: Dict
    ):
        """Test getting specific client details."""

        client_id = test_oauth_client["client_id"]
        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.get(f"/admin/clients/{client_id}", headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert result["client_id"] == client_id
        assert result["client_name"] == test_oauth_client["client_name"]
        assert "assigned_scopes" in result  # Should include scope information

    @pytest.mark.asyncio
    async def test_get_nonexistent_client(self, test_server: AsyncTestServer, admin_token_with_scopes: str):
        """Test getting details for non-existent client."""

        fake_client_id = str(uuid4())
        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.get(f"/admin/clients/{fake_client_id}", headers=headers)
        await response.expect_status(404)

    @pytest.mark.asyncio
    async def test_update_client(
        self, test_server: AsyncTestServer, admin_token_with_scopes: str, test_oauth_client: Dict
    ):
        """Test updating client information."""

        client_id = test_oauth_client["client_id"]
        update_data = {"client_name": "Updated Test Client", "client_uri": "https://updated.example.com"}

        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.put(f"/admin/clients/{client_id}", json=update_data, headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert result["client_name"] == "Updated Test Client"
        assert result["client_uri"] == "https://updated.example.com"

    @pytest.mark.asyncio
    async def test_delete_client(
        self, test_server: AsyncTestServer, admin_token_with_scopes: str, test_oauth_client: Dict
    ):
        """Test deactivating (deleting) a client."""

        client_id = test_oauth_client["client_id"]
        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.delete(f"/admin/clients/{client_id}", headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert result["client_id"] == client_id
        assert result["message"] == "Client deactivated successfully"


class TestAdminAPIScopeManagement:
    """Test admin API scope management endpoints."""

    @pytest.mark.asyncio
    async def test_list_scopes_success(
        self, test_server: AsyncTestServer, admin_token_with_scopes: str, test_oauth_scope: Dict
    ):
        """Test listing OAuth scopes with admin token."""

        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.get("/admin/scopes", headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert isinstance(result, list)
        # Should include our test scope
        scope_names = [scope["scope_name"] for scope in result]
        assert test_oauth_scope["scope_name"] in scope_names

    @pytest.mark.asyncio
    async def test_create_scope_success(self, test_server: AsyncTestServer, admin_token_with_scopes: str):
        """Test creating new OAuth scope."""

        scope_data = {
            "scope_name": f"api_test_{generate_random_identifier()}",
            "description": "Test scope created via API",
            "is_default": False,
            "is_active": True,
        }

        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.post("/admin/scopes", json=scope_data, headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert result["scope_name"] == scope_data["scope_name"]
        assert result["description"] == scope_data["description"]
        assert result["is_active"] is True

    @pytest.mark.asyncio
    async def test_get_scope_details(
        self, test_server: AsyncTestServer, admin_token_with_scopes: str, test_oauth_scope: Dict
    ):
        """Test getting specific scope details."""

        scope_name = test_oauth_scope["scope_name"]
        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.get(f"/admin/scopes/{scope_name}", headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert result["scope_name"] == scope_name
        assert result["description"] == test_oauth_scope["description"]

    @pytest.mark.asyncio
    async def test_update_scope(
        self, test_server: AsyncTestServer, admin_token_with_scopes: str, test_oauth_scope: Dict
    ):
        """Test updating scope information."""

        scope_name = test_oauth_scope["scope_name"]
        update_data = {"description": "Updated scope description", "is_default": True}

        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.put(f"/admin/scopes/{scope_name}", json=update_data, headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert result["description"] == "Updated scope description"
        assert result["is_default"] is True

    @pytest.mark.asyncio
    async def test_delete_scope(
        self, test_server: AsyncTestServer, admin_token_with_scopes: str, test_oauth_scope: Dict
    ):
        """Test deactivating (deleting) a scope."""

        scope_name = test_oauth_scope["scope_name"]
        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.delete(f"/admin/scopes/{scope_name}", headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert result["scope_name"] == scope_name
        assert result["message"] == "Scope deactivated successfully"

    @pytest.mark.asyncio
    async def test_get_default_scopes(self, test_server: AsyncTestServer, admin_token_with_scopes: str):
        """Test getting default scopes."""

        headers = {"Authorization": f"Bearer {admin_token_with_scopes}"}
        response = await test_server.client.get("/admin/scopes/defaults", headers=headers)
        await response.expect_status(200)

        result = await response.json()
        assert isinstance(result, list)


class TestAdminAPISecurityAndErrors:
    """Test admin API security and error handling."""

    @pytest.mark.asyncio
    async def test_admin_endpoints_require_authentication(self, test_server: AsyncTestServer):
        """Test that admin endpoints require authentication."""

        # Test various endpoints without authentication
        endpoints = ["/admin/status", "/admin/clients", "/admin/scopes", "/admin/users"]

        for endpoint in endpoints:
            response = await test_server.client.get(endpoint)
            await response.expect_status(401)

    @pytest.mark.asyncio
    async def test_admin_endpoints_require_admin_privileges(
        self, test_server: AsyncTestServer, regular_user_token: str
    ):
        """Test that admin endpoints require admin privileges."""

        headers = {"Authorization": f"Bearer {regular_user_token}"}

        # Test various endpoints with regular user token
        endpoints = ["/admin/status", "/admin/clients", "/admin/scopes"]

        for endpoint in endpoints:
            response = await test_server.client.get(endpoint, headers=headers)
            await response.expect_status(403)

    @pytest.mark.asyncio
    async def test_invalid_token_handling(self, test_server: AsyncTestServer):
        """Test handling of invalid JWT tokens."""

        headers = {"Authorization": "Bearer invalid_token"}
        response = await test_server.client.get("/admin/status", headers=headers)
        await response.expect_status(401)

    @pytest.mark.asyncio
    async def test_malformed_authorization_header(self, test_server: AsyncTestServer):
        """Test handling of malformed authorization headers."""

        # Test various malformed headers
        malformed_headers = [
            {"Authorization": "InvalidScheme token"},
            {"Authorization": "Bearer"},  # Missing token
            {"Authorization": ""},  # Empty
        ]

        for headers in malformed_headers:
            response = await test_server.client.get("/admin/status", headers=headers)
            await response.expect_status(401)
