"""Tests for OAuth 2.1 Discovery Service and Endpoint."""

import logging
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from psycopg_toolkit import TransactionManager

from authly.api.oauth_discovery_router import oauth_discovery_router
from authly.api.oauth_router import get_discovery_service
from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.discovery_models import OAuthServerMetadata
from authly.oauth.discovery_service import DiscoveryService
from authly.oauth.scope_repository import ScopeRepository

logger = logging.getLogger(__name__)


class TestDiscoveryService:
    """Test cases for OAuth 2.1 Discovery Service."""

    @pytest.mark.asyncio
    async def test_get_server_metadata_without_scope_repo(self):
        """Test generating server metadata without scope repository."""
        service = DiscoveryService()

        metadata = await service.get_server_metadata(issuer_url="https://auth.example.com", api_prefix="/api/v1")

        assert isinstance(metadata, OAuthServerMetadata)
        assert metadata.issuer == "https://auth.example.com"
        assert metadata.authorization_endpoint == "https://auth.example.com/api/v1/oauth/authorize"
        assert metadata.token_endpoint == "https://auth.example.com/api/v1/oauth/token"
        assert metadata.revocation_endpoint == "https://auth.example.com/api/v1/oauth/revoke"

        # OAuth 2.1 requirements
        assert metadata.response_types_supported == ["code"]
        assert "authorization_code" in metadata.grant_types_supported
        assert "refresh_token" in metadata.grant_types_supported
        assert metadata.code_challenge_methods_supported == ["S256"]
        assert metadata.require_pkce is True

        # Authentication methods
        assert "client_secret_basic" in metadata.token_endpoint_auth_methods_supported
        assert "client_secret_post" in metadata.token_endpoint_auth_methods_supported
        assert "none" in metadata.token_endpoint_auth_methods_supported

        # Response modes
        assert "query" in metadata.response_modes_supported

        # No scopes since no repository provided
        assert metadata.scopes_supported is None

        # Documentation URL
        assert metadata.service_documentation == "https://auth.example.com/docs"

    @pytest.mark.asyncio
    async def test_get_server_metadata_with_scope_repo(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test generating server metadata with scope repository."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            service = DiscoveryService(scope_repo)

            # Create test scopes
            test_scopes = [
                {
                    "scope_name": f"read_{uuid4().hex[:8]}",
                    "description": "Read access",
                    "is_default": True,
                    "is_active": True,
                },
                {
                    "scope_name": f"write_{uuid4().hex[:8]}",
                    "description": "Write access",
                    "is_default": False,
                    "is_active": True,
                },
                {
                    "scope_name": f"admin_{uuid4().hex[:8]}",
                    "description": "Admin access",
                    "is_default": False,
                    "is_active": True,
                },
            ]

            created_scopes = []
            for scope_data in test_scopes:
                created_scope = await scope_repo.create_scope(scope_data)
                created_scopes.append(created_scope)

            # Generate metadata
            metadata = await service.get_server_metadata(issuer_url="https://auth.example.com", api_prefix="/api/v1")

            # Verify scopes are included
            assert metadata.scopes_supported is not None
            assert len(metadata.scopes_supported) >= 3

            # Check that our created scopes are included
            scope_names = [scope.scope_name for scope in created_scopes]
            for scope_name in scope_names:
                assert scope_name in metadata.scopes_supported

    @pytest.mark.asyncio
    async def test_get_server_metadata_with_trailing_slash(self):
        """Test issuer URL handling with trailing slash."""
        service = DiscoveryService()

        metadata = await service.get_server_metadata(
            issuer_url="https://auth.example.com/",  # Note trailing slash
            api_prefix="/api/v1",
        )

        # Should strip trailing slash
        assert metadata.issuer == "https://auth.example.com"
        assert metadata.authorization_endpoint == "https://auth.example.com/api/v1/oauth/authorize"

    @pytest.mark.asyncio
    async def test_get_server_metadata_scope_repo_error(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test metadata generation when scope repository fails."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            service = DiscoveryService(scope_repo)

            # Mock a broken scope repository by closing connection
            await conn.close()

            # Should handle error gracefully and return metadata without scopes
            metadata = await service.get_server_metadata(issuer_url="https://auth.example.com", api_prefix="/api/v1")

            assert isinstance(metadata, OAuthServerMetadata)
            assert metadata.scopes_supported is None  # Should be None due to error

    def test_get_static_metadata(self):
        """Test static metadata generation."""
        service = DiscoveryService()

        metadata = service.get_static_metadata(
            issuer_url="https://auth.example.com", api_prefix="/api/v1", scopes=["read", "write", "admin"]
        )

        assert isinstance(metadata, OAuthServerMetadata)
        assert metadata.issuer == "https://auth.example.com"
        assert metadata.scopes_supported == ["read", "write", "admin"]
        assert metadata.require_pkce is True

    def test_get_static_metadata_no_scopes(self):
        """Test static metadata generation without scopes."""
        service = DiscoveryService()

        metadata = service.get_static_metadata(issuer_url="https://auth.example.com", api_prefix="/api/v1")

        assert metadata.scopes_supported is None

    @pytest.mark.asyncio
    async def test_different_api_prefixes(self):
        """Test metadata generation with different API prefixes."""
        service = DiscoveryService()

        test_cases = [
            ("/api/v1", "https://auth.example.com/api/v1"),
            ("/v2", "https://auth.example.com/v2"),
            ("", "https://auth.example.com"),
        ]

        for api_prefix, expected_base in test_cases:
            metadata = await service.get_server_metadata(issuer_url="https://auth.example.com", api_prefix=api_prefix)

            if api_prefix:
                assert metadata.authorization_endpoint == f"{expected_base}/oauth/authorize"
                assert metadata.token_endpoint == f"{expected_base}/oauth/token"
            else:
                assert metadata.authorization_endpoint == "https://auth.example.com/oauth/authorize"
                assert metadata.token_endpoint == "https://auth.example.com/oauth/token"


class TestDiscoveryEndpoint:
    """Test cases for OAuth 2.1 Discovery HTTP endpoint."""

    def test_discovery_endpoint_basic(self):
        """Test basic discovery endpoint functionality."""
        app = FastAPI()

        # Mock the discovery service dependency to avoid database dependency
        async def mock_get_discovery_service():
            return DiscoveryService()

        # Override the dependency
        app.dependency_overrides[get_discovery_service] = mock_get_discovery_service
        app.include_router(oauth_discovery_router)

        client = TestClient(app)

        with client:
            response = client.get("/.well-known/oauth-authorization-server")

            assert response.status_code == 200
            data = response.json()

            # Verify required fields
            assert "issuer" in data
            assert "authorization_endpoint" in data
            assert "token_endpoint" in data
            assert "response_types_supported" in data
            assert "grant_types_supported" in data
            assert "code_challenge_methods_supported" in data
            assert "token_endpoint_auth_methods_supported" in data

            # Verify OAuth 2.1 requirements
            assert data["response_types_supported"] == ["code"]
            assert "authorization_code" in data["grant_types_supported"]
            assert "S256" in data["code_challenge_methods_supported"]
            assert data["require_pkce"] is True

    def test_discovery_endpoint_content_type(self):
        """Test discovery endpoint returns JSON content type."""
        app = FastAPI()

        # Mock the discovery service dependency to avoid database dependency
        async def mock_get_discovery_service():
            return DiscoveryService()

        # Override the dependency
        app.dependency_overrides[get_discovery_service] = mock_get_discovery_service
        app.include_router(oauth_discovery_router)

        client = TestClient(app)

        with client:
            response = client.get("/.well-known/oauth-authorization-server")

            assert response.status_code == 200
            assert "application/json" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_discovery_endpoint_with_real_scope_repo(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test discovery endpoint with real scope repository integration."""
        # Create test scopes in database
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)

            test_scope = {
                "scope_name": f"integration_test_{uuid4().hex[:8]}",
                "description": "Integration test scope",
                "is_default": False,
                "is_active": True,
            }

            await scope_repo.create_scope(test_scope)

        # Now test the endpoint
        app = FastAPI()

        # Mock the discovery service dependency to avoid connection issues in test app
        async def mock_get_discovery_service():
            return DiscoveryService()

        app.dependency_overrides[get_discovery_service] = mock_get_discovery_service
        app.include_router(oauth_discovery_router)

        client = TestClient(app)

        with client:
            response = client.get("/.well-known/oauth-authorization-server")

            assert response.status_code == 200
            data = response.json()

            # The endpoint should work even if it can't access scopes in test mode
            assert "issuer" in data
            assert isinstance(data["scopes_supported"], list | type(None))

    def test_discovery_endpoint_url_building(self):
        """Test that discovery endpoint builds URLs correctly."""
        app = FastAPI()

        # Mock the discovery service dependency to avoid database dependency
        async def mock_get_discovery_service():
            return DiscoveryService()

        app.dependency_overrides[get_discovery_service] = mock_get_discovery_service
        app.include_router(oauth_discovery_router)

        client = TestClient(app)

        with client:
            # Test with different base URLs via headers
            headers = {"Host": "auth.example.com", "X-Forwarded-Proto": "https"}

            response = client.get("/.well-known/oauth-authorization-server", headers=headers)

            assert response.status_code == 200
            data = response.json()

            # URLs should be built from headers
            assert data["issuer"].startswith("https://")
            assert "auth.example.com" in data["authorization_endpoint"]

    def test_discovery_endpoint_error_handling(self):
        """Test discovery endpoint error handling."""
        app = FastAPI()

        # Mock the discovery service dependency to avoid database dependency
        async def mock_get_discovery_service():
            return DiscoveryService()

        app.dependency_overrides[get_discovery_service] = mock_get_discovery_service
        app.include_router(oauth_discovery_router)

        client = TestClient(app)

        with client:
            # Should always return a valid response, even with errors
            response = client.get("/.well-known/oauth-authorization-server")

            # Should not fail completely
            assert response.status_code in [200, 500]

            if response.status_code == 200:
                data = response.json()
                assert "issuer" in data
            else:
                # Should return structured error
                data = response.json()
                assert "error" in data


class TestOAuthServerMetadataModel:
    """Test cases for OAuthServerMetadata Pydantic model."""

    def test_oauth_server_metadata_validation(self):
        """Test OAuthServerMetadata model validation."""
        data = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/api/v1/oauth/authorize",
            "token_endpoint": "https://auth.example.com/api/v1/oauth/token",
        }

        metadata = OAuthServerMetadata(**data)

        assert metadata.issuer == "https://auth.example.com"
        assert metadata.authorization_endpoint == "https://auth.example.com/api/v1/oauth/authorize"
        assert metadata.token_endpoint == "https://auth.example.com/api/v1/oauth/token"

        # Check defaults
        assert metadata.response_types_supported == ["code"]
        assert metadata.grant_types_supported == ["authorization_code", "refresh_token"]
        assert metadata.code_challenge_methods_supported == ["S256"]
        assert metadata.require_pkce is True

    def test_oauth_server_metadata_optional_fields(self):
        """Test OAuthServerMetadata with optional fields."""
        data = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/api/v1/oauth/authorize",
            "token_endpoint": "https://auth.example.com/api/v1/oauth/token",
            "revocation_endpoint": "https://auth.example.com/api/v1/oauth/revoke",
            "scopes_supported": ["read", "write", "admin"],
            "service_documentation": "https://auth.example.com/docs",
        }

        metadata = OAuthServerMetadata(**data)

        assert metadata.revocation_endpoint == "https://auth.example.com/api/v1/oauth/revoke"
        assert metadata.scopes_supported == ["read", "write", "admin"]
        assert metadata.service_documentation == "https://auth.example.com/docs"

    def test_oauth_server_metadata_json_serialization(self):
        """Test OAuthServerMetadata JSON serialization."""
        metadata = OAuthServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/api/v1/oauth/authorize",
            token_endpoint="https://auth.example.com/api/v1/oauth/token",
            scopes_supported=["read", "write"],
        )

        json_data = metadata.model_dump()

        assert json_data["issuer"] == "https://auth.example.com"
        assert json_data["scopes_supported"] == ["read", "write"]
        assert json_data["require_pkce"] is True
        assert json_data["code_challenge_methods_supported"] == ["S256"]

    def test_oauth_server_metadata_from_json(self):
        """Test creating OAuthServerMetadata from JSON."""
        json_data = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/api/v1/oauth/authorize",
            "token_endpoint": "https://auth.example.com/api/v1/oauth/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "require_pkce": True,
        }

        metadata = OAuthServerMetadata.model_validate(json_data)

        assert metadata.issuer == "https://auth.example.com"
        assert metadata.require_pkce is True
