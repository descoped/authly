"""
Tests for OIDC Discovery endpoint and service.
"""

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from psycopg_toolkit import TransactionManager
from unittest.mock import Mock, AsyncMock

from authly.api.oidc_router import get_base_url, oidc_discovery
from authly.oauth.discovery_service import DiscoveryService
from authly.oauth.scope_repository import ScopeRepository
from authly.oidc.discovery import OIDCDiscoveryService, OIDCServerMetadata


class TestOIDCDiscoveryService:
    """Test OIDC Discovery Service functionality."""
    
    @pytest.fixture
    def mock_oauth_discovery_service(self):
        """Create mock OAuth discovery service."""
        service = Mock(spec=DiscoveryService)
        service.get_server_metadata = AsyncMock()
        return service
    
    @pytest.fixture
    def oidc_discovery_service(self, mock_oauth_discovery_service):
        """Create OIDC discovery service with mocked OAuth service."""
        return OIDCDiscoveryService(mock_oauth_discovery_service)
    
    @pytest.fixture
    def sample_oauth_metadata(self):
        """Sample OAuth metadata for testing."""
        from authly.oauth.discovery_models import OAuthServerMetadata
        return OAuthServerMetadata(
            issuer="https://test.example.com",
            authorization_endpoint="https://test.example.com/api/v1/oauth/authorize",
            token_endpoint="https://test.example.com/api/v1/auth/token",
            revocation_endpoint="https://test.example.com/api/v1/auth/revoke",
            response_types_supported=["code"],
            grant_types_supported=["authorization_code", "refresh_token"],
            code_challenge_methods_supported=["S256"],
            token_endpoint_auth_methods_supported=["client_secret_basic", "client_secret_post", "none"],
            scopes_supported=["read", "write", "admin"],
            require_pkce=True,
            response_modes_supported=["query"]
        )
    
    async def test_get_oidc_server_metadata(self, oidc_discovery_service, mock_oauth_discovery_service, sample_oauth_metadata):
        """Test OIDC server metadata generation."""
        # Setup mock
        mock_oauth_discovery_service.get_server_metadata.return_value = sample_oauth_metadata
        
        # Generate OIDC metadata
        metadata = await oidc_discovery_service.get_oidc_server_metadata(
            issuer_url="https://test.example.com",
            api_prefix="/api/v1"
        )
        
        # Verify OIDC-specific fields
        assert isinstance(metadata, OIDCServerMetadata)
        assert metadata.issuer == "https://test.example.com"
        assert metadata.userinfo_endpoint == "https://test.example.com/api/v1/oidc/userinfo"
        assert metadata.jwks_uri == "https://test.example.com/.well-known/jwks.json"
        
        # Verify OAuth fields are preserved
        assert metadata.authorization_endpoint == sample_oauth_metadata.authorization_endpoint
        assert metadata.token_endpoint == sample_oauth_metadata.token_endpoint
        assert metadata.revocation_endpoint == sample_oauth_metadata.revocation_endpoint
        
        # Verify OIDC extensions - only advertise actually supported flows
        assert "code" in metadata.response_types_supported
        assert "id_token" not in metadata.response_types_supported  # Not implemented
        assert "code id_token" not in metadata.response_types_supported  # Not implemented
        assert "RS256" in metadata.id_token_signing_alg_values_supported
        assert "HS256" in metadata.id_token_signing_alg_values_supported
        assert "public" in metadata.subject_types_supported
        
        # Verify OIDC scopes are included
        assert "openid" in metadata.scopes_supported
        assert "profile" in metadata.scopes_supported
        assert "email" in metadata.scopes_supported
        
        # Verify OAuth scopes are preserved
        assert "read" in metadata.scopes_supported
        assert "write" in metadata.scopes_supported
        assert "admin" in metadata.scopes_supported
        
        # Verify OIDC claims
        assert "sub" in metadata.claims_supported
        assert "name" in metadata.claims_supported
        assert "email" in metadata.claims_supported
        assert "profile" in metadata.claims_supported
        
        # Verify OAuth 2.1 requirements
        assert metadata.require_pkce is True
        assert "S256" in metadata.code_challenge_methods_supported
        
        # Verify response modes - only advertise supported modes
        assert "query" in metadata.response_modes_supported
        assert "fragment" not in metadata.response_modes_supported  # Not needed for auth code flow
    
    def test_get_static_oidc_metadata(self, oidc_discovery_service):
        """Test static OIDC metadata generation."""
        metadata = oidc_discovery_service.get_static_oidc_metadata("https://test.example.com")
        
        # Verify basic structure
        assert isinstance(metadata, OIDCServerMetadata)
        assert metadata.issuer == "https://test.example.com"
        assert metadata.userinfo_endpoint == "https://test.example.com/api/v1/oidc/userinfo"
        assert metadata.jwks_uri == "https://test.example.com/.well-known/jwks.json"
        
        # Verify standard OIDC scopes
        assert "openid" in metadata.scopes_supported
        assert "profile" in metadata.scopes_supported
        assert "email" in metadata.scopes_supported
        assert "address" in metadata.scopes_supported
        assert "phone" in metadata.scopes_supported
        
        # Verify standard claims
        assert "sub" in metadata.claims_supported
        assert "name" in metadata.claims_supported
        assert "email" in metadata.claims_supported
        assert "email_verified" in metadata.claims_supported
        assert "phone_number" in metadata.claims_supported
        assert "address" in metadata.claims_supported
        
        # Verify OAuth 2.1 compliance
        assert metadata.require_pkce is True
        assert "S256" in metadata.code_challenge_methods_supported
    
    async def test_oidc_metadata_with_custom_issuer(self, oidc_discovery_service, mock_oauth_discovery_service, sample_oauth_metadata):
        """Test OIDC metadata with custom issuer URL."""
        # Setup mock with custom issuer
        custom_metadata = sample_oauth_metadata.model_copy()
        custom_metadata.issuer = "https://auth.custom.com"
        mock_oauth_discovery_service.get_server_metadata.return_value = custom_metadata
        
        # Generate OIDC metadata
        metadata = await oidc_discovery_service.get_oidc_server_metadata(
            issuer_url="https://auth.custom.com",
            api_prefix="/api/v1"
        )
        
        # Verify custom issuer is used
        assert metadata.issuer == "https://auth.custom.com"
        assert metadata.userinfo_endpoint == "https://auth.custom.com/api/v1/oidc/userinfo"
        assert metadata.jwks_uri == "https://auth.custom.com/.well-known/jwks.json"


class TestOIDCDiscoveryRouter:
    """Test OIDC Discovery Router functionality."""
    
    def test_get_base_url_normal_request(self):
        """Test base URL extraction from normal request."""
        # Mock request with normal headers
        request = Mock(spec=Request)
        request.url.scheme = "https"
        request.url.netloc = "auth.example.com"
        request.headers = {}
        
        base_url = get_base_url(request)
        assert base_url == "https://auth.example.com"
    
    def test_get_base_url_with_forwarded_headers(self):
        """Test base URL extraction with forwarded headers."""
        # Mock request with forwarded headers
        request = Mock(spec=Request)
        request.url.scheme = "http"
        request.url.netloc = "localhost:8000"
        request.headers = {
            "x-forwarded-proto": "https",
            "x-forwarded-host": "auth.example.com"
        }
        
        base_url = get_base_url(request)
        assert base_url == "https://auth.example.com"
    
    def test_get_base_url_with_host_header(self):
        """Test base URL extraction with host header."""
        # Mock request with host header
        request = Mock(spec=Request)
        request.url.scheme = "https"
        request.url.netloc = "localhost:8000"
        request.headers = {"host": "auth.example.com"}
        
        base_url = get_base_url(request)
        assert base_url == "https://auth.example.com"


class TestOIDCDiscoveryIntegration:
    """Integration tests for OIDC Discovery endpoint."""
    
    @pytest.fixture
    def sample_oauth_metadata(self):
        """Sample OAuth metadata for testing."""
        from authly.oauth.discovery_models import OAuthServerMetadata
        return OAuthServerMetadata(
            issuer="https://test.example.com",
            authorization_endpoint="https://test.example.com/api/v1/oauth/authorize",
            token_endpoint="https://test.example.com/api/v1/auth/token",
            revocation_endpoint="https://test.example.com/api/v1/auth/revoke",
            response_types_supported=["code"],
            grant_types_supported=["authorization_code", "refresh_token"],
            code_challenge_methods_supported=["S256"],
            token_endpoint_auth_methods_supported=["client_secret_basic", "client_secret_post", "none"],
            scopes_supported=["read", "write", "admin"],
            require_pkce=True,
            response_modes_supported=["query"]
        )
    
    async def test_oidc_discovery_endpoint_success(self, sample_oauth_metadata):
        """Test successful OIDC discovery endpoint response."""
        # Mock OAuth discovery service
        mock_oauth_service = Mock(spec=DiscoveryService)
        mock_oauth_service.get_server_metadata = AsyncMock(return_value=sample_oauth_metadata)
        
        # Mock request
        request = Mock(spec=Request)
        request.url.scheme = "https"
        request.url.netloc = "test.example.com"
        request.headers = {}
        request.client.host = "127.0.0.1"
        
        # Call endpoint
        metadata = await oidc_discovery(request, mock_oauth_service)
        
        # Verify response
        assert isinstance(metadata, OIDCServerMetadata)
        assert metadata.issuer == "https://test.example.com"
        assert metadata.userinfo_endpoint == "https://test.example.com/api/v1/oidc/userinfo"
        assert "openid" in metadata.scopes_supported
        assert "profile" in metadata.scopes_supported
        assert "sub" in metadata.claims_supported
    
    async def test_oidc_discovery_endpoint_fallback(self):
        """Test OIDC discovery endpoint fallback to static metadata."""
        # Mock OAuth discovery service that raises exception
        mock_oauth_service = Mock(spec=DiscoveryService)
        mock_oauth_service.get_server_metadata = AsyncMock(side_effect=Exception("Database error"))
        
        # Mock request
        request = Mock(spec=Request)
        request.url.scheme = "https"
        request.url.netloc = "test.example.com"
        request.headers = {}
        request.client.host = "127.0.0.1"
        
        # Call endpoint - should return static metadata
        metadata = await oidc_discovery(request, mock_oauth_service)
        
        # Verify fallback response
        assert isinstance(metadata, OIDCServerMetadata)
        assert metadata.issuer == "https://test.example.com"
        assert metadata.userinfo_endpoint == "https://test.example.com/api/v1/oidc/userinfo"
        assert "openid" in metadata.scopes_supported
        assert "profile" in metadata.scopes_supported


class TestOIDCDiscoveryCompliance:
    """Test OIDC Discovery compliance with OpenID Connect specification."""
    
    @pytest.fixture
    def oidc_discovery_service(self):
        """Create OIDC discovery service with real OAuth service."""
        mock_oauth_service = Mock(spec=DiscoveryService)
        return OIDCDiscoveryService(mock_oauth_service)
    
    def test_oidc_metadata_required_fields(self, oidc_discovery_service):
        """Test that OIDC metadata contains all required fields."""
        metadata = oidc_discovery_service.get_static_oidc_metadata("https://test.example.com")
        
        # Required fields per OpenID Connect Discovery 1.0
        assert hasattr(metadata, 'issuer')
        assert hasattr(metadata, 'authorization_endpoint')
        assert hasattr(metadata, 'token_endpoint')
        assert hasattr(metadata, 'userinfo_endpoint')
        assert hasattr(metadata, 'jwks_uri')
        assert hasattr(metadata, 'response_types_supported')
        assert hasattr(metadata, 'subject_types_supported')
        assert hasattr(metadata, 'id_token_signing_alg_values_supported')
        
        # Verify required values
        assert metadata.issuer is not None
        assert metadata.authorization_endpoint is not None
        assert metadata.token_endpoint is not None
        assert metadata.userinfo_endpoint is not None
        assert metadata.jwks_uri is not None
        assert len(metadata.response_types_supported) > 0
        assert len(metadata.subject_types_supported) > 0
        assert len(metadata.id_token_signing_alg_values_supported) > 0
    
    def test_oidc_metadata_openid_scope_requirement(self, oidc_discovery_service):
        """Test that 'openid' scope is always included."""
        metadata = oidc_discovery_service.get_static_oidc_metadata("https://test.example.com")
        
        # OpenID Connect requires the 'openid' scope
        assert "openid" in metadata.scopes_supported
        
        # Verify standard OIDC scopes
        standard_oidc_scopes = ["openid", "profile", "email", "address", "phone"]
        for scope in standard_oidc_scopes:
            assert scope in metadata.scopes_supported
    
    def test_oidc_metadata_subject_types(self, oidc_discovery_service):
        """Test subject types compliance."""
        metadata = oidc_discovery_service.get_static_oidc_metadata("https://test.example.com")
        
        # Must support at least one subject type
        assert len(metadata.subject_types_supported) > 0
        
        # Common subject types
        valid_subject_types = ["public", "pairwise"]
        for subject_type in metadata.subject_types_supported:
            assert subject_type in valid_subject_types
    
    def test_oidc_metadata_signing_algorithms(self, oidc_discovery_service):
        """Test ID token signing algorithms."""
        metadata = oidc_discovery_service.get_static_oidc_metadata("https://test.example.com")
        
        # Must support at least one signing algorithm
        assert len(metadata.id_token_signing_alg_values_supported) > 0
        
        # Common signing algorithms
        valid_algorithms = ["RS256", "HS256", "ES256", "PS256"]
        for algorithm in metadata.id_token_signing_alg_values_supported:
            assert algorithm in valid_algorithms
    
    def test_oidc_metadata_response_types(self, oidc_discovery_service):
        """Test OIDC response types."""
        metadata = oidc_discovery_service.get_static_oidc_metadata("https://test.example.com")
        
        # Must support authorization code flow
        assert "code" in metadata.response_types_supported
        
        # Should NOT advertise unsupported ID token flows
        assert "id_token" not in metadata.response_types_supported  # Not implemented
        
        # Should NOT advertise unsupported hybrid flows
        assert "code id_token" not in metadata.response_types_supported  # Not implemented
    
    def test_oidc_metadata_urls_valid(self, oidc_discovery_service):
        """Test that all URLs in metadata are valid."""
        metadata = oidc_discovery_service.get_static_oidc_metadata("https://test.example.com")
        
        # All URLs should start with the issuer
        base_url = metadata.issuer
        
        assert metadata.authorization_endpoint.startswith(base_url)
        assert metadata.token_endpoint.startswith(base_url)
        assert metadata.userinfo_endpoint.startswith(base_url)
        assert metadata.jwks_uri.startswith(base_url)
        
        # Verify specific endpoint paths
        assert "/oauth/authorize" in metadata.authorization_endpoint
        assert "/auth/token" in metadata.token_endpoint
        assert "/oidc/userinfo" in metadata.userinfo_endpoint
        assert "/.well-known/jwks.json" in metadata.jwks_uri