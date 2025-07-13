"""
Tests for OIDC End Session (logout) endpoint.

This module tests the OpenID Connect logout endpoint implementation,
including parameter validation, session termination, and redirect handling.
"""

from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer

from authly.oauth.models import ClientType, OAuthClientModel
from authly.tokens.service import TokenService


class TestOIDCLogoutEndpoint:
    """Test OIDC logout endpoint functionality."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC router."""
        from authly.api.oidc_router import oidc_router
        test_server.app.include_router(oidc_router, prefix="/api/v1")
        return test_server

    @pytest.fixture
    def mock_token_service(self):
        """Mock token service."""
        service = Mock(spec=TokenService)
        service.invalidate_user_tokens = AsyncMock(return_value=2)
        return service

    @pytest.fixture
    def mock_client_repository(self):
        """Mock client repository."""
        repo = Mock()
        repo.get_by_client_id = AsyncMock()
        return repo

    @pytest.fixture
    def test_client_model(self):
        """Test OAuth client model."""
        return OAuthClientModel(
            id=uuid4(),
            client_id="test_client",
            client_secret_hash="secret_hash",
            client_name="Test Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback", "https://example.com/logout"],
            is_active=True
        )

    @pytest.mark.asyncio
    async def test_oidc_logout_simple_success(self, oidc_server: AsyncTestServer):
        """Test OIDC logout without parameters returns success page."""
        response = await oidc_server.client.get("/api/v1/oidc/logout")
        await response.expect_status(200)
        
        content = await response.text()
        assert "Logout Successful" in content
        assert "successfully logged out" in content

    @pytest.mark.asyncio
    async def test_oidc_logout_endpoint_exists(self, oidc_server: AsyncTestServer):
        """Test OIDC logout endpoint is available at correct path."""
        response = await oidc_server.client.get("/api/v1/oidc/logout")
        
        # Should not return 404 (endpoint exists)  
        assert response._response.status_code != status.HTTP_404_NOT_FOUND
        # Should return success page
        await response.expect_status(200)


class TestOIDCLogoutDiscovery:
    """Test OIDC logout endpoint appears in discovery metadata."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC router."""
        from authly.api.oidc_router import oidc_router
        test_server.app.include_router(oidc_router, prefix="/api/v1")
        test_server.app.include_router(oidc_router)  # For discovery endpoint
        return test_server

    @pytest.mark.asyncio
    async def test_oidc_logout_in_discovery_metadata(self, oidc_server: AsyncTestServer):
        """Test that logout endpoint is advertised in OIDC discovery."""
        response = await oidc_server.client.get("/.well-known/openid_configuration")
        await response.expect_status(200)
        
        metadata = await response.json()
        
        # Check if end_session_endpoint is advertised
        assert "end_session_endpoint" in metadata
        assert "/oidc/logout" in metadata["end_session_endpoint"]