"""
Tests for OIDC Session Management endpoints.

This module tests the OpenID Connect Session Management 1.0 specification
implementation including session iframe, session check, and front-channel logout.
"""

import pytest
from fastapi_testing import AsyncTestServer


class TestOIDCSessionIframe:
    """Test OIDC Session Management iframe endpoint."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC router."""
        from authly.api.oidc_router import oidc_router

        test_server.app.include_router(oidc_router, prefix="/api/v1")
        return test_server

    @pytest.mark.asyncio
    async def test_session_iframe_endpoint_exists(self, oidc_server: AsyncTestServer):
        """Test that session iframe endpoint exists and returns HTML."""
        response = await oidc_server.client.get("/api/v1/oidc/session/iframe")
        await response.expect_status(200)

        content = await response.text()
        assert "<!DOCTYPE html>" in content
        assert "OIDC Session Management" in content

    @pytest.mark.asyncio
    async def test_session_iframe_contains_javascript(self, oidc_server: AsyncTestServer):
        """Test that session iframe contains required JavaScript functionality."""
        response = await oidc_server.client.get("/api/v1/oidc/session/iframe")
        await response.expect_status(200)

        content = await response.text()
        # Check for essential session management JavaScript
        assert "postMessage" in content
        assert "addEventListener" in content
        assert "oidc-session-check" in content
        assert "handleMessage" in content

    @pytest.mark.asyncio
    async def test_session_iframe_security_headers(self, oidc_server: AsyncTestServer):
        """Test that session iframe has proper security headers."""
        response = await oidc_server.client.get("/api/v1/oidc/session/iframe")
        await response.expect_status(200)

        headers = response._response.headers
        assert headers.get("Cache-Control") == "no-cache, no-store, must-revalidate"
        assert headers.get("Pragma") == "no-cache"
        assert headers.get("Expires") == "0"
        assert headers.get("X-Frame-Options") == "SAMEORIGIN"


class TestOIDCSessionCheck:
    """Test OIDC Session status check endpoint."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC router."""
        from authly.api.oidc_router import oidc_router

        test_server.app.include_router(oidc_router, prefix="/api/v1")
        return test_server

    @pytest.mark.asyncio
    async def test_session_check_endpoint_exists(self, oidc_server: AsyncTestServer):
        """Test that session check endpoint exists and returns JSON."""
        response = await oidc_server.client.get("/api/v1/oidc/session/check")
        await response.expect_status(200)

        data = await response.json()
        assert "session_state" in data
        assert "authenticated" in data

    @pytest.mark.asyncio
    async def test_session_check_without_client_id(self, oidc_server: AsyncTestServer):
        """Test session check without client_id parameter."""
        response = await oidc_server.client.get("/api/v1/oidc/session/check")
        await response.expect_status(200)

        data = await response.json()
        assert data["client_id"] is None
        assert data["authenticated"] is False
        assert data["session_state"] == "logged_out"

    @pytest.mark.asyncio
    async def test_session_check_with_client_id(self, oidc_server: AsyncTestServer):
        """Test session check with client_id parameter."""
        response = await oidc_server.client.get("/api/v1/oidc/session/check?client_id=test_client")
        await response.expect_status(200)

        data = await response.json()
        assert data["client_id"] == "test_client"
        assert "check_time" in data

    @pytest.mark.asyncio
    async def test_session_check_with_auth_header(self, oidc_server: AsyncTestServer):
        """Test session check with authorization header (simulated authentication)."""
        headers = {"authorization": "Bearer fake_token"}
        response = await oidc_server.client.get("/api/v1/oidc/session/check", headers=headers)
        await response.expect_status(200)

        data = await response.json()
        assert data["authenticated"] is True
        assert data["session_state"] == "active"


class TestOIDCFrontChannelLogout:
    """Test OIDC Front-channel logout endpoint."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC router."""
        from authly.api.oidc_router import oidc_router

        test_server.app.include_router(oidc_router, prefix="/api/v1")
        return test_server

    @pytest.mark.asyncio
    async def test_frontchannel_logout_endpoint_exists(self, oidc_server: AsyncTestServer):
        """Test that front-channel logout endpoint exists and returns HTML."""
        response = await oidc_server.client.get("/api/v1/oidc/frontchannel/logout")
        await response.expect_status(200)

        content = await response.text()
        assert "<!DOCTYPE html>" in content
        assert "Logout Processing" in content

    @pytest.mark.asyncio
    async def test_frontchannel_logout_with_parameters(self, oidc_server: AsyncTestServer):
        """Test front-channel logout with issuer and session parameters."""
        # Get the correct base URL from the test server
        base_url = oidc_server.base_url

        params = {"iss": base_url, "sid": "test_session_123"}
        response = await oidc_server.client.get("/api/v1/oidc/frontchannel/logout", params=params)
        await response.expect_status(200)

        content = await response.text()
        assert "Front-Channel Logout" in content
        assert "Processing logout request" in content

    @pytest.mark.asyncio
    async def test_frontchannel_logout_invalid_issuer(self, oidc_server: AsyncTestServer):
        """Test front-channel logout with invalid issuer parameter."""
        params = {"iss": "https://malicious.example.com", "sid": "test_session_123"}
        response = await oidc_server.client.get("/api/v1/oidc/frontchannel/logout", params=params)
        await response.expect_status(400)

    @pytest.mark.asyncio
    async def test_frontchannel_logout_security_headers(self, oidc_server: AsyncTestServer):
        """Test that front-channel logout has proper security headers."""
        response = await oidc_server.client.get("/api/v1/oidc/frontchannel/logout")
        await response.expect_status(200)

        headers = response._response.headers
        assert headers.get("Cache-Control") == "no-cache, no-store, must-revalidate"
        assert headers.get("Pragma") == "no-cache"
        assert headers.get("Expires") == "0"


class TestOIDCSessionManagementDiscovery:
    """Test that session management endpoints are properly advertised in discovery."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC router."""
        from authly.api.oidc_router import oidc_router

        test_server.app.include_router(oidc_router, prefix="/api/v1")
        test_server.app.include_router(oidc_router)  # For discovery endpoint
        return test_server

    @pytest.mark.asyncio
    async def test_session_management_in_discovery(self, oidc_server: AsyncTestServer):
        """Test that session management endpoints are advertised in OIDC discovery."""
        response = await oidc_server.client.get("/.well-known/openid_configuration")
        await response.expect_status(200)

        metadata = await response.json()

        # Check session management endpoints
        assert "check_session_iframe" in metadata
        assert "/oidc/session/iframe" in metadata["check_session_iframe"]

        # Check front-channel logout support
        assert "frontchannel_logout_supported" in metadata
        assert metadata["frontchannel_logout_supported"] is True

        assert "frontchannel_logout_session_supported" in metadata
        assert metadata["frontchannel_logout_session_supported"] is True

    @pytest.mark.asyncio
    async def test_end_session_endpoint_in_discovery(self, oidc_server: AsyncTestServer):
        """Test that end session endpoint is properly advertised."""
        response = await oidc_server.client.get("/.well-known/openid_configuration")
        await response.expect_status(200)

        metadata = await response.json()

        # Check end session endpoint
        assert "end_session_endpoint" in metadata
        assert "/oidc/logout" in metadata["end_session_endpoint"]


class TestOIDCSessionManagementIntegration:
    """Integration tests for OIDC session management workflow."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC router."""
        from authly.api.oidc_router import oidc_router

        test_server.app.include_router(oidc_router, prefix="/api/v1")
        test_server.app.include_router(oidc_router)  # For discovery endpoint
        return test_server

    @pytest.mark.asyncio
    async def test_session_management_workflow(self, oidc_server: AsyncTestServer):
        """Test complete session management workflow."""
        # 1. Get discovery metadata with session management endpoints
        discovery_response = await oidc_server.client.get("/.well-known/openid_configuration")
        await discovery_response.expect_status(200)

        metadata = await discovery_response.json()
        iframe_url = metadata["check_session_iframe"]
        metadata["end_session_endpoint"]

        # 2. Access session iframe (extract path from URL)
        from urllib.parse import urlparse

        iframe_path = urlparse(iframe_url).path
        iframe_response = await oidc_server.client.get(iframe_path)
        await iframe_response.expect_status(200)

        iframe_content = await iframe_response.text()
        assert "OIDC Session Management" in iframe_content

        # 3. Check session status
        session_response = await oidc_server.client.get("/api/v1/oidc/session/check")
        await session_response.expect_status(200)

        session_data = await session_response.json()
        assert "session_state" in session_data

        # 4. Perform end session logout
        logout_response = await oidc_server.client.get("/api/v1/oidc/logout")
        await logout_response.expect_status(200)

        logout_content = await logout_response.text()
        assert "Logout Successful" in logout_content

    @pytest.mark.asyncio
    async def test_cross_client_logout_coordination(self, oidc_server: AsyncTestServer):
        """Test front-channel logout coordination between clients."""
        # Get the correct base URL from the test server
        base_url = oidc_server.base_url

        # Simulate logout initiated by one client
        params = {"iss": base_url, "sid": "shared_session_123"}

        # Front-channel logout should coordinate across clients
        response = await oidc_server.client.get("/api/v1/oidc/frontchannel/logout", params=params)
        await response.expect_status(200)

        content = await response.text()
        assert "Processing front-channel logout" in content
        assert "shared_session_123" in content
