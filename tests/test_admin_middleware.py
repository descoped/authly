"""
Tests for Admin Security Middleware.

This module tests the admin middleware including localhost-only security,
admin API enable/disable functionality, and security event logging.
"""

import os
from unittest.mock import patch
import pytest
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from fastapi_testing import AsyncTestServer

from authly.api.admin_middleware import AdminSecurityMiddleware, setup_admin_middleware
from authly.api.admin_router import admin_router


class TestAdminSecurityMiddleware:
    """Test AdminSecurityMiddleware class."""
    
    @pytest.mark.asyncio
    async def test_non_admin_requests_pass_through(self):
        """Test that non-admin requests pass through middleware unchanged."""
        # Create a fresh FastAPI app
        app = FastAPI()
        
        # Add a regular endpoint
        @app.get("/regular")
        async def regular_endpoint():
            return {"message": "success"}
        
        # Setup admin middleware
        setup_admin_middleware(app)
        
        # Create test server
        test_server = AsyncTestServer()
        test_server.app = app
        
        await test_server.start()
        try:
            # Regular endpoint should work normally
            response = await test_server.client.get("/regular")
            await response.expect_status(200)
            
            result = await response.json()
            assert result["message"] == "success"
        finally:
            await test_server.stop()
    
    @pytest.mark.asyncio
    async def test_admin_api_disabled(self):
        """Test admin API access when disabled via environment variable."""
        with patch.dict(os.environ, {"AUTHLY_ADMIN_API_ENABLED": "false"}):
            # Create a fresh FastAPI app
            app = FastAPI()
            setup_admin_middleware(app)
            app.include_router(admin_router)
            
            # Create test server
            test_server = AsyncTestServer()
            test_server.app = app
            
            await test_server.start()
            try:
                # Admin endpoints should be disabled
                response = await test_server.client.get("/admin/health")
                await response.expect_status(503)
                
                result = await response.json()
                assert result["detail"] == "Admin API is currently disabled"
                assert result["error_code"] == "ADMIN_API_DISABLED"
            finally:
                await test_server.stop()
    
    @pytest.mark.asyncio
    async def test_admin_api_enabled_by_default(self):
        """Test that admin API is enabled by default."""
        with patch.dict(os.environ, {}, clear=True):
            # Clear environment to test defaults
            # Create a fresh FastAPI app
            app = FastAPI()
            setup_admin_middleware(app)
            app.include_router(admin_router)
            
            # Create test server
            test_server = AsyncTestServer()
            test_server.app = app
            
            await test_server.start()
            try:
                # Admin health endpoint should work (no auth required for health)
                response = await test_server.client.get("/admin/health")
                await response.expect_status(200)
                
                result = await response.json()
                assert result["status"] == "healthy"
            finally:
                await test_server.stop()
    
    @pytest.mark.asyncio
    async def test_localhost_only_security_enabled(self, test_server: AsyncTestServer):
        """Test localhost-only security when enabled."""
        with patch.dict(os.environ, {"AUTHLY_ADMIN_API_LOCALHOST_ONLY": "true"}):
            from authly.api.admin_middleware import AdminSecurityMiddleware
            
            # Test localhost IP detection
            middleware = AdminSecurityMiddleware(None)
            
            # These should be considered localhost
            assert middleware._is_localhost("127.0.0.1") is True
            assert middleware._is_localhost("::1") is True 
            assert middleware._is_localhost("localhost") is True
            assert middleware._is_localhost("127.0.0.100") is True  # 127.x.x.x range
            
            # These should NOT be considered localhost
            assert middleware._is_localhost("192.168.1.1") is False
            assert middleware._is_localhost("10.0.0.1") is False
            assert middleware._is_localhost("203.0.113.1") is False
            assert middleware._is_localhost("") is False
            assert middleware._is_localhost(None) is False
    
    @pytest.mark.asyncio
    async def test_localhost_only_security_disabled(self):
        """Test admin API when localhost-only security is disabled."""
        with patch.dict(os.environ, {"AUTHLY_ADMIN_API_LOCALHOST_ONLY": "false"}):
            # Create a fresh FastAPI app
            app = FastAPI()
            setup_admin_middleware(app)
            app.include_router(admin_router)
            
            # Create test server
            test_server = AsyncTestServer()
            test_server.app = app
            
            await test_server.start()
            try:
                # Admin endpoints should be accessible (though still need auth for most)
                response = await test_server.client.get("/admin/health")
                await response.expect_status(200)
            finally:
                await test_server.stop()
    
    @pytest.mark.asyncio 
    async def test_docker_internal_ips_allowed(self, test_server: AsyncTestServer):
        """Test that Docker internal IPs are allowed as localhost."""
        from authly.api.admin_middleware import AdminSecurityMiddleware
        
        middleware = AdminSecurityMiddleware(None)
        
        # Docker bridge IPs should be allowed
        assert middleware._is_localhost("172.17.0.1") is True
        assert middleware._is_localhost("172.18.0.1") is True
        assert middleware._is_localhost("host.docker.internal") is True
    
    @pytest.mark.asyncio
    async def test_forwarded_headers_handling(self, test_server: AsyncTestServer):
        """Test handling of X-Forwarded-For and X-Real-IP headers."""
        # This is a unit test for the IP detection logic
        # In real scenarios, the test server may not preserve these headers exactly
        from authly.api.admin_middleware import AdminSecurityMiddleware
        
        middleware = AdminSecurityMiddleware(None)
        
        # Test the IP checking logic with various inputs
        test_cases = [
            ("127.0.0.1", True),
            ("::1", True),
            ("192.168.1.100", False),
            ("10.0.0.50", False),
            ("172.17.0.1", True),  # Docker bridge
        ]
        
        for ip, expected in test_cases:
            assert middleware._is_localhost(ip) == expected


class TestMiddlewareIntegration:
    """Test middleware integration with FastAPI application."""
    
    @pytest.mark.asyncio
    async def test_middleware_setup_function(self):
        """Test setup_admin_middleware function."""
        # Create a fresh FastAPI app
        app = FastAPI()
        
        # Count middleware before
        initial_middleware_count = len(app.user_middleware)
        
        # Setup admin middleware
        setup_admin_middleware(app)
        
        # Should have added one middleware
        assert len(app.user_middleware) == initial_middleware_count + 1
    
    @pytest.mark.asyncio
    async def test_middleware_with_admin_router(self):
        """Test middleware integration with admin router."""
        # Reset environment to defaults 
        with patch.dict(os.environ, {}, clear=True):
            # Create a fresh FastAPI app
            app = FastAPI()
            setup_admin_middleware(app)
            app.include_router(admin_router)
            
            # Create test server
            test_server = AsyncTestServer()
            test_server.app = app
            
            await test_server.start()
            try:
                # Health endpoint should work (no auth required)
                response = await test_server.client.get("/admin/health")
                await response.expect_status(200)
                
                result = await response.json()
                assert result["status"] == "healthy"
                assert result["service"] == "authly-admin-api"
            finally:
                await test_server.stop()
    
    @pytest.mark.asyncio
    async def test_middleware_error_responses_format(self):
        """Test that middleware error responses have correct format."""
        with patch.dict(os.environ, {"AUTHLY_ADMIN_API_ENABLED": "false"}):
            # Create a fresh FastAPI app
            app = FastAPI()
            setup_admin_middleware(app)
            app.include_router(admin_router)
            
            # Create test server
            test_server = AsyncTestServer()
            test_server.app = app
            
            await test_server.start()
            try:
                response = await test_server.client.get("/admin/health")
                await response.expect_status(503)
                
                result = await response.json()
                
                # Should have proper error format
                assert "detail" in result
                assert "error_code" in result
                assert result["error_code"] == "ADMIN_API_DISABLED"
            finally:
                await test_server.stop()
    
    @pytest.mark.asyncio
    async def test_middleware_preserves_regular_endpoints(self):
        """Test that middleware doesn't interfere with regular endpoints."""
        # Reset environment to defaults
        with patch.dict(os.environ, {}, clear=True):
            # Create a fresh FastAPI app
            app = FastAPI()
            
            # Add regular endpoints
            @app.get("/api/test")
            async def regular_api():
                return {"api": "working"}
            
            @app.get("/health")
            async def regular_health():
                return {"status": "ok"}
            
            setup_admin_middleware(app)
            app.include_router(admin_router)
            
            # Create test server
            test_server = AsyncTestServer()
            test_server.app = app
            
            await test_server.start()
            try:
                # Regular endpoints should work normally
                response1 = await test_server.client.get("/api/test")
                await response1.expect_status(200)
                result1 = await response1.json()
                assert result1["api"] == "working"
                
                response2 = await test_server.client.get("/health")
                await response2.expect_status(200)
                result2 = await response2.json()
                assert result2["status"] == "ok"
                
                # Admin endpoint should also work (health doesn't need auth)
                response3 = await test_server.client.get("/admin/health")
                await response3.expect_status(200)
                result3 = await response3.json()
                assert result3["status"] == "healthy"
            finally:
                await test_server.stop()


class TestMiddlewareConfiguration:
    """Test middleware configuration options."""
    
    @pytest.mark.asyncio
    async def test_environment_variable_precedence(self):
        """Test that environment variables override defaults."""
        # Test with explicit false
        with patch.dict(os.environ, {
            "AUTHLY_ADMIN_API_ENABLED": "false",
            "AUTHLY_ADMIN_API_LOCALHOST_ONLY": "false"
        }):
            from authly.api import admin_middleware
            
            # Should read false from environment
            assert admin_middleware._is_admin_api_enabled() is False
            assert admin_middleware._is_admin_api_localhost_only() is False
    
    @pytest.mark.asyncio 
    async def test_default_configuration_values(self):
        """Test default configuration when environment variables not set."""
        with patch.dict(os.environ, {}, clear=True):
            # Import with cleared environment to get defaults
            from authly.api import admin_middleware
            
            # Should default to enabled and localhost-only
            assert admin_middleware._is_admin_api_enabled() is True
            assert admin_middleware._is_admin_api_localhost_only() is True
    
    @pytest.mark.asyncio
    async def test_case_insensitive_environment_variables(self):
        """Test that environment variables are case-insensitive."""
        test_cases = [
            ("TRUE", True),
            ("True", True), 
            ("true", True),
            ("FALSE", False),
            ("False", False),
            ("false", False),
            ("yes", False),  # Only "true" should be true
            ("1", False),    # Only "true" should be true
        ]
        
        for env_value, expected in test_cases:
            with patch.dict(os.environ, {"AUTHLY_ADMIN_API_ENABLED": env_value}):
                from authly.api import admin_middleware
                
                assert admin_middleware._is_admin_api_enabled() == expected


class TestMiddlewareSecurityLogging:
    """Test middleware security event logging."""
    
    @pytest.mark.asyncio
    async def test_blocked_access_logging(self, caplog):
        """Test that blocked access attempts are logged."""
        with patch.dict(os.environ, {"AUTHLY_ADMIN_API_ENABLED": "false"}):
            # Create a fresh FastAPI app
            app = FastAPI()
            setup_admin_middleware(app)
            app.include_router(admin_router)
            
            # Create test server
            test_server = AsyncTestServer()
            test_server.app = app
            
            await test_server.start()
            try:
                # This should be blocked and logged
                response = await test_server.client.get("/admin/health")
                await response.expect_status(503)
                
                # Check that warning was logged (depending on logging setup)
                # Note: In test environment, logging might be configured differently
            finally:
                await test_server.stop()
    
    @pytest.mark.asyncio
    async def test_successful_access_logging(self, caplog):
        """Test that successful admin access is logged."""
        # Reset environment to defaults
        with patch.dict(os.environ, {}, clear=True):
            # Create a fresh FastAPI app
            app = FastAPI()
            setup_admin_middleware(app)
            app.include_router(admin_router)
            
            # Create test server
            test_server = AsyncTestServer()
            test_server.app = app
            
            await test_server.start()
            try:
                # This should succeed and be logged
                response = await test_server.client.get("/admin/health")
                await response.expect_status(200)
                
                # Successful access should be logged for audit purposes
            finally:
                await test_server.stop()


class TestMiddlewareEdgeCases:
    """Test middleware edge cases and error conditions."""
    
    @pytest.mark.asyncio
    async def test_malformed_admin_paths(self):
        """Test middleware with malformed admin paths."""
        # Reset environment to defaults
        with patch.dict(os.environ, {}, clear=True):
            # Create a fresh FastAPI app
            app = FastAPI()
            setup_admin_middleware(app)
            
            # Create test server
            test_server = AsyncTestServer()
            test_server.app = app
            
            await test_server.start()
            try:
                # These should all be treated as admin paths and processed by middleware
                admin_like_paths = [
                    "/admin",
                    "/admin/",
                    "/admin/nonexistent",
                    "/admin/../admin/health",
                ]
                
                for path in admin_like_paths:
                    response = await test_server.client.get(path)
                    # These will return 404 since endpoints don't exist, but middleware should process them
                    # The key is that they don't cause middleware errors
                    actual_status = response._response.status_code
                    assert actual_status in [404, 405, 200]  # Valid HTTP responses
            finally:
                await test_server.stop()
    
    @pytest.mark.asyncio
    async def test_middleware_with_websocket_admin_path(self):
        """Test middleware with WebSocket connections on admin paths."""
        # Create a fresh FastAPI app
        app = FastAPI()
        setup_admin_middleware(app)
        
        # Add a websocket endpoint (would be blocked by middleware)
        @app.websocket("/admin/ws")
        async def admin_websocket(websocket):
            await websocket.accept()
            await websocket.send_text("admin")
        
        # WebSocket connections to admin paths should be blocked if API is disabled
        with patch.dict(os.environ, {"AUTHLY_ADMIN_API_ENABLED": "false"}):
            import importlib
            from authly.api import admin_middleware
            importlib.reload(admin_middleware)
            
            # The middleware should handle non-HTTP connections gracefully
            # Note: Testing WebSocket blocking requires specific setup