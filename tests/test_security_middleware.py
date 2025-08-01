"""
Tests for Security Headers Middleware.

Tests comprehensive security headers implementation including:
- HSTS configuration and environment controls
- CSP policy validation and customization
- Security headers presence and values
- Environment-based configuration behavior
- Integration with FastAPI application
"""

import os
import unittest.mock
from typing import Dict

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authly.api.security_middleware import SecurityHeadersMiddleware, get_security_config, setup_security_middleware


class TestSecurityHeadersMiddleware:
    """Test security headers middleware functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.app = FastAPI()

        @self.app.get("/test")
        async def test_endpoint():
            return {"message": "test"}

        @self.app.get("/health")
        async def health_endpoint():
            return {"status": "healthy"}

    def test_default_security_headers(self):
        """Test that default security headers are applied."""
        self.app.add_middleware(SecurityHeadersMiddleware)
        client = TestClient(self.app)

        response = client.get("/test")

        # Verify response is successful
        assert response.status_code == 200

        # Verify security headers are present
        headers = response.headers
        assert "X-Frame-Options" in headers
        assert headers["X-Frame-Options"] == "DENY"

        assert "X-Content-Type-Options" in headers
        assert headers["X-Content-Type-Options"] == "nosniff"

        assert "X-XSS-Protection" in headers
        assert headers["X-XSS-Protection"] == "1; mode=block"

        assert "Referrer-Policy" in headers
        assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

        assert "Cross-Origin-Opener-Policy" in headers
        assert headers["Cross-Origin-Opener-Policy"] == "same-origin"

        assert "Cross-Origin-Embedder-Policy" in headers
        assert headers["Cross-Origin-Embedder-Policy"] == "require-corp"

        assert "Cross-Origin-Resource-Policy" in headers
        assert headers["Cross-Origin-Resource-Policy"] == "same-origin"

    def test_csp_header(self):
        """Test Content Security Policy header."""
        self.app.add_middleware(SecurityHeadersMiddleware)
        client = TestClient(self.app)

        response = client.get("/test")

        # Verify CSP header is present
        assert "Content-Security-Policy" in response.headers
        csp = response.headers["Content-Security-Policy"]

        # Verify key CSP directives
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'self'" in csp
        assert "form-action 'self'" in csp

    def test_permissions_policy_header(self):
        """Test Permissions Policy header."""
        self.app.add_middleware(SecurityHeadersMiddleware)
        client = TestClient(self.app)

        response = client.get("/test")

        # Verify Permissions Policy header is present
        assert "Permissions-Policy" in response.headers
        permissions = response.headers["Permissions-Policy"]

        # Verify key permissions are disabled
        assert "camera=()" in permissions
        assert "microphone=()" in permissions
        assert "geolocation=()" in permissions
        assert "payment=()" in permissions
        assert "usb=()" in permissions

    @pytest.mark.parametrize("scheme", ["http", "https"])
    def test_hsts_https_only(self, scheme):
        """Test HSTS header is only added for HTTPS requests."""
        self.app.add_middleware(SecurityHeadersMiddleware)
        client = TestClient(self.app, base_url=f"{scheme}://testserver")

        response = client.get("/test")

        if scheme == "https":
            # HSTS should be present for HTTPS
            assert "Strict-Transport-Security" in response.headers
            hsts = response.headers["Strict-Transport-Security"]
            assert "max-age=" in hsts
            assert "includeSubDomains" in hsts
            assert "preload" in hsts
        else:
            # HSTS should not be present for HTTP in production
            # (unless in development mode)
            pass  # We'll test development mode separately

    @unittest.mock.patch.dict(os.environ, {"AUTHLY_ENVIRONMENT": "development"})
    def test_hsts_development_mode(self):
        """Test HSTS header in development mode."""
        self.app.add_middleware(SecurityHeadersMiddleware)
        client = TestClient(self.app, base_url="http://testserver")

        response = client.get("/test")

        # HSTS should be present even for HTTP in development
        assert "Strict-Transport-Security" in response.headers

    @unittest.mock.patch.dict(os.environ, {"AUTHLY_SECURITY_HSTS_ENABLED": "false"})
    def test_hsts_disabled(self):
        """Test HSTS can be disabled via environment variable."""
        self.app.add_middleware(SecurityHeadersMiddleware)
        client = TestClient(self.app, base_url="https://testserver")

        response = client.get("/test")

        # HSTS should not be present when disabled
        assert "Strict-Transport-Security" not in response.headers

    @unittest.mock.patch.dict(os.environ, {"AUTHLY_SECURITY_CSP_ENABLED": "false"})
    def test_csp_disabled(self):
        """Test CSP can be disabled via environment variable."""
        self.app.add_middleware(SecurityHeadersMiddleware)
        client = TestClient(self.app)

        response = client.get("/test")

        # CSP should not be present when disabled
        assert "Content-Security-Policy" not in response.headers

    def test_custom_csp_policy(self):
        """Test custom CSP policy can be set."""
        custom_csp = "default-src 'none'; script-src 'self';"
        self.app.add_middleware(SecurityHeadersMiddleware, csp_policy=custom_csp)
        client = TestClient(self.app)

        response = client.get("/test")

        assert "Content-Security-Policy" in response.headers
        assert response.headers["Content-Security-Policy"] == custom_csp

    def test_custom_frame_options(self):
        """Test custom frame options can be set."""
        self.app.add_middleware(SecurityHeadersMiddleware, frame_options="SAMEORIGIN")
        client = TestClient(self.app)

        response = client.get("/test")

        assert response.headers["X-Frame-Options"] == "SAMEORIGIN"

    def test_custom_headers(self):
        """Test custom headers can be added."""
        custom_headers = {"X-Custom-Header": "custom-value", "X-Another-Header": "another-value"}
        self.app.add_middleware(SecurityHeadersMiddleware, custom_headers=custom_headers)
        client = TestClient(self.app)

        response = client.get("/test")

        for header_name, header_value in custom_headers.items():
            assert response.headers[header_name] == header_value

    def test_hsts_configuration_options(self):
        """Test HSTS configuration options."""
        self.app.add_middleware(
            SecurityHeadersMiddleware, hsts_max_age=3600, hsts_include_subdomains=False, hsts_preload=False
        )
        client = TestClient(self.app, base_url="https://testserver")

        response = client.get("/test")

        hsts = response.headers["Strict-Transport-Security"]
        assert hsts == "max-age=3600"
        assert "includeSubDomains" not in hsts
        assert "preload" not in hsts

    def test_multiple_endpoints(self):
        """Test security headers are applied to all endpoints."""
        self.app.add_middleware(SecurityHeadersMiddleware)
        client = TestClient(self.app)

        # Test multiple endpoints
        endpoints = ["/test", "/health"]

        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.status_code == 200

            # Verify security headers are present on all endpoints
            assert "X-Frame-Options" in response.headers
            assert "X-Content-Type-Options" in response.headers
            assert "Content-Security-Policy" in response.headers


class TestSecurityConfiguration:
    """Test security configuration helpers."""

    def test_get_security_config_defaults(self):
        """Test default security configuration values."""
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            config = get_security_config()

            assert config["hsts_enabled"] == "true"
            assert config["csp_enabled"] == "true"
            assert config["hsts_max_age"] == "31536000"
            assert config["frame_options"] == "DENY"
            assert config["referrer_policy"] == "strict-origin-when-cross-origin"
            assert config["environment"] == "production"

    @unittest.mock.patch.dict(
        os.environ,
        {
            "AUTHLY_SECURITY_HSTS_ENABLED": "false",
            "AUTHLY_SECURITY_CSP_ENABLED": "false",
            "AUTHLY_SECURITY_HSTS_MAX_AGE": "7200",
            "AUTHLY_SECURITY_FRAME_OPTIONS": "SAMEORIGIN",
            "AUTHLY_SECURITY_REFERRER_POLICY": "no-referrer",
            "AUTHLY_ENVIRONMENT": "development",
        },
    )
    def test_get_security_config_custom(self):
        """Test custom security configuration values."""
        config = get_security_config()

        assert config["hsts_enabled"] == "false"
        assert config["csp_enabled"] == "false"
        assert config["hsts_max_age"] == "7200"
        assert config["frame_options"] == "SAMEORIGIN"
        assert config["referrer_policy"] == "no-referrer"
        assert config["environment"] == "development"


class TestSecurityMiddlewareIntegration:
    """Test security middleware integration with FastAPI."""

    def test_setup_security_middleware(self):
        """Test setup_security_middleware function."""
        app = FastAPI()

        @app.get("/test")
        async def test_endpoint():
            return {"message": "test"}

        # Setup security middleware
        setup_security_middleware(app)

        client = TestClient(app)
        response = client.get("/test")

        # Verify security headers are present after setup
        assert "X-Frame-Options" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert "X-Content-Type-Options" in response.headers

    def test_setup_with_custom_options(self):
        """Test setup_security_middleware with custom options."""
        app = FastAPI()

        @app.get("/test")
        async def test_endpoint():
            return {"message": "test"}

        # Setup with custom options
        setup_security_middleware(app, frame_options="SAMEORIGIN", custom_headers={"X-Custom": "value"})

        client = TestClient(app)
        response = client.get("/test")

        # Verify custom configuration is applied
        assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
        assert response.headers["X-Custom"] == "value"


class TestSecurityPolicyContent:
    """Test security policy content and structure."""

    def test_default_csp_restrictive(self):
        """Test that default CSP is appropriately restrictive."""
        middleware = SecurityHeadersMiddleware(None)
        csp = middleware._get_default_csp()

        # Verify restrictive policies
        assert "object-src 'none'" in csp
        assert "frame-src 'none'" in csp
        assert "child-src 'none'" in csp
        assert "worker-src 'none'" in csp
        assert "manifest-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp

        # Verify controlled permissions
        assert "default-src 'self'" in csp
        assert "base-uri 'self'" in csp
        assert "form-action 'self'" in csp

    def test_default_permissions_policy_restrictive(self):
        """Test that default permissions policy is appropriately restrictive."""
        middleware = SecurityHeadersMiddleware(None)
        permissions = middleware._get_default_permissions_policy()

        # Verify key permissions are disabled
        sensitive_features = [
            "camera=(),",
            "microphone=(),",
            "geolocation=(),",
            "payment=(),",
            "usb=(),",
            "encrypted-media=(),",
            "fullscreen=(),",
            "picture-in-picture=(),",
        ]

        for feature in sensitive_features:
            assert feature in permissions

    def test_environment_detection(self):
        """Test environment detection logic."""
        middleware = SecurityHeadersMiddleware(None)

        # Test development environments
        with unittest.mock.patch.dict(os.environ, {"AUTHLY_ENVIRONMENT": "development"}):
            assert middleware._is_development() is True

        with unittest.mock.patch.dict(os.environ, {"AUTHLY_ENVIRONMENT": "dev"}):
            assert middleware._is_development() is True

        with unittest.mock.patch.dict(os.environ, {"AUTHLY_ENVIRONMENT": "local"}):
            assert middleware._is_development() is True

        # Test production environment
        with unittest.mock.patch.dict(os.environ, {"AUTHLY_ENVIRONMENT": "production"}):
            assert middleware._is_development() is False

        with unittest.mock.patch.dict(os.environ, {"AUTHLY_ENVIRONMENT": "prod"}):
            assert middleware._is_development() is False
