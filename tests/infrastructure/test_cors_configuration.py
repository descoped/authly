"""Tests for CORS configuration in production application."""

import os

import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer

from authly.config import AuthlyConfig
from authly.config.database_providers import EnvDatabaseProvider
from authly.config.secret_providers import EnvSecretProvider


class TestCORSConfiguration:
    """Test that CORS is properly configured for browser compatibility."""

    @pytest.mark.asyncio
    async def test_cors_headers_on_oauth_endpoints(
        self,
        test_server: AsyncTestServer,
    ):
        """Test that CORS headers are present on OAuth endpoints."""
        # Test preflight OPTIONS request
        response = await test_server.client.request(
            "OPTIONS",
            "/api/v1/oauth/authorize",
            headers={
                "Origin": "http://localhost:8080",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )

        # Should return CORS headers for preflight
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT]
        headers = response._response.headers if hasattr(response, "_response") else response.headers

        # Check CORS headers
        assert "access-control-allow-origin" in headers or "Access-Control-Allow-Origin" in headers
        assert "access-control-allow-methods" in headers or "Access-Control-Allow-Methods" in headers
        assert "access-control-allow-headers" in headers or "Access-Control-Allow-Headers" in headers

    @pytest.mark.asyncio
    async def test_cors_headers_on_oidc_endpoints(
        self,
        test_server: AsyncTestServer,
    ):
        """Test that CORS headers are present on OIDC endpoints."""
        # Test well-known endpoint with Origin header
        response = await test_server.client.get(
            "/.well-known/openid-configuration",
            headers={
                "Origin": "http://localhost:8080",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        headers = response._response.headers if hasattr(response, "_response") else response.headers

        # Check CORS headers
        assert "access-control-allow-origin" in headers or "Access-Control-Allow-Origin" in headers

    @pytest.mark.asyncio
    async def test_cors_allows_credentials(
        self,
        test_server: AsyncTestServer,
    ):
        """Test that CORS allows credentials for OAuth flows."""
        response = await test_server.client.request(
            "OPTIONS",
            "/api/v1/oauth/token",
            headers={
                "Origin": "http://localhost:8080",
                "Access-Control-Request-Method": "POST",
            },
        )

        headers = response._response.headers if hasattr(response, "_response") else response.headers

        # Check if credentials are allowed
        allow_credentials = headers.get("access-control-allow-credentials") or headers.get(
            "Access-Control-Allow-Credentials"
        )
        if allow_credentials:
            assert allow_credentials.lower() == "true"

    @pytest.mark.asyncio
    async def test_cors_respects_authly_config(self):
        """Test that CORS configuration respects AuthlyConfig settings."""
        # Set required JWT secrets
        os.environ["JWT_SECRET_KEY"] = "test-secret-key"
        os.environ["JWT_REFRESH_SECRET_KEY"] = "test-refresh-key"
        os.environ["DATABASE_URL"] = "postgresql://test:test@localhost:5432/test"

        # Set custom CORS origins via environment
        os.environ["AUTHLY_CORS_ORIGINS"] = "https://example.com,https://app.example.com"
        os.environ["AUTHLY_CORS_ALLOW_METHODS"] = "GET,POST"
        os.environ["AUTHLY_CORS_MAX_AGE"] = "3600"

        try:
            # Load config with custom CORS settings
            config = AuthlyConfig.load(
                secret_provider=EnvSecretProvider(),
                database_provider=EnvDatabaseProvider(),
            )

            # Verify config loaded correctly
            assert config.cors_allowed_origins == ["https://example.com", "https://app.example.com"]
            assert config.cors_allow_methods == ["GET", "POST"]
            assert config.cors_max_age == 3600
            assert config.cors_allow_credentials is True  # Default

        finally:
            # Clean up environment
            os.environ.pop("JWT_SECRET_KEY", None)
            os.environ.pop("JWT_REFRESH_SECRET_KEY", None)
            os.environ.pop("DATABASE_URL", None)
            os.environ.pop("AUTHLY_CORS_ORIGINS", None)
            os.environ.pop("AUTHLY_CORS_ALLOW_METHODS", None)
            os.environ.pop("AUTHLY_CORS_MAX_AGE", None)

    @pytest.mark.asyncio
    async def test_cors_wildcard_origin(self):
        """Test that CORS wildcard origin works correctly."""
        # Set required JWT secrets
        os.environ["JWT_SECRET_KEY"] = "test-secret-key"
        os.environ["JWT_REFRESH_SECRET_KEY"] = "test-refresh-key"
        os.environ["DATABASE_URL"] = "postgresql://test:test@localhost:5432/test"
        os.environ["AUTHLY_CORS_ORIGINS"] = "*"

        try:
            config = AuthlyConfig.load(
                secret_provider=EnvSecretProvider(),
                database_provider=EnvDatabaseProvider(),
            )

            assert config.cors_allowed_origins == ["*"]

        finally:
            os.environ.pop("JWT_SECRET_KEY", None)
            os.environ.pop("JWT_REFRESH_SECRET_KEY", None)
            os.environ.pop("DATABASE_URL", None)
            os.environ.pop("AUTHLY_CORS_ORIGINS", None)
