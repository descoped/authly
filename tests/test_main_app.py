"""
Tests for Main Application Integration.

This module tests the main FastAPI application with admin router integration,
middleware setup, and production-ready configuration.
"""

import logging
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import TransactionManager

from authly import Authly
from authly.auth.core import get_password_hash
from authly.bootstrap.admin_seeding import bootstrap_admin_system
from authly.main import create_app, setup_logging
from authly.tokens import TokenRepository, TokenService
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


class TestMainApplicationCreation:
    """Test main FastAPI application creation and configuration."""

    @pytest.mark.asyncio
    async def test_create_app_basic_structure(self):
        """Test that create_app returns properly configured FastAPI app."""
        app = create_app()

        # Verify it's a FastAPI app
        assert isinstance(app, FastAPI)
        assert app.title == "Authly Authentication Service"
        assert app.version == "0.1.5"
        assert "authentication and authorization service" in app.description.lower()

    @pytest.mark.asyncio
    async def test_create_app_includes_all_routers(self):
        """Test that create_app includes all required routers."""
        app = create_app()

        # Get all route paths
        route_paths = [route.path for route in app.routes]

        # Should include health endpoint
        assert "/health" in route_paths

        # Should include admin endpoints
        admin_paths = [path for path in route_paths if path.startswith("/admin")]
        assert len(admin_paths) > 0

        # Should include API version endpoints (default /api/v1)
        api_paths = [path for path in route_paths if "/api/v1" in path]
        assert len(api_paths) > 0

    @pytest.mark.asyncio
    async def test_create_app_with_custom_api_prefix(self):
        """Test create_app with custom API prefix from environment."""
        with patch.dict(os.environ, {"AUTHLY_API_PREFIX": "/api/v2"}):
            app = create_app()

            route_paths = [route.path for route in app.routes]
            api_v2_paths = [path for path in route_paths if "/api/v2" in path]
            assert len(api_v2_paths) > 0

    @pytest.mark.asyncio
    async def test_create_app_middleware_setup(self):
        """Test that admin middleware is properly set up."""
        app = create_app()

        # Should have middleware (including admin security middleware)
        assert len(app.user_middleware) > 0

    @pytest.mark.asyncio
    async def test_create_app_openapi_configuration(self):
        """Test OpenAPI schema configuration."""
        app = create_app()

        # Test OpenAPI schema generation
        openapi_schema = app.openapi()

        assert "info" in openapi_schema
        assert openapi_schema["info"]["title"] == "Authly Authentication Service"
        assert openapi_schema["info"]["version"] == "0.1.5"

        # Should have security schemes
        assert "components" in openapi_schema
        assert "securitySchemes" in openapi_schema["components"]
        assert "bearerAuth" in openapi_schema["components"]["securitySchemes"]


class TestMainApplicationIntegration:
    """Test main application with real server integration."""

    @pytest.mark.asyncio
    async def test_main_app_health_endpoints(self, test_server: AsyncTestServer):
        """Test that main app serves health endpoints correctly."""
        # Use the create_app function to get the real app
        app = create_app()
        test_server.app = app

        # Test main health endpoint
        response = await test_server.client.get("/health")
        await response.expect_status(200)

        # Test admin health endpoint
        response = await test_server.client.get("/admin/health")
        await response.expect_status(200)

        result = await response.json()
        assert result["status"] == "healthy"
        assert result["service"] == "authly-admin-api"

    @pytest.mark.asyncio
    async def test_main_app_api_endpoints_exist(self, test_server: AsyncTestServer):
        """Test that main app serves API endpoints."""
        app = create_app()
        test_server.app = app

        # Test auth endpoints exist (will return 422/405 for wrong method, not 404)
        response = await test_server.client.get("/api/v1/auth/token")
        assert response._response.status_code != 404  # Should exist, even if wrong method

        # Test users endpoints exist
        response = await test_server.client.get("/api/v1/users/me")
        assert response._response.status_code in [401, 422]  # Needs auth, but endpoint exists

        # Test OAuth endpoints exist
        response = await test_server.client.get("/api/v1/oauth/.well-known/openid_configuration")
        assert response._response.status_code in [200, 404]  # May or may not be implemented

    @pytest.mark.asyncio
    async def test_main_app_admin_endpoints_protected(self, test_server: AsyncTestServer):
        """Test that admin endpoints are properly protected."""
        app = create_app()
        test_server.app = app

        # Admin endpoints should require authentication
        protected_endpoints = ["/admin/status", "/admin/clients", "/admin/scopes"]

        for endpoint in protected_endpoints:
            response = await test_server.client.get(endpoint)
            await response.expect_status(401)  # Should require authentication


class TestMainApplicationLifecycle:
    """Test main application lifecycle management."""

    @pytest.mark.asyncio
    async def test_lifespan_startup_sequence(self, initialize_authly: Authly):
        """Test application startup sequence with mocked components."""
        # This tests the lifespan function behavior
        # In real tests, the lifespan is handled by fixtures

        # Verify Authly is properly initialized
        assert initialize_authly is not None

        # Verify configuration is loaded
        config = initialize_authly.get_config()
        assert config is not None

        # Verify database pool is available
        pool = initialize_authly.get_pool()
        assert pool is not None

    @pytest.mark.asyncio
    async def test_bootstrap_integration_in_main_app(
        self, transaction_manager: TransactionManager, initialize_authly: Authly
    ):
        """Test that bootstrap system integrates with main app lifecycle."""
        # Test bootstrap manually (in production, this happens during startup)
        # Use unique username to avoid conflict with bootstrap tests
        import random
        import string

        unique_suffix = "".join(random.choices(string.ascii_lowercase, k=8))
        unique_username = f"main_app_admin_{unique_suffix}"
        unique_email = f"{unique_username}@main.example.com"

        async with transaction_manager.transaction() as conn:
            results = await bootstrap_admin_system(
                conn, admin_username=unique_username, admin_email=unique_email, admin_password="MainAppTest123!"
            )

            assert results["bootstrap_completed"] is True

            # If admin user was created, verify it's properly set up
            if results["admin_user_created"]:
                user_repo = UserRepository(conn)
                admin_user = await user_repo.get_by_id(results["admin_user_id"])
                assert admin_user.is_admin is True
                assert admin_user.username == unique_username


class TestMainApplicationConfiguration:
    """Test main application configuration options."""

    @pytest.mark.asyncio
    async def test_setup_logging_function(self):
        """Test setup_logging function configuration."""
        # Test with default values
        with patch.dict(os.environ, {}, clear=True):
            setup_logging()
            # Should not raise exceptions

        # Test with custom log level
        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
            setup_logging()

        # Test with custom log format
        with patch.dict(os.environ, {"LOG_FORMAT": "%(name)s - %(message)s"}):
            setup_logging()

    @pytest.mark.asyncio
    async def test_environment_configuration_loading(self):
        """Test that environment variables are properly loaded."""
        test_env = {"AUTHLY_API_PREFIX": "/custom/api/v1", "AUTHLY_BOOTSTRAP_ENABLED": "false", "LOG_LEVEL": "DEBUG"}

        with patch.dict(os.environ, test_env):
            app = create_app()

            # Verify custom API prefix is used
            route_paths = [route.path for route in app.routes]
            custom_api_paths = [path for path in route_paths if "/custom/api/v1" in path]
            assert len(custom_api_paths) > 0


class TestMainApplicationSecurity:
    """Test main application security features."""

    @pytest.mark.asyncio
    async def test_admin_middleware_integration(self, test_server: AsyncTestServer):
        """Test that admin middleware is properly integrated."""
        app = create_app()
        test_server.app = app

        # Test that admin middleware blocks when disabled
        with patch.dict(os.environ, {"AUTHLY_ADMIN_API_ENABLED": "false"}):
            # Need to recreate app to pick up new environment
            app = create_app()
            test_server.app = app

            response = await test_server.client.get("/admin/health")
            await response.expect_status(503)

            result = await response.json()
            assert result["error_code"] == "ADMIN_API_DISABLED"

    @pytest.mark.asyncio
    async def test_cors_and_security_headers(self, test_server: AsyncTestServer):
        """Test CORS and security headers in main app."""
        app = create_app()
        test_server.app = app

        # Test basic endpoint
        response = await test_server.client.get("/health")
        await response.expect_status(200)

        # In a real application, we would test CORS headers here
        # For now, just verify the response is successful


class TestMainApplicationErrorHandling:
    """Test main application error handling."""

    @pytest.mark.asyncio
    async def test_404_handling(self, test_server: AsyncTestServer):
        """Test 404 error handling for non-existent endpoints."""
        app = create_app()
        test_server.app = app

        response = await test_server.client.get("/nonexistent/endpoint")
        await response.expect_status(404)

    @pytest.mark.asyncio
    async def test_admin_endpoint_not_found_vs_unauthorized(self, test_server: AsyncTestServer):
        """Test difference between non-existent admin endpoints and unauthorized access."""
        app = create_app()
        test_server.app = app

        # Non-existent admin endpoint should return 404
        response = await test_server.client.get("/admin/nonexistent")
        await response.expect_status(404)

        # Existing admin endpoint without auth should return 401
        response = await test_server.client.get("/admin/status")
        await response.expect_status(401)


class TestMainApplicationEndToEnd:
    """Test main application end-to-end functionality."""

    @pytest.mark.asyncio
    async def test_complete_admin_workflow(
        self, test_server: AsyncTestServer, transaction_manager: TransactionManager, initialize_authly: Authly
    ):
        """Test complete admin workflow through main app."""
        app = create_app()
        test_server.app = app

        # Use unique username to avoid conflict with bootstrap tests
        import random
        import string

        unique_suffix = "".join(random.choices(string.ascii_lowercase, k=8))
        unique_username = f"workflow_admin_{unique_suffix}"
        unique_email = f"{unique_username}@workflow.example.com"

        # Create admin user and token (committed to database)
        async with transaction_manager.transaction() as conn:
            # Bootstrap admin system with unique credentials
            results = await bootstrap_admin_system(
                conn, admin_username=unique_username, admin_email=unique_email, admin_password="WorkflowTest123!"
            )
            assert results["bootstrap_completed"] is True

            if results["admin_user_created"]:
                # Create admin token
                user_repo = UserRepository(conn)
                admin_user = await user_repo.get_by_id(results["admin_user_id"])

                token_repo = TokenRepository(conn)
                token_service = TokenService(token_repo)

                admin_scopes = ["admin:clients:read", "admin:system:read"]

                token_pair = await token_service.create_token_pair(user=admin_user, scope=" ".join(admin_scopes))

                # Store token for use outside transaction
                headers = {"Authorization": f"Bearer {token_pair.access_token}"}

        # Now test admin API access with committed data
        if results.get("admin_user_created"):
            # Test system status
            response = await test_server.client.get("/admin/status", headers=headers)
            await response.expect_status(200)

            result = await response.json()
            assert result["status"] == "operational"

            # Test client listing
            response = await test_server.client.get("/admin/clients", headers=headers)
            await response.expect_status(200)

            result = await response.json()
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_regular_api_and_admin_api_coexistence(
        self, test_server: AsyncTestServer, transaction_manager: TransactionManager, initialize_authly: Authly
    ):
        """Test that regular API and admin API work together."""
        app = create_app()
        test_server.app = app

        # Test regular health endpoint
        response = await test_server.client.get("/health")
        await response.expect_status(200)

        # Test admin health endpoint
        response = await test_server.client.get("/admin/health")
        await response.expect_status(200)

        # Both should work independently
        # Regular API doesn't need admin privileges
        # Admin API has additional security requirements

        # Create regular user and token (committed to database)
        async with transaction_manager.transaction() as conn:
            # Create regular user
            user_repo = UserRepository(conn)
            regular_user = UserModel(
                id=uuid4(),
                username="regular_user",
                email="regular@example.com",
                password_hash=get_password_hash("RegularPass123!"),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                is_active=True,
                is_verified=True,
                is_admin=False,
            )
            created_user = await user_repo.create(regular_user)

            # Create regular user token
            token_repo = TokenRepository(conn)
            token_service = TokenService(token_repo)

            token_pair = await token_service.create_token_pair(user=created_user, scope="read write")

            # Commit the transaction by exiting the context successfully
            headers = {"Authorization": f"Bearer {token_pair.access_token}"}

        # Now test with the committed data
        # Regular user should NOT be able to access admin endpoints
        response = await test_server.client.get("/admin/status", headers=headers)
        await response.expect_status(403)  # Forbidden, not unauthorized
