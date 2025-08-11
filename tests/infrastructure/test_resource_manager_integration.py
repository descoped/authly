"""
Test resource manager integration with fastapi-testing.

Tests the new resource manager architecture with existing test patterns.
"""

from fastapi_testing import AsyncTestServer

from authly.core.deployment_modes import DeploymentMode
from authly.core.resource_manager import AuthlyResourceManager


class TestResourceManagerIntegration:
    """Test resource manager integration patterns."""

    async def test_resource_manager_fixture(self, test_resource_manager: AuthlyResourceManager):
        """Test that resource manager fixture works correctly."""
        assert test_resource_manager.mode == DeploymentMode.TESTING
        assert test_resource_manager.is_initialized

        # Access all resources
        config = test_resource_manager.get_config()
        database = test_resource_manager.get_database()
        pool = test_resource_manager.get_pool()
        transaction_manager = test_resource_manager.get_transaction_manager()

        assert config is not None
        assert database is not None
        assert pool is not None
        assert transaction_manager is not None

    async def test_legacy_test_server_compatibility(self, test_server: AsyncTestServer):
        """Test that legacy test server still works during transition."""
        # Test health endpoint with legacy server (should work because it initializes singleton)
        response = await test_server.client.get("/health")
        await response.expect_status(200)

        result = await response.json()
        assert "status" in result
        assert result["status"] == "healthy"

    async def test_fastapi_testing_infrastructure(
        self, resource_manager_server: AsyncTestServer, test_resource_manager: AuthlyResourceManager
    ):
        """Test that fastapi-testing infrastructure is correctly set up."""
        # Test that dependency injection is properly configured
        app = resource_manager_server.app

        # Test that dependency overrides are working
        assert len(app.dependency_overrides) > 0

        # Test that resource manager is accessible through dependency injection
        from authly.core.dependencies import get_resource_manager

        assert get_resource_manager in app.dependency_overrides

        # Get resource manager through the overridden dependency
        rm = app.dependency_overrides[get_resource_manager]()
        assert rm == test_resource_manager
        assert rm.mode == DeploymentMode.TESTING
        assert rm.is_initialized

    async def test_health_endpoint_with_resource_manager(self, resource_manager_server: AsyncTestServer):
        """Test that health endpoint works with resource manager after singleton removal."""
        # Test health endpoint with modern resource manager dependencies
        response = await resource_manager_server.client.get("/health")
        await response.expect_status(200)

        result = await response.json()
        assert "status" in result
        assert result["status"] == "healthy"
        assert "database" in result
        assert result["database"] == "connected"

    async def test_user_dependencies_with_resource_manager(self, resource_manager_server: AsyncTestServer):
        """Test that user dependencies work with resource manager after singleton removal."""
        # Test that OIDC userinfo endpoint works - this tests get_database_connection
        # We'll just test that the endpoint exists and doesn't crash with dependency injection
        response = await resource_manager_server.client.get(
            "/oidc/userinfo", headers={"Authorization": "Bearer invalid-token"}
        )
        # Should return 401 for invalid token, but that means the dependencies are working
        await response.expect_status(401)
