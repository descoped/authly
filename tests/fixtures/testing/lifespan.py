import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import pytest
from fastapi.applications import AppType
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import Database

# Legacy Authly import removed - using AuthlyResourceManager
from authly.config import AuthlyConfig
from authly.core.dependencies import (
    get_config,
    get_database,
    get_database_connection,
    get_database_pool,
    get_resource_manager,
    get_transaction_manager,
)
from authly.core.resource_manager import AuthlyResourceManager

logger = logging.getLogger(__name__)


@asynccontextmanager
async def resource_manager_test_server(
    test_resource_manager: AuthlyResourceManager,
    db_connection_override=None,
) -> AsyncGenerator[AsyncTestServer, None]:
    """Modern test server creation using AuthlyResourceManager.

    This is the new approach that fully integrates with the resource manager
    architecture and fastapi-testing patterns.
    """
    from fastapi import FastAPI

    from authly.api import auth_router, health_router, oauth_router, oidc_router, users_router
    from authly.api.admin_middleware import setup_admin_middleware
    from authly.api.admin_router import admin_router
    from authly.api.oauth_discovery_router import oauth_discovery_router

    app = FastAPI(title="Authly Test Server - Resource Manager")

    # Set up admin middleware
    setup_admin_middleware(app)

    # Include all routers like main.py but without lifespan
    app.include_router(health_router)
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(users_router, prefix="/api/v1")
    app.include_router(oauth_router, prefix="/api/v1")
    app.include_router(oidc_router)  # OIDC router (no prefix - uses well-known paths)
    app.include_router(oauth_discovery_router)  # OAuth discovery router (no prefix - RFC 8414 compliance)
    app.include_router(admin_router)

    # Create test server with the configured app
    server = AsyncTestServer()
    server.app = app

    # Create test-specific dependency factory functions
    def get_test_resource_manager():
        return test_resource_manager

    def get_test_config():
        return test_resource_manager.get_config()

    def get_test_database():
        return test_resource_manager.get_database()

    def get_test_transaction_manager():
        return test_resource_manager.get_transaction_manager()

    async def get_test_db_pool():
        return test_resource_manager.get_pool()

    async def get_test_db_connection():
        pool = test_resource_manager.get_pool()
        async with pool.connection() as conn:
            await conn.set_autocommit(True)  # Match production behavior
            yield conn

    # Set up dependency overrides with resource manager integration
    dependency_overrides = {
        get_resource_manager: get_test_resource_manager,
        get_config: get_test_config,
        get_database: get_test_database,
        get_transaction_manager: get_test_transaction_manager,
        get_database_pool: get_test_db_pool,
        get_database_connection: get_test_db_connection,
    }

    # Add custom database connection override if provided
    if db_connection_override:
        dependency_overrides[get_database_connection] = db_connection_override
        # Legacy dependency override removed - using resource manager patterns

    # Wire up dependencies using proper FastAPI dependency overrides
    app_: AppType = server.app
    app_.dependency_overrides.update(dependency_overrides)

    try:
        # CORS Middleware
        from fastapi.middleware.cors import CORSMiddleware

        app_.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Modify for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Custom startup logic here if needed
        await server.start()
        logger.info(f"Resource manager test server started - mode: {test_resource_manager.mode.value}")
        yield server
    finally:
        # Custom cleanup logic
        logger.info("Shutting down resource manager test server")
        await server.stop()


@asynccontextmanager
async def custom_test_server(
    initialize_authly: AuthlyResourceManager,
    test_config: AuthlyConfig,
    db: Database,
    db_connection_override=None,
) -> AsyncGenerator[AsyncTestServer, None]:
    """Updated test server creation using resource manager.

    Migrated to use AuthlyResourceManager instead of legacy Authly singleton.
    """
    # Updated to use resource manager architecture
    # Create FastAPI app with all routes but without lifespan
    from fastapi import FastAPI

    from authly.api import auth_router, health_router, oauth_router, oidc_router, users_router
    from authly.api.admin_middleware import setup_admin_middleware
    from authly.api.admin_router import admin_router
    from authly.api.oauth_discovery_router import oauth_discovery_router

    app = FastAPI(title="Authly Test Server")

    # Set up admin middleware
    setup_admin_middleware(app)

    # Include all routers like main.py but without lifespan
    app.include_router(health_router)
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(users_router, prefix="/api/v1")
    app.include_router(oauth_router, prefix="/api/v1")
    app.include_router(oidc_router)  # OIDC router (no prefix - uses well-known paths)
    app.include_router(oauth_discovery_router)  # OAuth discovery router (no prefix - RFC 8414 compliance)
    app.include_router(admin_router)

    # Create test server with the configured app
    server = AsyncTestServer()
    server.app = app

    # Wire up dependencies using proper FastAPI dependency overrides
    app_: AppType = server.app

    # Set up dependency injection without app.state
    from authly.core.dependencies import create_resource_manager_provider

    # Create the provider and override the default dependency
    provider = create_resource_manager_provider(initialize_authly)
    app.dependency_overrides[get_resource_manager] = provider

    # Create test-specific dependency factory functions
    def get_test_resource_manager():
        return initialize_authly

    def get_test_config() -> AuthlyConfig:
        return test_config

    def get_test_database():
        return initialize_authly.get_database()

    def get_test_transaction_manager():
        return initialize_authly.get_transaction_manager()

    async def get_test_db_pool():
        return await db.get_pool()

    async def get_test_db_connection():
        pool = await db.get_pool()
        async with pool.connection() as conn:
            await conn.set_autocommit(True)  # Match production behavior
            yield conn

    # Set up dependency overrides (no app state pollution)
    dependency_overrides = {
        get_resource_manager: get_test_resource_manager,
        get_config: get_test_config,
        get_database: get_test_database,
        get_transaction_manager: get_test_transaction_manager,
        get_database_pool: get_test_db_pool,
        get_database_connection: get_test_db_connection,
    }

    # Add custom database connection override if provided
    if db_connection_override:
        dependency_overrides[get_database_connection] = db_connection_override
        # Legacy dependency override removed - using resource manager patterns

    app_.dependency_overrides.update(dependency_overrides)

    try:
        # CORS Middleware
        from fastapi.middleware.cors import CORSMiddleware

        app_.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Modify for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Custom startup logic here if needed
        await server.start()
        yield server
    finally:
        # Custom cleanup logic
        await db.cleanup()
        await server.stop()


@pytest.fixture(scope="function")
async def resource_manager_server(
    test_resource_manager: AuthlyResourceManager,
) -> AsyncGenerator[AsyncTestServer, None]:
    """Modern test server fixture using AuthlyResourceManager.

    This is the preferred fixture for new tests that want to use the
    full resource manager architecture with fastapi-testing integration.
    """
    async with resource_manager_test_server(
        test_resource_manager,
    ) as server:
        yield server


@pytest.fixture(scope="function")
async def test_server(
    initialize_authly: AuthlyResourceManager,  # Updated to use resource manager
    test_config: AuthlyConfig,
    _database_instance: Database,
) -> AsyncGenerator[AsyncTestServer, None]:
    """Updated test server fixture using AuthlyResourceManager.

    Migrated from legacy Authly singleton to modern resource manager architecture.
    """
    async with custom_test_server(
        initialize_authly,
        test_config,
        _database_instance,
    ) as server:
        yield server


@pytest.fixture(scope="function")
async def hybrid_test_server(
    initialize_authly_with_resource_manager: AuthlyResourceManager,
    test_resource_manager: AuthlyResourceManager,
) -> AsyncGenerator[AsyncTestServer, None]:
    """Updated test server using resource manager.

    Fully migrated to use AuthlyResourceManager architecture.
    """
    async with resource_manager_test_server(
        test_resource_manager,
    ) as server:
        yield server
