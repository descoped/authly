import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import pytest
from fastapi.applications import AppType
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import Database

from authly import Authly, get_config
from authly.config import AuthlyConfig

logger = logging.getLogger(__name__)


@asynccontextmanager
async def custom_test_server(
    initialize_authly: Authly,
    test_config: AuthlyConfig,
    db: Database,
    db_connection_override=None,
) -> AsyncGenerator[AsyncTestServer, None]:
    """Custom test server creation with full control over lifecycle"""
    # Create FastAPI app with all routes but without lifespan
    from fastapi import FastAPI

    from authly.api import auth_router, health_router, oauth_router, oidc_router, users_router
    from authly.api.oauth_discovery_router import oauth_discovery_router
    from authly.api.admin_middleware import setup_admin_middleware
    from authly.api.admin_router import admin_router

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

    # Wire up dependencies before server starts
    app_: AppType = server.app
    dependency_overrides = {
        get_config: lambda: test_config,
    }

    # Add database connection override if provided
    if db_connection_override:
        from authly import authly_db_connection

        dependency_overrides[authly_db_connection] = db_connection_override

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
async def test_server(
    initialize_authly: Authly,  # Add this dependency
    test_config: AuthlyConfig,
    _database_instance: Database,
) -> AsyncGenerator[AsyncTestServer, None]:
    async with custom_test_server(
        initialize_authly,
        test_config,
        _database_instance,
    ) as server:
        yield server
