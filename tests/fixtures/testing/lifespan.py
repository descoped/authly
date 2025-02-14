import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import pytest
from fastapi.applications import AppType
from fastapi_testing import TestServer
from psycopg_toolkit import Database

from authly import get_config, Authly
from authly.config import AuthlyConfig
from authly.tokens import TokenStore, TokenService, get_token_store, get_token_service

logger = logging.getLogger(__name__)


@asynccontextmanager
async def custom_test_server(
        initialize_authly: Authly,
        test_config: AuthlyConfig,
        db: Database,
) -> AsyncGenerator[TestServer, None]:
    """Custom test server creation with full control over lifecycle"""
    server = TestServer()

    # Wire up dependencies before server starts
    app_: AppType = server.app
    app_.dependency_overrides.update({
        get_config: lambda: test_config,
    })

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


@pytest.fixture(scope='function')
async def test_server(
        initialize_authly: Authly,  # Add this dependency
        test_config: AuthlyConfig,
        _database_instance: Database,
) -> AsyncGenerator[TestServer, None]:
    async with custom_test_server(
            initialize_authly,
            test_config,
            _database_instance,
    ) as server:
        yield server
