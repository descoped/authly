import asyncio
import logging

import pytest
from fastapi import APIRouter
from fastapi_testing import AsyncTestServer
from psycopg import AsyncTransaction

from authly.api import health_router
from authly.config.config import AuthlyConfig

logger = logging.getLogger(__name__)


class PingRouter:
    router = APIRouter()

    @staticmethod
    @router.get("/ping", status_code=200)
    async def read_root():
        return {"status": "ok"}


@pytest.mark.asyncio
async def test_authly_initialization(initialize_authly):
    # Use initialize_authly directly since it's now the Authly instance
    assert initialize_authly.get_config() is not None


@pytest.mark.asyncio
async def test_ping(test_server: AsyncTestServer, transaction: AsyncTransaction):
    # Register routes
    test_server.app.include_router(PingRouter().router)

    # Make your request
    response = await test_server.client.get("/ping")
    _, response_json = await asyncio.gather(response.expect_status(200), response.json())
    logger.info(f"Ping response: {response_json}")
    assert response_json == {"status": "ok"}


@pytest.mark.asyncio
async def test_health(test_config: AuthlyConfig, test_server: AsyncTestServer):
    # Register routes
    test_server.app.include_router(health_router)

    # Make your request
    response = await test_server.client.get("/health")
    _, health_response = await asyncio.gather(response.expect_status(200), response.json())
    assert health_response == {"status": "healthy", "database": "connected"}
