import asyncio
import logging

import pytest
from fastapi import APIRouter
from fastapi_testing import TestServer
from psycopg import AsyncTransaction

from authly import Authly
from fixtures.testing import test_server

logger = logging.getLogger(__name__)


class PingRouter:
    router = APIRouter()

    @staticmethod
    @router.get("/ping", status_code=200)
    async def read_root():
        return {"status": "ok"}


@pytest.mark.asyncio
async def test_api(test_server: TestServer, transaction: AsyncTransaction):
    # Register routes
    test_server.app.include_router(PingRouter().router)

    # Make your request
    response = await test_server.client.get("/ping")
    _, response_json = await asyncio.gather(
        response.expect_status(200),
        response.json()
    )
    logger.info(f"Ping response: {response_json}")
    assert response_json == {"status": "ok"}


@pytest.mark.asyncio
async def test_api_async(initialize_authly: Authly):
    # Use initialize_authly directly since it's now the Authly instance
    assert initialize_authly.get_config() is not None
