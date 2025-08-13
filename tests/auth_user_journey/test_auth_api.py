import logging
import random
import string
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from psycopg import AsyncConnection
from psycopg_toolkit import TransactionManager

from authly.api import auth_router, users_router
from authly.auth.core import get_password_hash
from authly.tokens import TokenRepository, TokenService
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


def generate_random_identifier(length: int = 10) -> str:
    """Generate a random string for use in both username and email."""
    return "".join(random.choices(string.ascii_lowercase, k=length))


@pytest.fixture(scope="function")
async def token_repository(db_connection: AsyncConnection) -> TokenRepository:
    """Create a token repository with a proper database connection."""
    return TokenRepository(db_connection)


@pytest.fixture(scope="function")
async def token_service(token_repository: TokenRepository, initialize_authly) -> TokenService:
    """Create a token service with a proper database connection."""
    config = initialize_authly.get_config()
    return TokenService(token_repository, config, None)


@pytest.fixture()
async def test_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a test user with random username."""
    identifier = generate_random_identifier()
    user_model = UserModel(
        id=uuid4(),
        username=identifier,
        email=f"{identifier}@example.com",
        password_hash=get_password_hash("Test123!"),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        is_active=True,
        is_verified=True,  # Default to verified
        is_admin=False,  # Admin status doesn't affect these tests
    )
    async with transaction_manager.transaction() as conn:
        repo = UserRepository(conn)
        return await repo.create(user_model)


@pytest.fixture()
async def create_unverified_user(transaction_manager: TransactionManager) -> UserModel:
    """Create an unverified test user with random username."""
    identifier = generate_random_identifier()
    user_model = UserModel(
        id=uuid4(),
        username=identifier,
        email=f"{identifier}@example.com",
        password_hash=get_password_hash("Test123!"),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        is_active=True,
        is_verified=False,
        is_admin=False,
    )
    async with transaction_manager.transaction() as conn:
        repo = UserRepository(conn)
        return await repo.create(user_model)


@pytest.fixture()
async def auth_server(test_server) -> AsyncGenerator[AsyncTestServer, Any]:
    test_server.app.include_router(auth_router, prefix="/api/v1")
    test_server.app.include_router(users_router, prefix="/api/v1")
    yield test_server


@pytest.mark.asyncio
async def test_unauthorized_access(auth_server: AsyncTestServer):
    response = await auth_server.client.get("/oidc/userinfo")
    await response.expect_status(401)


# Password grant tests removed for OAuth 2.1 compliance
# OAuth 2.1 does not support the password grant type.
# User authentication should be done through:
# 1. Authorization code flow with PKCE (for OAuth clients)
# 2. A separate non-OAuth login endpoint (if needed for first-party apps)
#
# The following tests were removed as they tested the deprecated password grant:
# - test_login_unverified: Tested login with unverified account
# - test_login_success: Tested successful password grant login
# - test_login_invalid_credentials: Tested invalid credentials with password grant
# - test_refresh_token_flow: Tested refresh token with initial password grant login
# - test_logout: Tested logout after password grant login
# - test_login_stores_tokens: Tested token storage with password grant
# - test_refresh_invalidates_old_token: Tested token invalidation with password grant
# - test_logout_invalidates_all_tokens: Tested logout invalidating all tokens
# - test_refresh_token_reuse: Tested refresh token reuse prevention
#
# These authentication flows should now use OAuth 2.1 authorization code flow with PKCE
# or a dedicated authentication service separate from OAuth.
