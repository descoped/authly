import logging
import random
import string
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from jose import jwt
from psycopg import AsyncConnection
from psycopg_toolkit import TransactionManager

from authly.api import auth_router, users_router
from authly.auth.core import get_password_hash
from authly.config.config import AuthlyConfig
from authly.tokens import TokenRepository, TokenService, TokenType
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
    response = await auth_server.client.get("/api/v1/users/me")
    await response.expect_status(401)


@pytest.mark.asyncio
async def test_login_unverified(auth_server: AsyncTestServer, create_unverified_user: UserModel):
    response = await auth_server.client.post(
        "/api/v1/oauth/token",
        json={"username": create_unverified_user.username, "password": "Test123!", "grant_type": "password"},
    )

    error_response = await response.json()
    await response.expect_status(403)
    assert error_response["detail"] == "Account not verified"


@pytest.mark.asyncio
async def test_login_success(test_config: AuthlyConfig, auth_server: AsyncTestServer, test_user: UserModel):
    response = await auth_server.client.post(
        "/api/v1/oauth/token", json={"username": test_user.username, "password": "Test123!", "grant_type": "password"}
    )

    auth_response = await response.json()
    await response.expect_status(200)

    assert "access_token" in auth_response
    assert "refresh_token" in auth_response
    assert "expires_in" in auth_response
    assert auth_response["token_type"] == "Bearer"

    payload = jwt.decode(auth_response["access_token"], test_config.secret_key, algorithms=[test_config.algorithm])
    assert payload["sub"] == str(test_user.id)


@pytest.mark.asyncio
async def test_login_invalid_credentials(auth_server: AsyncTestServer):
    response = await auth_server.client.post(
        "/api/v1/oauth/token",
        json={"username": generate_random_identifier(), "password": "wrongpass", "grant_type": "password"},
    )

    error_response = await response.json()
    await response.expect_status(401)
    assert error_response["detail"] == "Incorrect username or password"


@pytest.mark.asyncio
async def test_refresh_token_flow(auth_server: AsyncTestServer, test_user: UserModel):
    # First login
    login_response = await auth_server.client.post(
        "/api/v1/oauth/token", json={"username": test_user.username, "password": "Test123!", "grant_type": "password"}
    )

    tokens = await login_response.json()
    await login_response.expect_status(200)

    # Then refresh
    refresh_response = await auth_server.client.post(
        "/api/v1/oauth/refresh", json={"refresh_token": tokens["refresh_token"], "grant_type": "refresh_token"}
    )

    new_tokens = await refresh_response.json()
    await refresh_response.expect_status(200)

    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    assert "expires_in" in new_tokens
    assert new_tokens["token_type"] == "Bearer"

    # Verify tokens are different (token rotation)
    assert new_tokens["refresh_token"] != tokens["refresh_token"]


@pytest.mark.asyncio
async def test_logout(auth_server: AsyncTestServer, test_user: UserModel):
    # First login
    login_response = await auth_server.client.post(
        "/api/v1/oauth/token", json={"username": test_user.username, "password": "Test123!", "grant_type": "password"}
    )

    tokens = await login_response.json()
    await login_response.expect_status(200)

    # Then logout
    response = await auth_server.client.post(
        "/api/v1/auth/logout", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )

    logout_response = await response.json()
    await response.expect_status(200)
    assert logout_response["message"] == "Successfully logged out"


@pytest.mark.asyncio
async def test_login_stores_tokens(
    test_config: AuthlyConfig, auth_server: AsyncTestServer, test_user: UserModel, token_repository: TokenRepository
):
    """Test that login creates and stores both access and refresh tokens."""
    response = await auth_server.client.post(
        "/api/v1/oauth/token", json={"username": test_user.username, "password": "Test123!", "grant_type": "password"}
    )

    auth_response = await response.json()
    await response.expect_status(200)

    # Decode tokens to get JTIs
    access_payload = jwt.decode(
        auth_response["access_token"], test_config.secret_key, algorithms=[test_config.algorithm]
    )
    refresh_payload = jwt.decode(
        auth_response["refresh_token"], test_config.refresh_secret_key, algorithms=[test_config.algorithm]
    )

    # Verify tokens are stored
    stored_access = await token_repository.get_by_jti(access_payload["jti"])
    stored_refresh = await token_repository.get_by_jti(refresh_payload["jti"])

    assert stored_access is not None
    assert stored_refresh is not None
    assert stored_access.token_type == TokenType.ACCESS
    assert stored_refresh.token_type == TokenType.REFRESH


@pytest.mark.asyncio
async def test_refresh_invalidates_old_token(
    test_config: AuthlyConfig, auth_server: AsyncTestServer, test_user: UserModel, token_repository: TokenRepository
):
    """Test that refresh invalidates old token and stores new ones."""
    # First login
    login_response = await auth_server.client.post(
        "/api/v1/oauth/token", json={"username": test_user.username, "password": "Test123!", "grant_type": "password"}
    )

    tokens = await login_response.json()
    old_refresh_payload = jwt.decode(
        tokens["refresh_token"], test_config.refresh_secret_key, algorithms=[test_config.algorithm]
    )

    # Then refresh
    refresh_response = await auth_server.client.post(
        "/api/v1/oauth/refresh", json={"refresh_token": tokens["refresh_token"], "grant_type": "refresh_token"}
    )

    await refresh_response.expect_status(200)
    new_tokens = await refresh_response.json()

    # Verify old token is invalidated
    old_token = await token_repository.get_by_jti(old_refresh_payload["jti"])
    assert old_token.invalidated is True
    assert old_token.invalidated_at is not None

    # Verify new tokens are stored
    new_refresh_payload = jwt.decode(
        new_tokens["refresh_token"], test_config.refresh_secret_key, algorithms=[test_config.algorithm]
    )
    new_token = await token_repository.get_by_jti(new_refresh_payload["jti"])
    assert new_token is not None
    assert new_token.invalidated is False


@pytest.mark.asyncio
async def test_logout_invalidates_all_tokens(
    auth_server: AsyncTestServer, test_user: UserModel, token_repository: TokenRepository
):
    """Test that logout invalidates all user tokens."""
    # First login
    login_response = await auth_server.client.post(
        "/api/v1/oauth/token", json={"username": test_user.username, "password": "Test123!", "grant_type": "password"}
    )

    tokens = await login_response.json()

    # Create additional tokens through refresh
    await auth_server.client.post(
        "/api/v1/oauth/refresh", json={"refresh_token": tokens["refresh_token"], "grant_type": "refresh_token"}
    )

    # Then logout
    response = await auth_server.client.post(
        "/api/v1/auth/logout", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )

    await response.expect_status(200)
    logout_response = await response.json()
    assert logout_response["message"] == "Successfully logged out"
    assert logout_response["invalidated_tokens"] > 0

    # Verify all tokens are invalidated
    valid_tokens = await token_repository.get_user_tokens(test_user.id, valid_only=True)
    assert len(valid_tokens) == 0


@pytest.mark.asyncio
async def test_refresh_token_reuse(auth_server: AsyncTestServer, test_user: UserModel):
    """Test that reusing a refresh token after refresh fails."""
    # Initial login
    login_response = await auth_server.client.post(
        "/api/v1/oauth/token", json={"username": test_user.username, "password": "Test123!", "grant_type": "password"}
    )

    tokens = await login_response.json()
    old_refresh_token = tokens["refresh_token"]

    # First refresh - should succeed
    await auth_server.client.post(
        "/api/v1/oauth/refresh", json={"refresh_token": old_refresh_token, "grant_type": "refresh_token"}
    )

    # Try to reuse the old refresh token - should fail
    reuse_response = await auth_server.client.post(
        "/api/v1/oauth/refresh", json={"refresh_token": old_refresh_token, "grant_type": "refresh_token"}
    )

    await reuse_response.expect_status(401)
    error_response = await reuse_response.json()
    assert error_response["detail"] == "Token is invalid or expired"
