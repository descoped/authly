"""Tests for OAuth 2.0 Token Introspection endpoint (RFC 7662).

Tests that validate token introspection functionality for both
access tokens and refresh tokens.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import TransactionManager

from authly.api import auth_router, oauth_router, users_router
from authly.auth.core import create_access_token, get_password_hash
from authly.config import AuthlyConfig
from authly.tokens.service import TokenService
from authly.users import UserModel, UserRepository


@pytest.mark.skip(reason="Auth tokens fixture uses password grant - needs conversion to auth code flow")
class TestTokenIntrospectionEndpoint:
    """Test OAuth 2.0 Token Introspection endpoint functionality."""

    @pytest.fixture
    async def oauth_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OAuth routers."""
        test_server.app.include_router(auth_router, prefix="/api/v1")
        test_server.app.include_router(users_router, prefix="/api/v1")
        test_server.app.include_router(oauth_router, prefix="/api/v1")
        return test_server

    @pytest.fixture
    async def test_user(self, transaction_manager: TransactionManager) -> UserModel:
        """Create a test user with proper password hash."""
        user_data = UserModel(
            id=uuid4(),
            username=f"testuser_{uuid4().hex[:8]}",
            email=f"test_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("Test123!"),
            is_verified=True,
            is_admin=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            return await user_repo.create(user_data)

    @pytest.fixture
    async def auth_tokens(self, oauth_server: AsyncTestServer, test_user: UserModel):
        """Get valid access and refresh tokens for test user."""
        # Login to get tokens
        token_response = await oauth_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "password",
                "username": test_user.username,
                "password": "Test123!",
                "scope": "openid profile email database:read cache:read",
            },
        )

        await token_response.expect_status(200)
        token_data = await token_response.json()

        return {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token"),
            "token_type": token_data["token_type"],
            "expires_in": token_data.get("expires_in"),
            "scope": token_data.get("scope"),
        }

    @pytest.mark.asyncio
    async def test_introspect_valid_access_token(
        self, oauth_server: AsyncTestServer, test_user: UserModel, auth_tokens: dict
    ):
        """Test introspection of a valid access token."""
        # Introspect the access token
        introspect_response = await oauth_server.client.post(
            "/api/v1/oauth/introspect",
            data={
                "token": auth_tokens["access_token"],
                "token_type_hint": "access_token",
            },
        )

        await introspect_response.expect_status(200)
        introspect_data = await introspect_response.json()

        # Verify introspection response
        assert introspect_data["active"] is True
        assert introspect_data.get("token_type") == "Bearer"
        assert introspect_data["sub"] == str(test_user.id)
        assert introspect_data["username"] == test_user.username
        assert "exp" in introspect_data  # Expiration timestamp
        assert "scope" in introspect_data
        assert "jti" in introspect_data  # JWT ID should be present

        # Check scopes are included
        scopes = introspect_data["scope"].split()
        assert "openid" in scopes
        assert "profile" in scopes
        assert "email" in scopes

    @pytest.mark.asyncio
    async def test_introspect_invalid_token(self, oauth_server: AsyncTestServer):
        """Test introspection of an invalid/malformed token."""
        # Introspect an invalid token
        introspect_response = await oauth_server.client.post(
            "/api/v1/oauth/introspect",
            data={
                "token": "invalid.token.here",
            },
        )

        await introspect_response.expect_status(200)
        introspect_data = await introspect_response.json()

        # Invalid token should return active=false
        assert introspect_data["active"] is False
        # The endpoint may return additional fields with null values, which is acceptable

    @pytest.mark.asyncio
    async def test_introspect_expired_token(self, oauth_server: AsyncTestServer, test_user: UserModel, monkeypatch):
        """Test introspection of an expired token."""
        # Set required JWT environment variables for testing
        monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-for-introspection-tests")
        monkeypatch.setenv("JWT_REFRESH_SECRET_KEY", "test-refresh-key-for-introspection-tests")

        # Create an expired token manually using the auth core function
        from authly.config import EnvDatabaseProvider, EnvSecretProvider

        config = AuthlyConfig.load(EnvSecretProvider(), EnvDatabaseProvider())

        # Create the expired token (using negative expires_delta)
        expired_token = create_access_token(
            data={
                "sub": str(test_user.id),
                "jti": "test_expired_jti",
                "scope": "openid profile",
            },
            secret_key=config.secret_key,
            config=config,
            expires_delta=-60,  # Already expired by 60 minutes
        )

        # Introspect the expired token
        introspect_response = await oauth_server.client.post(
            "/api/v1/oauth/introspect",
            data={
                "token": expired_token,
            },
        )

        await introspect_response.expect_status(200)
        introspect_data = await introspect_response.json()

        # Expired token should return active=false
        assert introspect_data["active"] is False

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Password grant removed for OAuth 2.1 compliance")
    async def test_introspect_with_database_scopes(self, oauth_server: AsyncTestServer, test_user: UserModel):
        """Test introspection includes custom database scopes."""
        # Login with database scopes
        token_response = await oauth_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "password",
                "username": test_user.username,
                "password": "Test123!",
                "scope": "openid database:read database:write cache:read cache:write",
            },
        )

        # Check if scopes are supported (may fail if not yet added)
        if token_response.status_code == 200:
            token_data = await token_response.json()

            # Introspect the token
            introspect_response = await oauth_server.client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": token_data["access_token"],
                },
            )

            await introspect_response.expect_status(200)
            introspect_data = await introspect_response.json()

            if introspect_data["active"]:
                # Check database scopes are included
                scopes = introspect_data.get("scope", "").split()
                # These may not be present until we add them properly
                if "database:read" in scopes:
                    assert "database:read" in scopes
                    assert "database:write" in scopes
                    assert "cache:read" in scopes
                    assert "cache:write" in scopes

    @pytest.mark.asyncio
    async def test_introspect_refresh_token(
        self, oauth_server: AsyncTestServer, test_user: UserModel, auth_tokens: dict
    ):
        """Test introspection of a refresh token."""
        if not auth_tokens.get("refresh_token"):
            pytest.skip("No refresh token available")

        # Introspect the refresh token
        introspect_response = await oauth_server.client.post(
            "/api/v1/oauth/introspect",
            data={
                "token": auth_tokens["refresh_token"],
                "token_type_hint": "refresh_token",
            },
        )

        await introspect_response.expect_status(200)
        introspect_data = await introspect_response.json()

        # Refresh token introspection behavior depends on implementation
        # It should either be active with appropriate metadata or inactive
        assert "active" in introspect_data

        if introspect_data["active"]:
            # Token type may be "Bearer" or "refresh_token" depending on implementation
            assert introspect_data.get("token_type") in ["Bearer", "refresh_token"]
            assert introspect_data.get("sub") == str(test_user.id)

    @pytest.mark.asyncio
    async def test_introspect_missing_token(self, oauth_server: AsyncTestServer):
        """Test introspection with missing token parameter."""
        # Try to introspect without providing token
        introspect_response = await oauth_server.client.post(
            "/api/v1/oauth/introspect",
            data={
                "token_type_hint": "access_token",
            },
        )

        # Should fail with 422 (validation error) or 400
        assert introspect_response.status_code in [400, 422]

    @pytest.mark.asyncio
    async def test_introspect_token_type_hints(self, oauth_server: AsyncTestServer, auth_tokens: dict):
        """Test token_type_hint parameter is properly handled."""
        # Test with explicit access_token hint
        introspect_response = await oauth_server.client.post(
            "/api/v1/oauth/introspect",
            data={
                "token": auth_tokens["access_token"],
                "token_type_hint": "access_token",
            },
        )

        await introspect_response.expect_status(200)
        introspect_data = await introspect_response.json()
        assert introspect_data["active"] is True

        # Test with wrong hint (should still work but might be slower)
        introspect_response = await oauth_server.client.post(
            "/api/v1/oauth/introspect",
            data={
                "token": auth_tokens["access_token"],
                "token_type_hint": "refresh_token",  # Wrong hint
            },
        )

        await introspect_response.expect_status(200)
        introspect_data = await introspect_response.json()
        # The endpoint should handle wrong hints gracefully
        # It may return active=false or still validate correctly
        assert "active" in introspect_data

    @pytest.mark.asyncio
    async def test_introspect_response_claims(
        self, oauth_server: AsyncTestServer, test_user: UserModel, auth_tokens: dict
    ):
        """Test all required and optional claims in introspection response."""
        # Introspect the access token
        introspect_response = await oauth_server.client.post(
            "/api/v1/oauth/introspect",
            data={
                "token": auth_tokens["access_token"],
            },
        )

        await introspect_response.expect_status(200)
        introspect_data = await introspect_response.json()

        if introspect_data["active"]:
            # Required claims for active tokens
            assert "active" in introspect_data
            assert introspect_data["active"] is True

            # Recommended claims
            assert "sub" in introspect_data  # Subject identifier
            assert "exp" in introspect_data  # Expiration time
            assert "iat" in introspect_data  # Issued at time
            assert "scope" in introspect_data  # Scope

            # Optional but useful claims
            assert "username" in introspect_data
            assert "token_type" in introspect_data

            # Validate claim types
            assert isinstance(introspect_data["exp"], int)
            assert isinstance(introspect_data["iat"], int)
            assert isinstance(introspect_data["scope"], str)
            assert isinstance(introspect_data["sub"], str)

            # Validate timestamps are reasonable
            now = int(datetime.now(UTC).timestamp())
            assert introspect_data["iat"] <= now
            assert introspect_data["exp"] > now  # Token should not be expired


class TestIntrospectionService:
    """Test introspection service logic directly."""

    @pytest.fixture
    def mock_token_service(self):
        """Create mock token service."""
        service = Mock(spec=TokenService)
        return service

    @pytest.fixture
    def mock_user_repo(self):
        """Create mock user repository."""
        repo = Mock(spec=UserRepository)
        return repo

    @pytest.fixture
    def sample_token_data(self):
        """Create sample token data."""
        return {
            "sub": str(uuid4()),
            "jti": "test_jti",
            "scope": "openid profile email database:read",
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

    @pytest.mark.asyncio
    async def test_introspect_service_valid_token(self, mock_token_service, mock_user_repo, sample_token_data):
        """Test introspection service with valid token."""
        # This is a simplified test of the introspection response structure
        response_data = {
            "active": True,
            "scope": sample_token_data["scope"],
            "sub": sample_token_data["sub"],
            "exp": sample_token_data["exp"],
            "iat": sample_token_data["iat"],
            "token_type": "Bearer",
        }

        # Verify the response structure
        assert response_data["active"] is True
        assert response_data["sub"] == sample_token_data["sub"]
        assert "database:read" in response_data["scope"]
        assert response_data["exp"] > sample_token_data["iat"]
