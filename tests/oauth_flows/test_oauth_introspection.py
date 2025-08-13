"""Tests for OAuth 2.0 Token Introspection endpoint (RFC 7662).

Tests that validate token introspection functionality for both
access tokens and refresh tokens using real integration testing.
"""

import base64
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer
from psycopg_pool import AsyncConnectionPool

from authly.auth.core import create_access_token
from authly.config import AuthlyConfig
from authly.tokens.models import TokenModel, TokenType
from authly.users.models import UserModel


def generate_test_token_with_jti(
    config: AuthlyConfig, user_id: str, client_id: str | None = None, scope: str = "openid profile"
) -> tuple[str, str]:
    """Generate a test access token with JTI for introspection testing.

    Returns:
        Tuple of (token, jti)
    """
    jti = f"test_jti_{uuid4().hex}"  # Full UUID hex is 32 chars
    token_data = {
        "sub": str(user_id),
        "jti": jti,
        "scope": scope,
    }
    if client_id:
        token_data["client_id"] = client_id

    token = create_access_token(
        data=token_data,
        secret_key=config.secret_key,
        config=config,
        expires_delta=3600,  # 1 hour
    )
    return token, jti


class TestTokenIntrospectionEndpoint:
    """Test OAuth 2.0 Token Introspection endpoint functionality using real integration testing."""

    @pytest.mark.asyncio
    async def test_introspect_valid_access_token(
        self,
        test_server: AsyncTestServer,
        committed_user: UserModel,
        committed_oauth_client: dict[str, Any],
        db_pool: AsyncConnectionPool,
        test_config: AuthlyConfig,
    ) -> None:
        """Test introspection of a valid access token."""
        # Create a test token with known JTI
        token, jti = generate_test_token_with_jti(
            test_config, str(committed_user.id), committed_oauth_client["client_id"], "openid profile email"
        )

        # Store the token in the database
        async with db_pool.connection() as conn:
            await conn.set_autocommit(True)
            from authly.tokens.repository import TokenRepository

            token_repo = TokenRepository(conn)

            token_model = TokenModel(
                id=uuid4(),
                token_jti=jti,
                token_value=token,
                user_id=committed_user.id,
                client_id=None,  # We store client_id as string in token claims
                token_type=TokenType.ACCESS,
                scope="openid profile email",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                invalidated=False,
            )
            await token_repo.create(token_model)

        # Create Basic Auth header for client authentication
        credentials = f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Introspect the token
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "token": token,
                "token_type_hint": "access_token",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        introspect_data = await response.json()

        # Verify introspection response
        assert introspect_data["active"] is True
        assert introspect_data.get("token_type") == "Bearer"
        assert introspect_data["sub"] == str(committed_user.id)
        assert introspect_data["username"] == committed_user.username
        assert "exp" in introspect_data  # Expiration timestamp
        assert "scope" in introspect_data
        assert introspect_data["jti"] == jti

        # Check scopes are included
        scopes = introspect_data["scope"].split()
        assert "openid" in scopes
        assert "profile" in scopes
        assert "email" in scopes

    @pytest.mark.asyncio
    async def test_introspect_invalid_token(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client: dict[str, Any],
    ) -> None:
        """Test introspection of an invalid/malformed token."""
        # Create Basic Auth header for client authentication
        credentials = f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Introspect an invalid token
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "token": "invalid.token.here",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        introspect_data = await response.json()

        # Invalid token should return active=false
        assert introspect_data["active"] is False

    @pytest.mark.asyncio
    async def test_introspect_expired_token(
        self,
        test_server: AsyncTestServer,
        committed_user: UserModel,
        committed_oauth_client: dict[str, Any],
        db_pool: AsyncConnectionPool,
        test_config: AuthlyConfig,
    ) -> None:
        """Test introspection of an expired token."""
        # Create an expired token
        jti = f"expired_jti_{uuid4().hex}"  # Full UUID hex for 32+ chars
        expired_token = create_access_token(
            data={
                "sub": str(committed_user.id),
                "jti": jti,
                "scope": "openid profile",
                "client_id": committed_oauth_client["client_id"],
            },
            secret_key=test_config.secret_key,
            config=test_config,
            expires_delta=-3600,  # Already expired by 1 hour
        )

        # Store the expired token in the database
        async with db_pool.connection() as conn:
            await conn.set_autocommit(True)
            from authly.tokens.repository import TokenRepository

            token_repo = TokenRepository(conn)

            token_model = TokenModel(
                id=uuid4(),
                token_jti=jti,
                token_value=expired_token,
                user_id=committed_user.id,
                client_id=None,
                token_type=TokenType.ACCESS,
                scope="openid profile",
                expires_at=datetime.now(UTC) - timedelta(hours=1),  # Expired
                invalidated=False,
            )
            await token_repo.create(token_model)

        # Create Basic Auth header
        credentials = f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Introspect the expired token
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "token": expired_token,
            },
        )

        assert response.status_code == status.HTTP_200_OK
        introspect_data = await response.json()

        # Expired token should return active=false
        assert introspect_data["active"] is False

    @pytest.mark.asyncio
    async def test_introspect_revoked_token(
        self,
        test_server: AsyncTestServer,
        committed_user: UserModel,
        committed_oauth_client: dict[str, Any],
        db_pool: AsyncConnectionPool,
        test_config: AuthlyConfig,
    ) -> None:
        """Test introspection of a revoked token."""
        # Create a valid token
        token, jti = generate_test_token_with_jti(
            test_config, str(committed_user.id), committed_oauth_client["client_id"], "openid"
        )

        # Store the token as revoked
        async with db_pool.connection() as conn:
            await conn.set_autocommit(True)
            from authly.tokens.repository import TokenRepository

            token_repo = TokenRepository(conn)

            token_model = TokenModel(
                id=uuid4(),
                token_jti=jti,
                token_value=token,
                user_id=committed_user.id,
                client_id=None,
                token_type=TokenType.ACCESS,
                scope="openid",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                invalidated=True,  # Marked as revoked
            )
            await token_repo.create(token_model)

        # Create Basic Auth header
        credentials = f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Introspect the revoked token
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "token": token,
            },
        )

        assert response.status_code == status.HTTP_200_OK
        introspect_data = await response.json()

        # Revoked token should return active=false
        assert introspect_data["active"] is False

    @pytest.mark.asyncio
    async def test_introspect_missing_token(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client: dict[str, Any],
    ) -> None:
        """Test introspection with missing token parameter."""
        # Create Basic Auth header
        credentials = f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Try to introspect without providing token
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "token_type_hint": "access_token",
            },
        )

        # Should fail with 422 (validation error)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_introspect_without_authentication(
        self,
        test_server: AsyncTestServer,
    ) -> None:
        """Test that introspection requires client authentication."""
        # Try to introspect without authentication
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            data={
                "token": "some_token",
            },
        )

        # Should return 200 with active=false (per RFC 7662 - no error for security)
        assert response.status_code == status.HTTP_200_OK
        introspect_data = await response.json()
        assert introspect_data["active"] is False

    @pytest.mark.asyncio
    async def test_introspect_token_type_hints(
        self,
        test_server: AsyncTestServer,
        committed_user: UserModel,
        committed_oauth_client: dict[str, Any],
        db_pool: AsyncConnectionPool,
        test_config: AuthlyConfig,
    ) -> None:
        """Test token_type_hint parameter is properly handled."""
        # Create a test token
        token, jti = generate_test_token_with_jti(
            test_config, str(committed_user.id), committed_oauth_client["client_id"], "openid"
        )

        # Store the token
        async with db_pool.connection() as conn:
            await conn.set_autocommit(True)
            from authly.tokens.repository import TokenRepository

            token_repo = TokenRepository(conn)

            token_model = TokenModel(
                id=uuid4(),
                token_jti=jti,
                token_value=token,
                user_id=committed_user.id,
                client_id=None,
                token_type=TokenType.ACCESS,
                scope="openid",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                invalidated=False,
            )
            await token_repo.create(token_model)

        # Create Basic Auth header
        credentials = f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Test with explicit access_token hint
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "token": token,
                "token_type_hint": "access_token",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        introspect_data = await response.json()
        assert introspect_data["active"] is True

        # Test with wrong hint (should still work but might be slower)
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "token": token,
                "token_type_hint": "refresh_token",  # Wrong hint
            },
        )

        assert response.status_code == status.HTTP_200_OK
        introspect_data = await response.json()
        # The endpoint should handle wrong hints gracefully
        assert "active" in introspect_data

    @pytest.mark.asyncio
    async def test_introspect_response_claims(
        self,
        test_server: AsyncTestServer,
        committed_user: UserModel,
        committed_oauth_client: dict[str, Any],
        db_pool: AsyncConnectionPool,
        test_config: AuthlyConfig,
    ) -> None:
        """Test all required and optional claims in introspection response."""
        # Create a test token
        token, jti = generate_test_token_with_jti(
            test_config, str(committed_user.id), committed_oauth_client["client_id"], "openid profile email"
        )

        # Store the token
        async with db_pool.connection() as conn:
            await conn.set_autocommit(True)
            from authly.tokens.repository import TokenRepository

            token_repo = TokenRepository(conn)

            token_model = TokenModel(
                id=uuid4(),
                token_jti=jti,
                token_value=token,
                user_id=committed_user.id,
                client_id=None,
                token_type=TokenType.ACCESS,
                scope="openid profile email",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                invalidated=False,
            )
            await token_repo.create(token_model)

        # Create Basic Auth header
        credentials = f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Introspect the token
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "token": token,
            },
        )

        assert response.status_code == status.HTTP_200_OK
        introspect_data = await response.json()

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
            assert "jti" in introspect_data

            # Validate claim types
            assert isinstance(introspect_data["exp"], int)
            assert isinstance(introspect_data["iat"], int)
            assert isinstance(introspect_data["scope"], str)
            assert isinstance(introspect_data["sub"], str)

            # Validate timestamps are reasonable
            now = int(datetime.now(UTC).timestamp())
            assert introspect_data["iat"] <= now
            assert introspect_data["exp"] > now  # Token should not be expired

    @pytest.mark.asyncio
    async def test_introspect_public_client_authentication(
        self,
        test_server: AsyncTestServer,
        committed_public_client: dict[str, Any],
    ) -> None:
        """Test that public clients can introspect tokens (with limitations)."""
        # Public clients should be able to introspect but may have restrictions
        # Create Basic Auth header with empty password
        credentials = f"{committed_public_client['client_id']}:"
        encoded = base64.b64encode(credentials.encode()).decode()

        # Try to introspect with public client
        response = await test_server.client.post(
            "/api/v1/oauth/introspect",
            headers={"Authorization": f"Basic {encoded}"},
            data={
                "token": "dummy_token",
            },
        )

        # Should return 200 with active=false (token doesn't exist)
        assert response.status_code == status.HTTP_200_OK
        introspect_data = await response.json()
        assert introspect_data["active"] is False
