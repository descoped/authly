"""
Test token introspection endpoint.

Validates the newly implemented RFC 7662 compliant token introspection endpoint.
"""

import secrets
from uuid import uuid4

import pytest
from fastapi import status
from psycopg_toolkit import TransactionManager

from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, GrantType, TokenEndpointAuthMethod
from authly.tokens.service import TokenService
from authly.users import UserRepository
from authly.users.service import UserService


class TestTokenIntrospection:
    """Test the token introspection endpoint."""

    @pytest.mark.asyncio
    async def test_introspect_valid_access_token(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test introspecting a valid access token."""
        async with test_server.client as http_client, transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            user_service = UserService(user_repo)
            token_repo = initialize_authly.get_token_repository()
            client_repo = ClientRepository(conn)

            # Create test user
            username = f"introspect_user_{uuid4().hex[:8]}"
            email = f"{username}@example.com"
            password = "TestPassword123!"

            created_user = await user_service.create_user(
                username=username,
                email=email,
                password=password,
                is_admin=False,
                is_active=True,
                is_verified=True,
            )

            # Create client for introspection
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"introspect_client_{uuid4().hex[:8]}",
                "client_name": "Introspection Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "redirect_uris": ["https://localhost"],
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Create token service
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=client_repo,
            )

            # Create token pair for user
            token_response = await token_service.create_token_pair(user=created_user, scope="read write")

            # Introspect the access token
            import base64

            credentials = f"{created_client.client_id}:{client_secret}"
            basic_auth = base64.b64encode(credentials.encode()).decode()

            response = await http_client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": token_response.access_token,
                    "token_type_hint": "access_token",
                },
                headers={
                    "Authorization": f"Basic {basic_auth}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

            # Should succeed
            assert response.status_code == status.HTTP_200_OK
            data = response.json()

            # Verify introspection response
            assert data["active"] is True
            assert data["token_type"] == "access_token"
            assert data["scope"] == "read write"
            assert data["username"] == username
            assert data["sub"] == str(created_user.id)
            assert "exp" in data
            assert "iat" in data

    @pytest.mark.asyncio
    async def test_introspect_invalid_token(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test introspecting an invalid token."""
        async with test_server.client as http_client, transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create client for introspection
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"introspect_client_{uuid4().hex[:8]}",
                "client_name": "Introspection Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "redirect_uris": ["https://localhost"],
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Introspect an invalid token
            import base64

            credentials = f"{created_client.client_id}:{client_secret}"
            basic_auth = base64.b64encode(credentials.encode()).decode()

            response = await http_client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": "invalid_token_12345",
                    "token_type_hint": "access_token",
                },
                headers={
                    "Authorization": f"Basic {basic_auth}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

            # Should return inactive
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["active"] is False

    @pytest.mark.asyncio
    async def test_introspect_revoked_token(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test introspecting a revoked token."""
        async with test_server.client as http_client, transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            user_service = UserService(user_repo)
            token_repo = initialize_authly.get_token_repository()
            client_repo = ClientRepository(conn)

            # Create test user
            username = f"revoked_user_{uuid4().hex[:8]}"
            email = f"{username}@example.com"
            password = "TestPassword123!"

            created_user = await user_service.create_user(
                username=username,
                email=email,
                password=password,
                is_admin=False,
                is_active=True,
                is_verified=True,
            )

            # Create client
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"revoke_client_{uuid4().hex[:8]}",
                "client_name": "Revoke Test Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "redirect_uris": ["https://localhost"],
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Create token service
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=client_repo,
            )

            # Create and revoke token
            token_response = await token_service.create_token_pair(user=created_user, scope="read")

            # Revoke the token
            await token_service.revoke_token(token=token_response.access_token, token_type_hint="access_token")

            # Try to introspect the revoked token
            import base64

            credentials = f"{created_client.client_id}:{client_secret}"
            basic_auth = base64.b64encode(credentials.encode()).decode()

            response = await http_client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": token_response.access_token,
                    "token_type_hint": "access_token",
                },
                headers={
                    "Authorization": f"Basic {basic_auth}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

            # Should return inactive for revoked token
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["active"] is False

    @pytest.mark.asyncio
    async def test_introspect_without_auth(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test introspection without authentication (should fail)."""
        async with test_server.client as http_client:
            response = await http_client.post(
                "/api/v1/oauth/introspect",
                data={
                    "token": "some_token",
                    "token_type_hint": "access_token",
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

            # Should fail with 401
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
