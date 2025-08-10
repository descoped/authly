"""
Client Credentials Flow tests for OAuth 2.0.

Tests machine-to-machine authentication, scope validation, and token introspection.
"""

import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from psycopg_toolkit import TransactionManager

from authly.api import TokenRequest
from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import (
    ClientType,
    GrantType,
    TokenEndpointAuthMethod,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.tokens.models import TokenType
from authly.tokens.repository import TokenRepository
from authly.tokens.service import TokenService


class TestClientCredentialsGrant:
    """Test Client Credentials grant type for machine-to-machine auth."""

    @pytest.mark.asyncio
    async def test_client_credentials_grant_success(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test successful client credentials grant."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=client_repo,
            )

            # Create confidential client (required for client credentials)
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"machine_client_{uuid4().hex[:8]}",
                "client_name": "Machine Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Create scopes
            scope_data = {
                "scope_name": "api.read",
                "description": "Read API access",
                "is_default": False,
                "is_active": True,
            }
            await scope_repo.create_scope(scope_data)

            # Create token request
            token_request = TokenRequest(
                grant_type=GrantType.CLIENT_CREDENTIALS,
                client_id=created_client.client_id,
                client_secret=client_secret,
                scope="api.read",
            )

            # Request token
            token_response = await token_service.create_token(token_request)

            assert token_response is not None
            assert token_response.access_token is not None
            assert token_response.token_type == TokenType.BEARER
            assert token_response.expires_in > 0
            assert token_response.scope == "api.read"

            # Client credentials should NOT issue refresh token
            assert token_response.refresh_token is None

    @pytest.mark.asyncio
    async def test_client_credentials_requires_confidential_client(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that client credentials grant requires confidential client."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            ScopeRepository(conn)
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=client_repo,
            )

            # Create PUBLIC client (should not work)
            client_data = {
                "client_id": f"public_client_{uuid4().hex[:8]}",
                "client_name": "Public Client",
                "client_type": ClientType.PUBLIC,
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Try to use client credentials grant
            token_request = TokenRequest(
                grant_type=GrantType.CLIENT_CREDENTIALS,
                client_id=created_client.client_id,
                scope="api.read",
            )

            # Should fail - public clients can't use client credentials
            with pytest.raises(Exception) as exc_info:
                await token_service.create_token(token_request)

            assert "unauthorized" in str(exc_info.value).lower() or "public client" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_client_credentials_invalid_secret(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test client credentials with invalid client secret."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            ScopeRepository(conn)
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=client_repo,
            )

            # Create confidential client
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"machine_client_{uuid4().hex[:8]}",
                "client_name": "Machine Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Use WRONG secret
            token_request = TokenRequest(
                grant_type=GrantType.CLIENT_CREDENTIALS,
                client_id=created_client.client_id,
                client_secret="wrong_secret",
                scope="api.read",
            )

            # Should fail authentication
            with pytest.raises(Exception) as exc_info:
                await token_service.create_token(token_request)

            assert "invalid" in str(exc_info.value).lower() or "unauthorized" in str(exc_info.value).lower()


class TestClientCredentialsScopes:
    """Test scope handling in client credentials flow."""

    @pytest.mark.asyncio
    async def test_client_credentials_scope_validation(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that requested scopes are validated."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=client_repo,
            )

            # Create client with specific allowed scopes
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"limited_client_{uuid4().hex[:8]}",
                "client_name": "Limited Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "allowed_scopes": ["api.read", "api.list"],  # Limited scopes
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Create scopes
            for scope_name in ["api.read", "api.list", "api.write"]:
                await scope_repo.create_scope(
                    {
                        "scope_name": scope_name,
                        "description": f"{scope_name} access",
                        "is_active": True,
                    }
                )

            # Request allowed scope - should succeed
            token_request = TokenRequest(
                grant_type=GrantType.CLIENT_CREDENTIALS,
                client_id=created_client.client_id,
                client_secret=client_secret,
                scope="api.read api.list",
            )

            token_response = await token_service.create_token(token_request)
            assert token_response is not None
            assert "api.read" in token_response.scope
            assert "api.list" in token_response.scope

            # Request disallowed scope - should fail or filter
            token_request_invalid = TokenRequest(
                grant_type=GrantType.CLIENT_CREDENTIALS,
                client_id=created_client.client_id,
                client_secret=client_secret,
                scope="api.read api.write",  # api.write not allowed
            )

            try:
                token_response_filtered = await token_service.create_token(token_request_invalid)
                # If it succeeds, scope should be filtered
                assert "api.read" in token_response_filtered.scope
                assert "api.write" not in token_response_filtered.scope
            except Exception as e:
                # Or it might reject the request entirely
                assert "invalid_scope" in str(e).lower()

    @pytest.mark.asyncio
    async def test_client_credentials_no_user_context(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that client credentials tokens have no user context."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            ScopeRepository(conn)
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=client_repo,
            )

            # Create client
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"machine_client_{uuid4().hex[:8]}",
                "client_name": "Machine Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Request token
            token_request = TokenRequest(
                grant_type=GrantType.CLIENT_CREDENTIALS,
                client_id=created_client.client_id,
                client_secret=client_secret,
            )

            token_response = await token_service.create_token(token_request)

            # Verify token in database has no user association
            stored_token = await token_repo.get_token(token_response.access_token)
            assert stored_token is not None
            assert stored_token.user_id is None  # No user context
            assert stored_token.client_id == created_client.id


class TestClientAuthentication:
    """Test different client authentication methods."""

    @pytest.mark.asyncio
    async def test_client_secret_basic_auth(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test client authentication using HTTP Basic auth."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create client with basic auth
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"basic_auth_client_{uuid4().hex[:8]}",
                "client_name": "Basic Auth Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Verify client can authenticate with basic auth
            # In actual endpoint, this would be:
            # Authorization: Basic base64(client_id:client_secret)
            import base64

            credentials = f"{created_client.client_id}:{client_secret}"
            base64.b64encode(credentials.encode()).decode()

            # Verify authentication
            authenticated = await client_repo.authenticate_client(
                client_id=created_client.client_id,
                client_secret=client_secret,
            )
            assert authenticated is True

    @pytest.mark.asyncio
    async def test_client_secret_post_auth(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test client authentication using POST parameters."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create client with post auth
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"post_auth_client_{uuid4().hex[:8]}",
                "client_name": "POST Auth Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_POST,
            }
            created_client = await client_repo.create_client(client_data)

            # Verify client can authenticate with POST params
            authenticated = await client_repo.authenticate_client(
                client_id=created_client.client_id,
                client_secret=client_secret,
            )
            assert authenticated is True

    @pytest.mark.asyncio
    async def test_client_authentication_failure(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test client authentication failures."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create client
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"test_client_{uuid4().hex[:8]}",
                "client_name": "Test Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Test various failure scenarios

            # Wrong secret
            authenticated = await client_repo.authenticate_client(
                client_id=created_client.client_id,
                client_secret="wrong_secret",
            )
            assert authenticated is False

            # Non-existent client
            authenticated = await client_repo.authenticate_client(
                client_id="non_existent_client",
                client_secret=client_secret,
            )
            assert authenticated is False

            # Empty secret for confidential client
            authenticated = await client_repo.authenticate_client(
                client_id=created_client.client_id,
                client_secret="",
            )
            assert authenticated is False


class TestTokenIntrospection:
    """Test token introspection for client credentials tokens."""

    @pytest.mark.asyncio
    async def test_introspect_active_token(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test introspection of active token."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                client_repo=client_repo,
                scope_repo=ScopeRepository(conn),
                token_repo=token_repo,
                config=initialize_authly.config,
            )

            # Create client and token
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"introspect_client_{uuid4().hex[:8]}",
                "client_name": "Introspect Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Create token
            token_request = TokenRequest(
                grant_type=GrantType.CLIENT_CREDENTIALS,
                client_id=created_client.client_id,
                client_secret=client_secret,
                scope="api.read",
            )
            token_response = await token_service.create_token(token_request)

            # Introspect token
            introspection = await token_service.introspect_token(
                token=token_response.access_token,
                token_type_hint="access_token",
            )

            assert introspection is not None
            assert introspection["active"] is True
            assert introspection["client_id"] == created_client.client_id
            assert introspection["scope"] == "api.read"
            assert introspection["token_type"] == "Bearer"
            assert "exp" in introspection
            assert "iat" in introspection

    @pytest.mark.asyncio
    async def test_introspect_expired_token(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test introspection of expired token."""
        async with transaction_manager.transaction() as conn:
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=ClientRepository(conn),
            )

            # Create expired token
            expired_token_data = {
                "token": f"expired_token_{uuid4().hex}",
                "token_type": TokenType.BEARER,
                "client_id": uuid4(),
                "user_id": None,  # No user for client credentials
                "scope": "api.read",
                "expires_at": datetime.now(UTC) - timedelta(hours=1),  # Expired
                "issued_at": datetime.now(UTC) - timedelta(hours=2),
            }
            await token_repo.create_token(expired_token_data)

            # Introspect expired token
            introspection = await token_service.introspect_token(
                token=expired_token_data["token"],
                token_type_hint="access_token",
            )

            # Expired tokens should return active=false
            assert introspection is not None
            assert introspection["active"] is False

    @pytest.mark.asyncio
    async def test_introspect_revoked_token(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test introspection of revoked token."""
        async with transaction_manager.transaction() as conn:
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=ClientRepository(conn),
            )

            # Create and revoke token
            token_data = {
                "token": f"revoked_token_{uuid4().hex}",
                "token_type": TokenType.BEARER,
                "client_id": uuid4(),
                "user_id": None,
                "scope": "api.read",
                "expires_at": datetime.now(UTC) + timedelta(hours=1),
                "issued_at": datetime.now(UTC),
                "is_revoked": True,  # Revoked
            }
            await token_repo.create_token(token_data)

            # Introspect revoked token
            introspection = await token_service.introspect_token(
                token=token_data["token"],
                token_type_hint="access_token",
            )

            # Revoked tokens should return active=false
            assert introspection is not None
            assert introspection["active"] is False


class TestClientCredentialsTokenLifetime:
    """Test token lifetime for client credentials."""

    @pytest.mark.asyncio
    async def test_client_credentials_token_expiration(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that client credentials tokens expire correctly."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                client_repo=client_repo,
                scope_repo=ScopeRepository(conn),
                token_repo=token_repo,
                config=initialize_authly.config,
            )

            # Create client
            client_secret = secrets.token_urlsafe(32)
            client_data = {
                "client_id": f"expiry_client_{uuid4().hex[:8]}",
                "client_name": "Expiry Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": client_secret,
                "grant_types": [GrantType.CLIENT_CREDENTIALS],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            created_client = await client_repo.create_client(client_data)

            # Request token
            token_request = TokenRequest(
                grant_type=GrantType.CLIENT_CREDENTIALS,
                client_id=created_client.client_id,
                client_secret=client_secret,
            )
            token_response = await token_service.create_token(token_request)

            # Check expiration
            assert token_response.expires_in > 0

            # Default should be 1 hour (3600 seconds)
            assert token_response.expires_in == 3600

            # Verify in database
            stored_token = await token_repo.get_token(token_response.access_token)
            time_until_expiry = stored_token.expires_at - datetime.now(UTC)
            assert time_until_expiry.total_seconds() > 0
            assert time_until_expiry.total_seconds() <= 3600
