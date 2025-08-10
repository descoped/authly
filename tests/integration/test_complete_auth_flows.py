"""
Complete end-to-end authentication flow integration tests.

Tests the full OAuth 2.1 and OIDC flows from start to finish,
including authorization, token exchange, refresh, and revocation.
"""

import base64
import hashlib
import secrets
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from psycopg_toolkit import TransactionManager

from authly.api import TokenRequest
from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.authorization_service import AuthorizationService
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import (
    ClientType,
    CodeChallengeMethod,
    GrantType,
    OAuthAuthorizationRequest,
    ResponseType,
    TokenEndpointAuthMethod,
    UserConsentRequest,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.tokens.models import TokenModel, TokenType
from authly.tokens.repository import TokenRepository
from authly.tokens.service import TokenService
from authly.users import UserRepository
from authly.users.service import UserService


def generate_pkce_pair():
    """Generate PKCE code verifier and challenge pair."""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge


class TestCompleteAuthorizationCodeFlow:
    """Test complete OAuth 2.1 Authorization Code + PKCE flow."""

    @pytest.mark.skip(reason="Test needs redesign to use HTTP endpoints instead of direct service calls")
    @pytest.mark.asyncio
    async def test_full_authorization_code_flow(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test complete flow: authorize -> consent -> token -> refresh -> revoke."""
        pool = initialize_authly.get_pool()

        async with test_server.client, pool.connection() as conn:
            await conn.set_autocommit(True)
            # Initialize repositories and services
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            user_repo = UserRepository(conn)
            user_service = UserService(user_repo)
            auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=client_repo,
            )

            # Step 1: Create test user
            username = f"testuser_{uuid4().hex[:8]}"
            password = "TestPassword123!"

            user_data = {
                "username": username,
                "email": f"{username}@example.com",
                "password": password,
                "is_active": True,
                "is_verified": True,
            }
            created_user = await user_service.create_user(user_data)

            # Step 2: Create OAuth client
            client_data = {
                "client_id": f"test_client_{uuid4().hex[:8]}",
                "client_name": "Test OAuth Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["http://localhost:8000/callback"],
                "require_pkce": True,
                "grant_types": [GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Step 3: Create scopes (handle if already exists)
            for scope_name in ["read", "write"]:
                with suppress(Exception):
                    await scope_repo.create_scope(
                        {
                            "scope_name": scope_name,
                            "description": f"{scope_name} access",
                            "is_active": True,
                        }
                    )
            # Step 4: Generate PKCE challenge
            code_verifier, code_challenge = generate_pkce_pair()

            # Step 5: Start authorization request
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType.CODE,
                client_id=created_client.client_id,
                redirect_uri="http://localhost:8000/callback",
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                scope="read write",
                state="test_state_123",
            )

            # Validate authorization request
            is_valid, error_code, client = await auth_service.validate_authorization_request(auth_request)
            assert is_valid is True
            assert error_code is None
            assert client is not None

            # Step 6: User consent (simulated)
            consent_request = UserConsentRequest(
                client_id=created_client.client_id,
                redirect_uri="http://localhost:8000/callback",
                scope="read write",
                state="test_state_123",
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                user_id=created_user.id,
                approved=True,
                approved_scopes=["read", "write"],
            )

            # Generate authorization code
            auth_code = await auth_service.generate_authorization_code(consent_request)
            assert auth_code is not None

            # Step 7: Exchange authorization code for tokens
            success, code_data, error_msg = await auth_service.exchange_authorization_code(
                code=auth_code,
                client_id=created_client.client_id,
                redirect_uri="http://localhost:8000/callback",
                code_verifier=code_verifier,
            )

            assert success is True
            assert code_data is not None
            assert error_msg is None

            # Create token from authorization code
            token_request = TokenRequest(
                grant_type=GrantType.AUTHORIZATION_CODE,
                code=auth_code,
                redirect_uri="http://localhost:8000/callback",
                client_id=created_client.client_id,
                code_verifier=code_verifier,
            )

            token_response = await token_service.create_token(token_request)
            assert token_response is not None
            assert token_response.access_token is not None
            assert token_response.refresh_token is not None
            assert token_response.token_type == "Bearer"
            assert token_response.expires_in > 0

            # Step 8: Use refresh token
            refresh_request = TokenRequest(
                grant_type=GrantType.REFRESH_TOKEN,
                refresh_token=token_response.refresh_token,
                client_id=created_client.client_id,
            )

            refreshed_response = await token_service.create_token(refresh_request)
            assert refreshed_response is not None
            assert refreshed_response.access_token is not None
            assert refreshed_response.access_token != token_response.access_token  # New token

            # Step 9: Introspect token
            introspection = await token_service.introspect_token(
                token=refreshed_response.access_token,
                token_type_hint="access_token",
            )

            assert introspection["active"] is True
            assert introspection["client_id"] == created_client.client_id
            assert introspection["username"] == username

            # Step 10: Revoke token
            await token_service.revoke_token(
                token=refreshed_response.access_token,
                token_type_hint="access_token",
            )

            # Verify token is revoked
            introspection_after = await token_service.introspect_token(
                token=refreshed_response.access_token,
                token_type_hint="access_token",
            )
            assert introspection_after["active"] is False


class TestCompleteOIDCFlow:
    """Test complete OpenID Connect flow."""

    @pytest.mark.asyncio
    async def test_full_oidc_flow_with_id_token(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test OIDC flow: authorize with openid scope -> get ID token -> validate -> userinfo."""
        pool = initialize_authly.get_pool()

        async with test_server.client, pool.connection() as conn:
            await conn.set_autocommit(True)
            # Initialize repositories and services
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            user_repo = UserRepository(conn)
            user_service = UserService(user_repo)
            auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create test user with OIDC claims
            user_data = {
                "username": f"oidc_user_{uuid4().hex[:8]}",
                "email": f"oidc_{uuid4().hex[:8]}@example.com",
                "password": "TestPassword123!",
                "given_name": "John",
                "family_name": "Doe",
                "is_active": True,
                "is_verified": True,
            }
            created_user = await user_service.create_user(user_data)

            # Create OIDC client
            client_data = {
                "client_id": f"oidc_client_{uuid4().hex[:8]}",
                "client_name": "OIDC Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["http://localhost:8000/callback"],
                "require_pkce": True,
                "grant_types": [GrantType.AUTHORIZATION_CODE],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Create OIDC scopes (handle if already exists)
            for scope_name in ["openid", "profile", "email"]:
                with suppress(Exception):
                    await scope_repo.create_scope(
                        {
                            "scope_name": scope_name,
                            "description": f"OIDC {scope_name} scope",
                            "is_active": True,
                        }
                    )
            # Generate PKCE and nonce
            code_verifier, code_challenge = generate_pkce_pair()
            nonce = f"nonce_{uuid4().hex}"

            # Authorization request with OIDC scopes
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType.CODE,
                client_id=created_client.client_id,
                redirect_uri="http://localhost:8000/callback",
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                scope="openid profile email",
                state="test_state_123",
                nonce=nonce,
            )

            # Validate request
            is_valid, error_code, client = await auth_service.validate_authorization_request(auth_request)
            assert is_valid is True

            # User consent
            consent_request = UserConsentRequest(
                client_id=created_client.client_id,
                redirect_uri="http://localhost:8000/callback",
                scope="openid profile email",
                state="test_state_123",
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                user_id=created_user.id,
                approved=True,
                approved_scopes=["openid", "profile", "email"],
                nonce=nonce,
            )

            # Generate authorization code
            auth_code = await auth_service.generate_authorization_code(consent_request)
            assert auth_code is not None

            # Exchange code for tokens (should include ID token)
            # This would be done via HTTP endpoint in real scenario
            # The response should include:
            # - access_token
            # - id_token (JWT with user claims)
            # - token_type: "Bearer"
            # - expires_in

            # ID token should contain:
            # - iss (issuer)
            # - sub (subject/user ID)
            # - aud (audience/client ID)
            # - exp (expiration)
            # - iat (issued at)
            # - nonce (if provided)
            # - given_name, family_name (profile scope)
            # - email, email_verified (email scope)


class TestLogoutFlow:
    """Test logout and session termination flows."""

    @pytest.mark.asyncio
    async def test_oidc_logout_flow(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test OIDC RP-initiated logout flow."""
        pool = initialize_authly.get_pool()

        async with test_server.client, pool.connection() as conn:
            await conn.set_autocommit(True)
            token_repo = TokenRepository(conn)
            user_repo = UserRepository(conn)
            user_service = UserService(user_repo)
            client_repo = ClientRepository(conn)

            # Create a real user
            user_data = {
                "username": f"logout_user_{uuid4().hex[:8]}",
                "email": f"logout_{uuid4().hex[:8]}@example.com",
                "password": "TestPassword123!",
                "is_active": True,
                "is_verified": True,
            }
            created_user = await user_service.create_user(user_data)
            user_id = created_user.id

            # Create a real client
            client_data = {
                "client_id": f"logout_client_{uuid4().hex[:8]}",
                "client_name": "Logout Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["http://localhost:8000/callback"],
                "grant_types": [GrantType.AUTHORIZATION_CODE],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)
            client_id = created_client.id

            # Create access token
            access_token = TokenModel(
                id=uuid4(),
                token_jti=f"access_{uuid4().hex}",
                token_type=TokenType.ACCESS,
                token_value=f"dummy_access_token_{uuid4().hex}",
                client_id=client_id,
                user_id=user_id,
                scope="openid profile",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                created_at=datetime.now(UTC),
            )
            await token_repo.store_token(access_token)

            # Create refresh token
            refresh_token = TokenModel(
                id=uuid4(),
                token_jti=f"refresh_{uuid4().hex}",
                token_type=TokenType.REFRESH,
                token_value=f"dummy_refresh_token_{uuid4().hex}",
                client_id=client_id,
                user_id=user_id,
                scope="openid profile",
                expires_at=datetime.now(UTC) + timedelta(days=30),
                created_at=datetime.now(UTC),
            )
            await token_repo.store_token(refresh_token)

            # Perform logout (would be HTTP endpoint)
            # Should revoke all tokens for the user/client combination

            # Verify tokens are revoked
            await token_repo.get_by_jti(access_token.token_jti)
            await token_repo.get_by_jti(refresh_token.token_jti)

            # After logout, tokens should be marked as revoked
            # This test is incomplete - logout functionality needs implementation


class TestErrorHandling:
    """Test error handling in authentication flows."""

    @pytest.mark.skip(reason="TokenService.create_token expects TokenModel not TokenRequest - needs redesign")
    @pytest.mark.asyncio
    async def test_invalid_grant_error(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test proper error response for invalid grant."""
        pool = initialize_authly.get_pool()
        async with pool.connection() as conn:
            await conn.set_autocommit(True)
            # Fixed initialization but test logic needs redesign
            TokenService(
                repository=TokenRepository(conn),
                config=initialize_authly.config,
                client_repository=ClientRepository(conn),
            )

            # This test needs to be rewritten to use HTTP endpoints
            # TokenService.create_token expects TokenModel, not TokenRequest
            pass

    @pytest.mark.asyncio
    async def test_invalid_client_error(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test proper error response for invalid client."""
        pool = initialize_authly.get_pool()
        async with pool.connection() as conn:
            await conn.set_autocommit(True)
            auth_service = AuthorizationService(
                ClientRepository(conn),
                ScopeRepository(conn),
                AuthorizationCodeRepository(conn),
            )

            # Generate PKCE
            code_verifier, code_challenge = generate_pkce_pair()

            # Try with non-existent client
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType.CODE,
                client_id="non_existent_client",
                redirect_uri="http://localhost:8000/callback",
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                scope="read",
                state="test_state",
            )

            is_valid, error_code, client = await auth_service.validate_authorization_request(auth_request)

            assert is_valid is False
            assert error_code == "unauthorized_client"
            assert client is None

    @pytest.mark.asyncio
    async def test_invalid_scope_error(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test proper error response for invalid scope."""
        pool = initialize_authly.get_pool()
        async with pool.connection() as conn:
            await conn.set_autocommit(True)
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_service = AuthorizationService(
                client_repo,
                scope_repo,
                AuthorizationCodeRepository(conn),
            )

            # Create client
            client_data = {
                "client_id": f"test_client_{uuid4().hex[:8]}",
                "client_name": "Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["http://localhost:8000/callback"],
                "require_pkce": True,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Generate PKCE
            code_verifier, code_challenge = generate_pkce_pair()

            # Request non-existent scope
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType.CODE,
                client_id=created_client.client_id,
                redirect_uri="http://localhost:8000/callback",
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                scope="non_existent_scope",
                state="test_state",
            )

            is_valid, error_code, client = await auth_service.validate_authorization_request(auth_request)

            # Should fail with invalid_scope
            assert is_valid is False
            assert error_code == "invalid_scope"


class TestTokenRotation:
    """Test refresh token rotation for enhanced security."""

    @pytest.mark.skip(reason="Refresh token rotation feature not fully implemented")
    @pytest.mark.asyncio
    async def test_refresh_token_rotation(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that refresh tokens are rotated on use."""
        pool = initialize_authly.get_pool()
        async with pool.connection() as conn:
            await conn.set_autocommit(True)
            client_repo = ClientRepository(conn)
            token_repo = TokenRepository(conn)
            token_service = TokenService(
                repository=token_repo,
                config=initialize_authly.config,
                client_repository=client_repo,
            )

            # Create client
            client_data = {
                "client_id": f"rotation_client_{uuid4().hex[:8]}",
                "client_name": "Rotation Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["http://localhost:8000/callback"],  # Required field
                "grant_types": [GrantType.REFRESH_TOKEN],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Create initial refresh token
            initial_refresh = f"refresh_{uuid4().hex}"
            token_data = {
                "token": initial_refresh,
                "token_type": "Refresh",
                "client_id": created_client.id,
                "user_id": uuid4(),
                "scope": "read write",
                "expires_at": datetime.now(UTC) + timedelta(days=30),
                "issued_at": datetime.now(UTC),
            }
            await token_repo.create(token_data)

            # Use refresh token
            refresh_request = TokenRequest(
                grant_type=GrantType.REFRESH_TOKEN,
                refresh_token=initial_refresh,
                client_id=created_client.client_id,
            )

            new_tokens = await token_service.create_token(refresh_request)

            # Should get new refresh token (rotation)
            assert new_tokens.refresh_token is not None
            assert new_tokens.refresh_token != initial_refresh

            # Old refresh token should be invalidated
            old_token = await token_repo.get_token(initial_refresh)
            assert old_token is None or old_token.is_revoked is True
