"""
Test ID token generation in OIDC flows.

Validates that ID tokens are properly generated when openid scope is requested.
"""

import base64
import hashlib
import secrets
from uuid import uuid4

import jwt
import pytest
from fastapi import status
from psycopg_toolkit import TransactionManager

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
from authly.users import UserRepository
from authly.users.service import UserService


def generate_pkce_pair():
    """Generate PKCE code verifier and challenge pair."""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge


class TestIDTokenGeneration:
    """Test ID token generation in OIDC flows."""

    @pytest.mark.asyncio
    async def test_id_token_included_with_openid_scope(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that ID token is included when openid scope is requested."""
        async with test_server.client as http_client:
            pool = initialize_authly.get_pool()
            async with pool.connection() as conn:
                await conn.set_autocommit(True)
                # Initialize repositories and services
                client_repo = ClientRepository(conn)
                scope_repo = ScopeRepository(conn)
                auth_code_repo = AuthorizationCodeRepository(conn)
                user_repo = UserRepository(conn)
                user_service = UserService(user_repo)
                auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

                # Create test user
                username = f"oidc_user_{uuid4().hex[:8]}"
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

                # Create OIDC scopes (or ensure they exist)
                for scope_name in ["openid", "profile", "email"]:
                    existing_scope = await scope_repo.get_by_scope_name(scope_name)
                    if not existing_scope:
                        await scope_repo.create_scope(
                            {
                                "scope_name": scope_name,
                                "description": f"OIDC {scope_name} scope",
                                "is_active": True,
                            }
                        )

                # Generate PKCE and nonce
                code_verifier, code_challenge = generate_pkce_pair()
                nonce = f"test_nonce_{uuid4().hex}"

                # Create authorization request with openid scope
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

                # Validate authorization request
                is_valid, error_code, client = await auth_service.validate_authorization_request(auth_request)
                assert is_valid is True

                # Simulate user consent
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

                # Exchange code for tokens via HTTP endpoint
                response = await http_client.post(
                    "/api/v1/oauth/token",
                    data={
                        "grant_type": "authorization_code",
                        "code": auth_code,
                        "redirect_uri": "http://localhost:8000/callback",
                        "client_id": created_client.client_id,
                        "code_verifier": code_verifier,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                # Should succeed
                assert response.status_code == status.HTTP_200_OK
                token_data = await response.json()

                # Should include ID token when openid scope is requested
                assert token_data.get("id_token") is not None
                assert "access_token" in token_data
                assert "refresh_token" in token_data

                # Decode and validate ID token structure (without signature verification)
                id_token = token_data["id_token"]
                decoded = jwt.decode(id_token, options={"verify_signature": False})

                # Check required claims
                assert "iss" in decoded  # Issuer
                assert "sub" in decoded  # Subject (user ID)
                assert "aud" in decoded  # Audience (client ID)
                assert "exp" in decoded  # Expiration
                assert "iat" in decoded  # Issued at

                # Check nonce is included
                assert decoded.get("nonce") == nonce

                # Check user claims from profile scope
                assert "email" in decoded  # From email scope
                assert decoded["email"] == email

    @pytest.mark.asyncio
    async def test_no_id_token_without_openid_scope(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that ID token is NOT included without openid scope."""
        async with test_server.client as http_client:
            pool = initialize_authly.get_pool()
            async with pool.connection() as conn:
                await conn.set_autocommit(True)
                # Initialize repositories and services
                client_repo = ClientRepository(conn)
                scope_repo = ScopeRepository(conn)
                auth_code_repo = AuthorizationCodeRepository(conn)
                user_repo = UserRepository(conn)
                user_service = UserService(user_repo)
                auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

                # Create test user
                username = f"oauth_user_{uuid4().hex[:8]}"
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

                # Create OAuth client
                client_data = {
                    "client_id": f"oauth_client_{uuid4().hex[:8]}",
                    "client_name": "OAuth Test Client",
                    "client_type": ClientType.PUBLIC,
                    "redirect_uris": ["http://localhost:8000/callback"],
                    "require_pkce": True,
                    "grant_types": [GrantType.AUTHORIZATION_CODE],
                    "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
                }
                created_client = await client_repo.create_client(client_data)

                # Create regular OAuth scopes (no openid)
                for scope_name in ["read", "write"]:
                    existing_scope = await scope_repo.get_by_scope_name(scope_name)
                    if not existing_scope:
                        await scope_repo.create_scope(
                            {
                                "scope_name": scope_name,
                                "description": f"{scope_name} access",
                                "is_active": True,
                            }
                        )

                # Generate PKCE
                code_verifier, code_challenge = generate_pkce_pair()

                # Create authorization request WITHOUT openid scope
                auth_request = OAuthAuthorizationRequest(
                    response_type=ResponseType.CODE,
                    client_id=created_client.client_id,
                    redirect_uri="http://localhost:8000/callback",
                    code_challenge=code_challenge,
                    code_challenge_method=CodeChallengeMethod.S256,
                    scope="read write",  # No openid
                    state="test_state_123",
                )

                # Validate authorization request
                is_valid, error_code, client = await auth_service.validate_authorization_request(auth_request)
                assert is_valid is True

                # Simulate user consent
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

                # Exchange code for tokens
                response = await http_client.post(
                    "/api/v1/oauth/token",
                    data={
                        "grant_type": "authorization_code",
                        "code": auth_code,
                        "redirect_uri": "http://localhost:8000/callback",
                        "client_id": created_client.client_id,
                        "code_verifier": code_verifier,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                # Should succeed
                assert response.status_code == status.HTTP_200_OK
                token_data = await response.json()

                # Should NOT include ID token without openid scope
                assert token_data.get("id_token") is None
                assert "access_token" in token_data
                assert "refresh_token" in token_data
