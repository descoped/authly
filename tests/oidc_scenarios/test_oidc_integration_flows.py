"""
OIDC Integration Tests for Authorization Code Flow

This module contains integration tests for the OpenID Connect Authorization Code Flow,
testing the complete flow from authorization request to token exchange to UserInfo.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from jose import jwt
from psycopg_toolkit import TransactionManager

from authly.api import auth_router, oauth_router, oidc_router, users_router
from authly.auth.core import get_password_hash
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, OAuthClientModel, TokenEndpointAuthMethod
from authly.oauth.scope_repository import ScopeRepository
from authly.users import UserModel, UserRepository


class TestOIDCIntegrationFlows:
    """Test OIDC Authorization Code Flow integration."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
        test_server.app.include_router(auth_router, prefix="/api/v1")
        test_server.app.include_router(users_router, prefix="/api/v1")
        test_server.app.include_router(oauth_router, prefix="/api/v1")
        test_server.app.include_router(oidc_router)  # No prefix - uses well-known paths
        return test_server

    @pytest.fixture
    async def test_user(self, transaction_manager: TransactionManager) -> UserModel:
        """Create a test user for OIDC flows."""
        user_data = UserModel(
            id=uuid4(),
            username=f"oidcuser_{uuid4().hex[:8]}",
            email=f"oidc_{uuid4().hex[:8]}@example.com",
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
    async def test_client_confidential(self, transaction_manager: TransactionManager) -> OAuthClientModel:
        """Create a confidential OAuth client for testing."""
        client_data = OAuthClientModel(
            id=uuid4(),
            client_id=f"test_client_{uuid4().hex[:8]}",
            client_name="Test OIDC Client",
            client_secret_hash=get_password_hash("test_client_secret"),
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            require_pkce=True,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            return await client_repo.create(client_data)

    @pytest.fixture
    async def setup_oidc_scopes(self, transaction_manager: TransactionManager):
        """Set up required OIDC scopes."""
        scopes = [
            {"scope_name": "openid", "description": "OpenID Connect scope"},
            {"scope_name": "profile", "description": "Profile information"},
            {"scope_name": "email", "description": "Email address"},
            {"scope_name": "address", "description": "Address information"},
            {"scope_name": "phone", "description": "Phone number"},
        ]

        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            for scope_data in scopes:
                # Check if scope already exists
                existing = await scope_repo.get_by_scope_name(scope_data["scope_name"])
                if not existing:
                    from authly.oauth.models import OAuthScopeModel

                    scope_model = OAuthScopeModel(
                        id=uuid4(),
                        scope_name=scope_data["scope_name"],
                        description=scope_data["description"],
                        is_default=False,
                        is_active=True,
                        created_at=datetime.now(UTC),
                        updated_at=datetime.now(UTC),
                    )
                    await scope_repo.create(scope_model)

    @pytest.mark.asyncio
    async def test_oidc_discovery_endpoint_accuracy(self, oidc_server: AsyncTestServer):
        """Test that OIDC discovery endpoint advertises only supported flows."""

        # Get OIDC discovery metadata
        discovery_response = await oidc_server.client.get("/.well-known/openid-configuration")
        await discovery_response.expect_status(200)

        discovery_data = await discovery_response.json()

        # Should only advertise supported response types
        assert "code" in discovery_data["response_types_supported"]
        assert "id_token" not in discovery_data["response_types_supported"]
        assert "code id_token" not in discovery_data["response_types_supported"]

        # Should only advertise supported response modes
        assert "query" in discovery_data["response_modes_supported"]
        assert "fragment" not in discovery_data["response_modes_supported"]

        # Should include OIDC endpoints
        assert discovery_data["userinfo_endpoint"].endswith("/oidc/userinfo")
        assert discovery_data["jwks_uri"].endswith("/.well-known/jwks.json")

    @pytest.mark.asyncio
    async def test_jwks_endpoint_functionality(self, oidc_server: AsyncTestServer):
        """Test JWKS endpoint provides valid keys."""

        # Get JWKS
        jwks_response = await oidc_server.client.get("/.well-known/jwks.json")
        await jwks_response.expect_status(200)

        jwks_data = await jwks_response.json()

        # Should have keys array
        assert "keys" in jwks_data
        assert len(jwks_data["keys"]) > 0

        # Each key should have required fields
        for key in jwks_data["keys"]:
            assert "kty" in key  # Key type
            assert "use" in key  # Key use
            assert "alg" in key  # Algorithm
            assert "kid" in key  # Key ID
            assert "n" in key  # RSA modulus
            assert "e" in key  # RSA exponent

    @pytest.mark.asyncio
    async def test_userinfo_endpoint_requires_authentication(self, oidc_server: AsyncTestServer):
        """Test UserInfo endpoint requires proper authentication."""

        # Should fail without token
        userinfo_response = await oidc_server.client.get("/oidc/userinfo")
        await userinfo_response.expect_status(401)

        # Should fail with invalid token
        userinfo_response = await oidc_server.client.get(
            "/oidc/userinfo", headers={"Authorization": "Bearer invalid_token"}
        )
        await userinfo_response.expect_status(401)

    @pytest.mark.asyncio
    async def test_authorization_endpoint_with_oidc_params(
        self, oidc_server: AsyncTestServer, test_client_confidential: OAuthClientModel, setup_oidc_scopes
    ):
        """Test authorization endpoint handles OIDC parameters correctly."""

        # Test authorization request with OIDC parameters
        auth_params = {
            "response_type": "code",
            "client_id": test_client_confidential.client_id,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "scope": "openid profile email",
            "state": "test_state",
            "nonce": "test_nonce",
            "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "S256",
            "max_age": "3600",
            "display": "page",
            "prompt": "consent",
        }

        # OAuth 2.0 redirects with error when not authenticated
        auth_response = await oidc_server.client.get(
            "/api/v1/oauth/authorize", params=auth_params, follow_redirects=False
        )
        await auth_response.expect_status(302)

    @pytest.mark.asyncio
    async def test_token_endpoint_includes_id_token(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_confidential: OAuthClientModel,
        setup_oidc_scopes,
        transaction_manager: TransactionManager,
    ):
        """Test token endpoint includes ID token for OIDC requests."""

        # Create authorization code in database
        from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
        from authly.oauth.models import OAuthAuthorizationCodeModel

        auth_code = f"test_code_{uuid4().hex[:8]}"

        async with transaction_manager.transaction() as conn:
            code_repo = AuthorizationCodeRepository(conn)

            code_data = OAuthAuthorizationCodeModel(
                id=uuid4(),
                code=auth_code,
                client_id=test_client_confidential.id,
                user_id=test_user.id,
                scope="openid profile email",
                code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                code_challenge_method="S256",
                redirect_uri=test_client_confidential.redirect_uris[0],
                expires_at=datetime.now(UTC).replace(hour=23, minute=59),
                created_at=datetime.now(UTC),
                # OIDC parameters
                nonce="test_nonce",
                max_age=3600,
                display="page",
                prompt="consent",
            )

            await code_repo.create(code_data)

        # Exchange authorization code for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_result = await token_response.json()

        # Should include ID token for OIDC request
        assert "access_token" in token_result
        assert "id_token" in token_result
        assert "token_type" in token_result
        assert token_result["token_type"] == "Bearer"

        # Validate ID token structure
        id_token = token_result["id_token"]
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})

        # Should have required OIDC claims
        assert id_token_payload["iss"] == "https://authly.localhost"
        assert id_token_payload["sub"] == str(test_user.id)
        assert id_token_payload["aud"] == test_client_confidential.client_id
        assert id_token_payload["nonce"] == "test_nonce"
        assert "exp" in id_token_payload
        assert "iat" in id_token_payload

        # Should have scope-based claims
        assert "name" in id_token_payload  # profile scope
        assert "email" in id_token_payload  # email scope

    @pytest.mark.asyncio
    async def test_token_endpoint_no_id_token_for_non_oidc(self, oidc_server: AsyncTestServer, test_user: UserModel):
        """Test token endpoint doesn't include ID token for non-OIDC requests."""

        # Test password grant (non-OIDC)
        token_response = await oidc_server.client.post(
            "/api/v1/oauth/token",
            data={"grant_type": "password", "username": test_user.username, "password": "Test123!"},
        )

        await token_response.expect_status(200)
        token_result = await token_response.json()

        # Should not include ID token for non-OIDC request
        assert "access_token" in token_result
        assert token_result.get("id_token") is None
        assert "token_type" in token_result

    @pytest.mark.asyncio
    async def test_userinfo_endpoint_with_valid_token(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_confidential: OAuthClientModel,
        setup_oidc_scopes,
        transaction_manager: TransactionManager,
    ):
        """Test UserInfo endpoint with valid access token."""

        # Get access token through OIDC flow (similar to previous test)
        from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
        from authly.oauth.models import OAuthAuthorizationCodeModel

        auth_code = f"test_code_{uuid4().hex[:8]}"

        async with transaction_manager.transaction() as conn:
            code_repo = AuthorizationCodeRepository(conn)

            code_data = OAuthAuthorizationCodeModel(
                id=uuid4(),
                code=auth_code,
                client_id=test_client_confidential.id,
                user_id=test_user.id,
                scope="openid profile email",
                code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                code_challenge_method="S256",
                redirect_uri=test_client_confidential.redirect_uris[0],
                expires_at=datetime.now(UTC).replace(hour=23, minute=59),
                created_at=datetime.now(UTC),
                nonce="test_nonce",
            )

            await code_repo.create(code_data)

        # Get access token
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_result = await token_response.json()
        access_token = token_result["access_token"]

        # Use access token to get UserInfo
        userinfo_response = await oidc_server.client.get(
            "/oidc/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        await userinfo_response.expect_status(200)

        userinfo_result = await userinfo_response.json()

        # Should have user claims based on scopes
        assert userinfo_result["sub"] == str(test_user.id)
        assert "name" in userinfo_result  # profile scope
        assert "email" in userinfo_result  # email scope
        assert userinfo_result["email"] == test_user.email

    @pytest.mark.asyncio
    async def test_refresh_token_maintains_id_token(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_confidential: OAuthClientModel,
        setup_oidc_scopes,
        transaction_manager: TransactionManager,
    ):
        """Test refresh token flow maintains ID token for OIDC requests."""

        # Get initial tokens through OIDC flow
        from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
        from authly.oauth.models import OAuthAuthorizationCodeModel

        auth_code = f"test_code_{uuid4().hex[:8]}"

        async with transaction_manager.transaction() as conn:
            code_repo = AuthorizationCodeRepository(conn)

            code_data = OAuthAuthorizationCodeModel(
                id=uuid4(),
                code=auth_code,
                client_id=test_client_confidential.id,
                user_id=test_user.id,
                scope="openid profile email",
                code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                code_challenge_method="S256",
                redirect_uri=test_client_confidential.redirect_uris[0],
                expires_at=datetime.now(UTC).replace(hour=23, minute=59),
                created_at=datetime.now(UTC),
                nonce="test_nonce",
            )

            await code_repo.create(code_data)

        # Get initial tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_result = await token_response.json()
        refresh_token = token_result["refresh_token"]

        # Use refresh token to get new tokens
        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret",
        }

        refresh_response = await oidc_server.client.post("/api/v1/oauth/token", data=refresh_data)
        await refresh_response.expect_status(200)

        refresh_result = await refresh_response.json()

        # Should include ID token in refresh response for OIDC flows
        assert "access_token" in refresh_result
        assert "id_token" in refresh_result
        assert "refresh_token" in refresh_result

        # Validate new ID token
        new_id_token = refresh_result["id_token"]
        id_token_payload = jwt.decode(new_id_token, key="", options={"verify_signature": False, "verify_aud": False})

        assert id_token_payload["sub"] == str(test_user.id)
        assert id_token_payload["aud"] == test_client_confidential.client_id
        # Note: nonce is not preserved in refresh token flow as per OIDC spec
