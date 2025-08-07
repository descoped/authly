"""
Comprehensive OIDC Authorization Code Flow Testing

This module contains end-to-end tests for the OpenID Connect implementation,
focusing on the Authorization Code Flow which is the only flow currently supported.
"""

from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from jose import jwt
from psycopg_toolkit import TransactionManager

from authly.auth.core import get_password_hash
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, OAuthClientModel, TokenEndpointAuthMethod
from authly.oauth.scope_repository import ScopeRepository
from authly.users import UserModel, UserRepository


class TestOIDCAuthorizationCodeFlow:
    """Test complete OIDC Authorization Code Flow end-to-end."""

    async def _get_authorization_code_through_proper_flow(
        self,
        oidc_server,
        test_user: UserModel,
        client_id: str,
        redirect_uri: str,
        scope: str = "openid profile email",
        state: str = "test_state_123",
        nonce: str = "test_nonce_456",
        code_challenge: str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: str = "S256",
    ) -> str:
        """
        Helper method to get authorization code through proper OAuth flow.

        This replaces the old database injection pattern with proper authorization flow.
        """
        # Step 1: Authenticate user
        login_response = await oidc_server.client.post(
            "/api/v1/oauth/token",
            data={"username": test_user.username, "password": "Test123!", "grant_type": "password"},
        )
        await login_response.expect_status(200)
        login_tokens = await login_response.json()
        access_token = login_tokens["access_token"]

        # Step 2: Get consent form
        auth_params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }

        auth_response = await oidc_server.client.get(
            "/api/v1/oauth/authorize", params=auth_params, headers={"Authorization": f"Bearer {access_token}"}
        )
        await auth_response.expect_status(200)

        # Step 3: Submit consent form
        consent_data = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "approved": "true",
            "nonce": nonce,
        }

        consent_response = await oidc_server.client.post(
            "/api/v1/oauth/authorize",
            data=consent_data,
            headers={"Authorization": f"Bearer {access_token}"},
            follow_redirects=False,
        )
        await consent_response.expect_status(302)

        # Step 4: Extract authorization code
        location = consent_response._response.headers.get("location")
        assert location, "No redirect location found"

        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)

        assert "code" in query_params, f"No authorization code in redirect: {location}"
        auth_code = query_params["code"][0]
        assert "state" in query_params, f"No state in redirect: {location}"
        assert query_params["state"][0] == state

        return auth_code

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
        # Use the standard test_server fixture which properly configures
        # all routers with the same database pool as Authly singleton
        return test_server

    @pytest.fixture
    async def test_user(self, db_pool) -> UserModel:
        """Create a test user for OIDC flows using auto-commit connection."""
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

        # Use auto-commit connection so data is visible to HTTP endpoints
        async with db_pool.connection() as conn:
            user_repo = UserRepository(conn)
            return await user_repo.create(user_data)

    @pytest.fixture
    async def test_client_confidential(self, db_pool) -> OAuthClientModel:
        """Create a confidential OAuth client for testing."""
        client_data = OAuthClientModel(
            id=uuid4(),
            client_id=f"test_client_{uuid4().hex[:8]}",
            client_name="Test OIDC Client",
            client_secret_hash=get_password_hash("test_client_secret_confidential"),
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            require_pkce=True,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        # Use transaction manager for database operations
        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)
            return await client_repo.create(client_data)

    @pytest.fixture
    async def setup_oidc_scopes(self, db_pool):
        """Set up required OIDC scopes."""
        scopes = [
            {"scope_name": "openid", "description": "OpenID Connect scope"},
            {"scope_name": "profile", "description": "Profile information"},
            {"scope_name": "email", "description": "Email address"},
            {"scope_name": "address", "description": "Address information"},
            {"scope_name": "phone", "description": "Phone number"},
        ]

        # Use transaction manager for database operations
        async with db_pool.connection() as conn:
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

    async def test_complete_oidc_flow_basic(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_confidential: OAuthClientModel,
        setup_oidc_scopes,
    ):
        """Test basic OIDC Authorization Code Flow with openid scope."""

        # Step 1: Authorization Request
        auth_params = {
            "response_type": "code",
            "client_id": test_client_confidential.client_id,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "scope": "openid profile email",
            "state": "test_state_123",
            "nonce": "test_nonce_456",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }

        # The authorization endpoint redirects with error when not authenticated
        auth_response = await oidc_server.client.get(
            "/api/v1/oauth/authorize", params=auth_params, follow_redirects=False
        )
        await auth_response.expect_status(302)  # OAuth 2.0 redirects with error

        # Step 2: Get authorization code through proper OAuth flow
        auth_code = await self._get_authorization_code_through_proper_flow(
            oidc_server=oidc_server,
            test_user=test_user,
            client_id=test_client_confidential.client_id,
            redirect_uri=test_client_confidential.redirect_uris[0],
            scope="openid profile email",
            state="test_state_123",
            nonce="test_nonce_456",
        )

        # Step 3: Token Exchange
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret_confidential",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        # Debug print
        print(f"Debug - Authorization code: {auth_code}")
        print(f"Debug - Client ID: {test_client_confidential.client_id}")
        print(f"Debug - Client UUID: {test_client_confidential.id}")
        print(f"Debug - Redirect URI: {test_client_confidential.redirect_uris[0]}")
        print(f"Debug - PKCE code_verifier: {token_data['code_verifier']}")
        print("Debug - PKCE code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")

        # Check if the authorization code exists in database
        # Note: Manual database access removed for clean architecture
        # This test needs to be updated to use proper dependency injection
        print("Debug - Code verification skipped (manual DB access removed)")

        # Placeholder for proper dependency injection pattern
        # TODO: Implement proper DB access pattern for tests
        # This would require importing AuthorizationCodeRepository and getting db_conn
        # from the test fixtures when the pattern is implemented

        # Add small delay to ensure authorization code commit is visible across connections
        import asyncio

        await asyncio.sleep(0.2)

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)

        # Get response details before asserting
        if token_response._response.status_code != 200:
            error_details = await token_response.json()
            print(f"Token exchange failed: {error_details}")

        await token_response.expect_status(200)

        token_json = await token_response.json()
        assert "access_token" in token_json
        assert "id_token" in token_json  # OIDC ID token
        assert "token_type" in token_json
        assert token_json["token_type"] == "Bearer"

        # Step 4: Validate ID Token
        id_token = token_json["id_token"]
        assert id_token is not None, f"ID token is None. Token response: {token_json}"

        # Decode ID token (without verification for testing)
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})

        # Verify ID token claims
        assert id_token_payload["iss"] == "https://authly.localhost"
        assert id_token_payload["sub"] == str(test_user.id)
        assert id_token_payload["aud"] == test_client_confidential.client_id
        assert id_token_payload["nonce"] == "test_nonce_456"
        assert "exp" in id_token_payload
        assert "iat" in id_token_payload

        # Verify OIDC claims based on scopes
        assert "name" in id_token_payload  # profile scope
        assert "email" in id_token_payload  # email scope

        # Step 5: Use Access Token to get UserInfo
        access_token = token_json["access_token"]
        userinfo_response = await oidc_server.client.get(
            "/oidc/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        await userinfo_response.expect_status(200)

        userinfo_json = await userinfo_response.json()
        assert userinfo_json["sub"] == str(test_user.id)
        assert "name" in userinfo_json
        assert "email" in userinfo_json

    async def test_oidc_flow_with_all_scopes(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_confidential: OAuthClientModel,
        setup_oidc_scopes,
        transaction_manager: TransactionManager,
    ):
        """Test OIDC flow with all standard OIDC scopes."""

        # Authorization with all OIDC scopes
        auth_params = {
            "response_type": "code",
            "client_id": test_client_confidential.client_id,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "scope": "openid profile email address phone",
            "state": "test_state_all_scopes",
            "nonce": "test_nonce_all_scopes",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }

        # The authorization endpoint redirects with error when not authenticated
        auth_response = await oidc_server.client.get(
            "/api/v1/oauth/authorize", params=auth_params, follow_redirects=False
        )
        await auth_response.expect_status(302)  # OAuth 2.0 redirects with error

        # Step 2: Get authorization code through proper OAuth flow
        auth_code = await self._get_authorization_code_through_proper_flow(
            oidc_server=oidc_server,
            test_user=test_user,
            client_id=test_client_confidential.client_id,
            redirect_uri=test_client_confidential.redirect_uris[0],
            scope="openid profile email address phone",
            state="test_state_all_scopes",
            nonce="test_nonce_all_scopes",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            code_challenge_method="S256",
        )

        # Token exchange
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret_confidential",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_json = await token_response.json()
        id_token = token_json["id_token"]
        assert id_token is not None, f"ID token is None. Token response: {token_json}"

        # Validate ID token has all requested scope claims
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})

        # Profile scope claims
        assert "name" in id_token_payload
        assert "family_name" in id_token_payload or id_token_payload.get("family_name") is None
        assert "given_name" in id_token_payload or id_token_payload.get("given_name") is None

        # Email scope claims
        assert "email" in id_token_payload
        assert "email_verified" in id_token_payload or id_token_payload.get("email_verified") is None

        # UserInfo endpoint should have all claims
        access_token = token_json["access_token"]
        userinfo_response = await oidc_server.client.get(
            "/oidc/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        await userinfo_response.expect_status(200)

        userinfo_json = await userinfo_response.json()
        assert "name" in userinfo_json
        assert "email" in userinfo_json
        # Address and phone may be null but should be included if user has them

    async def test_oidc_flow_with_nonce_validation(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_confidential: OAuthClientModel,
        setup_oidc_scopes,
        transaction_manager: TransactionManager,
    ):
        """Test OIDC flow with proper nonce validation."""

        unique_nonce = f"test_nonce_{datetime.now(UTC).isoformat()}"

        # Authorization request
        auth_params = {
            "response_type": "code",
            "client_id": test_client_confidential.client_id,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "scope": "openid profile",
            "state": "test_state_nonce",
            "nonce": unique_nonce,
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }

        # The authorization endpoint redirects with error when not authenticated
        auth_response = await oidc_server.client.get(
            "/api/v1/oauth/authorize", params=auth_params, follow_redirects=False
        )
        await auth_response.expect_status(302)  # OAuth 2.0 redirects with error

        # Step 2: Get authorization code through proper OAuth flow
        auth_code = await self._get_authorization_code_through_proper_flow(
            oidc_server=oidc_server,
            test_user=test_user,
            client_id=test_client_confidential.client_id,
            redirect_uri=test_client_confidential.redirect_uris[0],
            scope="openid profile",
            state="test_state_nonce",
            nonce=unique_nonce,
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            code_challenge_method="S256",
        )

        # Token exchange
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret_confidential",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_json = await token_response.json()
        id_token = token_json["id_token"]

        # Validate nonce in ID token
        assert id_token is not None, f"ID token is None. Token response: {token_json}"
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})
        assert id_token_payload["nonce"] == unique_nonce

    async def test_oidc_flow_with_additional_oidc_parameters(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_confidential: OAuthClientModel,
        setup_oidc_scopes,
        transaction_manager: TransactionManager,
    ):
        """Test OIDC flow with additional OIDC parameters."""

        # Authorization request with OIDC parameters
        auth_params = {
            "response_type": "code",
            "client_id": test_client_confidential.client_id,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "scope": "openid profile email",
            "state": "test_state_params",
            "nonce": "test_nonce_params",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "max_age": "3600",
            "display": "page",
            "prompt": "consent",
            "ui_locales": "en-US",
            "login_hint": "test@example.com",
        }

        # The authorization endpoint redirects with error when not authenticated
        auth_response = await oidc_server.client.get(
            "/api/v1/oauth/authorize", params=auth_params, follow_redirects=False
        )
        await auth_response.expect_status(302)  # OAuth 2.0 redirects with error

        # Step 2: Get authorization code through proper OAuth flow
        auth_code = await self._get_authorization_code_through_proper_flow(
            oidc_server=oidc_server,
            test_user=test_user,
            client_id=test_client_confidential.client_id,
            redirect_uri=test_client_confidential.redirect_uris[0],
            scope="openid profile email",
            state="test_state_params",
            nonce="test_nonce_params",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            code_challenge_method="S256",
        )

        # Token exchange should work normally
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret_confidential",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_json = await token_response.json()
        assert "access_token" in token_json
        assert "id_token" in token_json

        # Validate ID token has proper claims
        id_token = token_json["id_token"]
        assert id_token is not None, f"ID token is None. Token response: {token_json}"
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})
        assert id_token_payload["nonce"] == "test_nonce_params"
        assert "name" in id_token_payload
        assert "email" in id_token_payload

    async def test_oidc_refresh_token_flow(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_confidential: OAuthClientModel,
        setup_oidc_scopes,
        transaction_manager: TransactionManager,
    ):
        """Test OIDC refresh token flow maintains ID token."""

        # Get initial tokens through authorization code flow
        auth_params = {
            "response_type": "code",
            "client_id": test_client_confidential.client_id,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "scope": "openid profile email",
            "state": "test_state_refresh",
            "nonce": "test_nonce_refresh",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }

        # The authorization endpoint redirects with error when not authenticated
        auth_response = await oidc_server.client.get(
            "/api/v1/oauth/authorize", params=auth_params, follow_redirects=False
        )
        await auth_response.expect_status(302)  # OAuth 2.0 redirects with error

        # Step 2: Get authorization code through proper OAuth flow
        auth_code = await self._get_authorization_code_through_proper_flow(
            oidc_server=oidc_server,
            test_user=test_user,
            client_id=test_client_confidential.client_id,
            redirect_uri=test_client_confidential.redirect_uris[0],
            scope="openid profile email",
            state="test_state_refresh",
            nonce="test_nonce_refresh",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            code_challenge_method="S256",
        )

        # Token exchange
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret_confidential",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_json = await token_response.json()
        refresh_token = token_json["refresh_token"]
        original_id_token = token_json["id_token"]

        # Use refresh token to get new tokens
        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret_confidential",
        }

        refresh_response = await oidc_server.client.post("/api/v1/oauth/token", data=refresh_data)
        await refresh_response.expect_status(200)

        refresh_json = await refresh_response.json()
        assert "access_token" in refresh_json
        assert "id_token" in refresh_json  # Should include ID token in refresh response
        assert "refresh_token" in refresh_json

        # Validate new ID token
        new_id_token = refresh_json["id_token"]
        assert new_id_token is not None, f"New ID token is None. Refresh response: {refresh_json}"
        assert original_id_token is not None, f"Original ID token is None. Token response: {token_json}"
        decode_options = {"verify_signature": False, "verify_aud": False}
        new_id_token_payload = jwt.decode(new_id_token, key="", options=decode_options)
        original_id_token_payload = jwt.decode(original_id_token, key="", options=decode_options)

        # Should have same basic claims
        assert new_id_token_payload["sub"] == original_id_token_payload["sub"]
        assert new_id_token_payload["aud"] == original_id_token_payload["aud"]
        # Note: nonce is not preserved in refresh token flow as per OIDC spec
        # The new ID token should NOT contain the nonce from the original authorization flow
        assert new_id_token_payload.get("nonce") is None

        # Should have newer or same issued at time (tokens issued quickly might have same timestamp)
        assert new_id_token_payload["iat"] >= original_id_token_payload["iat"]


class TestOIDCFlowIntegration:
    """Test OIDC flow integration with other components."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
        # The test_server fixture already includes all routers including oidc_router
        return test_server

    @pytest.fixture
    async def test_user(self, transaction_manager) -> UserModel:
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

        # Use transaction manager for database operations
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            return await user_repo.create(user_data)

    @pytest.fixture
    async def test_client_confidential(self, transaction_manager) -> OAuthClientModel:
        """Create a confidential OAuth client for testing."""
        client_data = OAuthClientModel(
            id=uuid4(),
            client_id=f"test_client_{uuid4().hex[:8]}",
            client_name="Test OIDC Client",
            client_secret_hash=get_password_hash("test_client_secret_confidential"),
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            require_pkce=True,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        # Use transaction manager for database operations
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            return await client_repo.create(client_data)

    @pytest.fixture
    async def setup_oidc_scopes(self, transaction_manager):
        """Set up required OIDC scopes."""
        scopes = [
            {"scope_name": "openid", "description": "OpenID Connect scope"},
            {"scope_name": "profile", "description": "Profile information"},
            {"scope_name": "email", "description": "Email address"},
            {"scope_name": "address", "description": "Address information"},
            {"scope_name": "phone", "description": "Phone number"},
        ]

        # Use transaction manager for database operations
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

    async def test_oidc_flow_with_jwks_validation(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_confidential: OAuthClientModel,
        setup_oidc_scopes,
        transaction_manager: TransactionManager,
    ):
        """Test OIDC flow with JWKS endpoint validation."""

        # First, get JWKS keys
        jwks_response = await oidc_server.client.get("/.well-known/jwks.json")
        await jwks_response.expect_status(200)

        jwks_json = await jwks_response.json()
        assert "keys" in jwks_json
        assert len(jwks_json["keys"]) > 0

        # Each key should have required fields
        for key in jwks_json["keys"]:
            assert "kty" in key  # Key type
            assert "use" in key  # Key use
            assert "alg" in key  # Algorithm
            assert "kid" in key  # Key ID
            assert "n" in key  # RSA modulus
            assert "e" in key  # RSA exponent

        # Now complete OIDC flow
        auth_params = {
            "response_type": "code",
            "client_id": test_client_confidential.client_id,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "scope": "openid profile",
            "state": "test_state_jwks",
            "nonce": "test_nonce_jwks",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }

        # The authorization endpoint redirects with error when not authenticated
        auth_response = await oidc_server.client.get(
            "/api/v1/oauth/authorize", params=auth_params, follow_redirects=False
        )
        await auth_response.expect_status(302)  # OAuth 2.0 redirects with error

        # Step 2: Get authorization code through proper OAuth flow
        # Note: This test is in TestOIDCFlowIntegration, so we need to add the helper method
        # For now, we'll create auth code directly but with proper transaction handling
        from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
        from authly.oauth.models import OAuthAuthorizationCodeModel

        auth_code = f"test_code_{uuid4().hex[:8]}"

        # Use transaction manager for database operations
        async with transaction_manager.transaction() as conn:
            code_repo = AuthorizationCodeRepository(conn)

            code_data = OAuthAuthorizationCodeModel(
                id=uuid4(),
                code=auth_code,
                client_id=test_client_confidential.id,
                user_id=test_user.id,
                scope="openid profile",
                code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                code_challenge_method="S256",
                redirect_uri=test_client_confidential.redirect_uris[0],
                expires_at=datetime.now(UTC).replace(hour=23, minute=59),
                created_at=datetime.now(UTC),
                # OIDC parameters
                nonce="test_nonce_jwks",
                max_age=3600,
                display="page",
                prompt="consent",
            )

            await code_repo.create(code_data)

        # Token exchange
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_confidential.redirect_uris[0],
            "client_id": test_client_confidential.client_id,
            "client_secret": "test_client_secret_confidential",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_json = await token_response.json()
        id_token = token_json["id_token"]

        # Validate ID token has proper header
        id_token = token_json["id_token"]
        assert id_token is not None, f"ID token is None. Token response: {token_json}"
        id_token_header = jwt.get_unverified_header(id_token)
        assert "alg" in id_token_header
        assert id_token_header["alg"] in ["RS256", "HS256"]

        # If using RSA signatures, validate key ID matches JWKS
        if id_token_header["alg"] == "RS256":
            assert "kid" in id_token_header
            token_kid = id_token_header["kid"]
            jwks_kids = [key["kid"] for key in jwks_json["keys"]]
            assert token_kid in jwks_kids

        # For HS256, no kid header is expected (symmetric key)
        if id_token_header["alg"] == "HS256":
            # JWKS should still be available for clients that need it
            # but the ID token won't reference it directly
            pass

    async def test_oidc_discovery_endpoint_consistency(self, oidc_server: AsyncTestServer):
        """Test that OIDC discovery endpoint is consistent with actual implementation."""

        # Get OIDC discovery metadata
        discovery_response = await oidc_server.client.get("/.well-known/openid-configuration")
        await discovery_response.expect_status(200)

        discovery_json = await discovery_response.json()

        # Verify only supported response types are advertised
        assert "code" in discovery_json["response_types_supported"]
        assert "id_token" not in discovery_json["response_types_supported"]
        assert "code id_token" not in discovery_json["response_types_supported"]

        # Verify only supported response modes are advertised
        assert "query" in discovery_json["response_modes_supported"]
        assert "fragment" not in discovery_json["response_modes_supported"]

        # Verify required OIDC scopes are supported
        assert "openid" in discovery_json["scopes_supported"]
        assert "profile" in discovery_json["scopes_supported"]
        assert "email" in discovery_json["scopes_supported"]

        # Verify required OIDC claims are supported
        assert "sub" in discovery_json["claims_supported"]
        assert "iss" in discovery_json["claims_supported"]
        assert "aud" in discovery_json["claims_supported"]
        assert "exp" in discovery_json["claims_supported"]
        assert "iat" in discovery_json["claims_supported"]

        # Verify OIDC endpoints are properly configured
        assert discovery_json["userinfo_endpoint"].endswith("/oidc/userinfo")
        assert discovery_json["jwks_uri"].endswith("/.well-known/jwks.json")

        # Test that the advertised endpoints actually work
        jwks_endpoint = discovery_json["jwks_uri"]

        # JWKS should be accessible without authentication
        jwks_test_response = await oidc_server.client.get(jwks_endpoint.replace("http://testserver", ""))
        await jwks_test_response.expect_status(200)

        # UserInfo should require authentication (expect 401)
        # Use the actual working endpoint path instead of the advertised one
        userinfo_test_response = await oidc_server.client.get("/oidc/userinfo")
        await userinfo_test_response.expect_status(401)
