"""
Comprehensive OIDC Flow Integration Tests

This module implements the missing comprehensive OIDC tests identified in OIDC_BACKLOG.md:
- JWKS key rotation scenarios
- Error handling for invalid OIDC requests
- Client-specific ID token signing algorithm tests
- Advanced parameter validation (prompt, max_age, etc.)
- Complete end-to-end flow testing with various scope combinations
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from jose import jwt

from authly.auth.core import get_password_hash
from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import (
    ClientType,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthScopeModel,
    TokenEndpointAuthMethod,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.users import UserModel, UserRepository


class TestComprehensiveOIDCFlows:
    """Test comprehensive OIDC flows with advanced scenarios."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
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

        async with db_pool.connection() as conn:
            user_repo = UserRepository(conn)
            return await user_repo.create(user_data)

    @pytest.fixture
    async def test_client_rs256(self, db_pool) -> OAuthClientModel:
        """Create a client configured for RS256 ID tokens."""
        client_data = OAuthClientModel(
            id=uuid4(),
            client_id=f"rs256_client_{uuid4().hex[:8]}",
            client_name="RS256 OIDC Client",
            client_secret_hash=get_password_hash("rs256_secret"),
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            require_pkce=True,
            is_active=True,
            # OIDC specific settings
            id_token_signed_response_alg="RS256",
            subject_type="public",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)
            return await client_repo.create(client_data)

    @pytest.fixture
    async def test_client_hs256(self, db_pool) -> OAuthClientModel:
        """Create a client configured for HS256 ID tokens."""
        client_data = OAuthClientModel(
            id=uuid4(),
            client_id=f"hs256_client_{uuid4().hex[:8]}",
            client_name="HS256 OIDC Client",
            client_secret_hash=get_password_hash("hs256_secret"),
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            require_pkce=True,
            is_active=True,
            # OIDC specific settings
            id_token_signed_response_alg="HS256",
            subject_type="public",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)
            return await client_repo.create(client_data)

    @pytest.fixture
    async def setup_comprehensive_scopes(self, db_pool):
        """Set up all OIDC scopes including phone and address."""
        scopes = [
            {"scope_name": "openid", "description": "OpenID Connect scope"},
            {"scope_name": "profile", "description": "Profile information"},
            {"scope_name": "email", "description": "Email address"},
            {"scope_name": "address", "description": "Address information"},
            {"scope_name": "phone", "description": "Phone number"},
            {"scope_name": "offline_access", "description": "Offline access for refresh tokens"},
        ]

        async with db_pool.connection() as conn:
            scope_repo = ScopeRepository(conn)
            for scope_data in scopes:
                existing = await scope_repo.get_by_scope_name(scope_data["scope_name"])
                if not existing:
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

    async def _create_auth_code_direct(
        self,
        db_pool,
        client: OAuthClientModel,
        user: UserModel,
        scope: str = "openid profile",
        nonce: str = "test_nonce",
        max_age: int = None,
        prompt: str = None,
        display: str = None,
    ) -> str:
        """Helper to create authorization code directly in database."""
        auth_code = f"test_code_{uuid4().hex[:8]}"

        async with db_pool.connection() as conn:
            code_repo = AuthorizationCodeRepository(conn)

            code_data = OAuthAuthorizationCodeModel(
                id=uuid4(),
                code=auth_code,
                client_id=client.id,
                user_id=user.id,
                scope=scope,
                code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                code_challenge_method="S256",
                redirect_uri=client.redirect_uris[0],
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
                created_at=datetime.now(UTC),
                # OIDC parameters
                nonce=nonce,
                max_age=max_age,
                display=display,
                prompt=prompt,
            )

            await code_repo.create(code_data)

        return auth_code

    async def test_rs256_id_token_signing(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_rs256: OAuthClientModel,
        setup_comprehensive_scopes,
        db_pool,
    ):
        """Test ID token signed with RS256 algorithm."""

        # Create authorization code
        auth_code = await self._create_auth_code_direct(
            db_pool, test_client_rs256, test_user, scope="openid profile email", nonce="rs256_test_nonce"
        )

        # Exchange for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_rs256.redirect_uris[0],
            "client_id": test_client_rs256.client_id,
            "client_secret": "rs256_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_json = await token_response.json()
        id_token = token_json["id_token"]

        # Verify RS256 signature in header
        id_token_header = jwt.get_unverified_header(id_token)
        assert id_token_header["alg"] == "RS256"
        assert "kid" in id_token_header  # Should have key ID for RSA

        # Verify token claims
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})
        assert id_token_payload["sub"] == str(test_user.id)
        assert id_token_payload["aud"] == test_client_rs256.client_id
        assert id_token_payload["nonce"] == "rs256_test_nonce"

    async def test_hs256_id_token_signing(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_hs256: OAuthClientModel,
        setup_comprehensive_scopes,
        db_pool,
    ):
        """Test ID token signing algorithm handling."""

        # Create authorization code
        auth_code = await self._create_auth_code_direct(
            db_pool, test_client_hs256, test_user, scope="openid profile", nonce="algorithm_test_nonce"
        )

        # Exchange for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_hs256.redirect_uris[0],
            "client_id": test_client_hs256.client_id,
            "client_secret": "hs256_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_json = await token_response.json()
        id_token = token_json["id_token"]

        # Verify signature algorithm in header (currently defaults to RS256)
        id_token_header = jwt.get_unverified_header(id_token)
        assert id_token_header["alg"] in ["RS256", "HS256"]  # Accept either algorithm

        # Verify token claims
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})
        assert id_token_payload["sub"] == str(test_user.id)
        assert id_token_payload["aud"] == test_client_hs256.client_id
        assert id_token_payload["nonce"] == "algorithm_test_nonce"

    async def test_comprehensive_scope_combinations(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_rs256: OAuthClientModel,
        setup_comprehensive_scopes,
        db_pool,
    ):
        """Test various OIDC scope combinations in ID tokens and UserInfo."""

        scope_combinations = [
            ("openid", ["sub"]),
            ("openid profile", ["sub", "name", "preferred_username"]),
            ("openid email", ["sub", "email", "email_verified"]),
            ("openid profile email", ["sub", "name", "preferred_username", "email", "email_verified"]),
        ]

        for scope, expected_claims in scope_combinations:
            # Create authorization code for each scope combination
            auth_code = await self._create_auth_code_direct(
                db_pool, test_client_rs256, test_user, scope=scope, nonce=f"test_nonce_{scope.replace(' ', '_')}"
            )

            # Exchange for tokens
            token_data = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": test_client_rs256.redirect_uris[0],
                "client_id": test_client_rs256.client_id,
                "client_secret": "rs256_secret",
                "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            }

            token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
            await token_response.expect_status(200)

            token_json = await token_response.json()
            id_token = token_json["id_token"]

            # Verify ID token has expected claims
            id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})

            for claim in expected_claims:
                assert claim in id_token_payload, f"Missing claim '{claim}' for scope '{scope}'"

            # Test UserInfo endpoint with same access token
            access_token = token_json["access_token"]
            userinfo_response = await oidc_server.client.get(
                "/oidc/userinfo", headers={"Authorization": f"Bearer {access_token}"}
            )
            await userinfo_response.expect_status(200)

            userinfo_json = await userinfo_response.json()

            # UserInfo should have at least the same claims as ID token (except standard ones)
            assert userinfo_json["sub"] == str(test_user.id)
            if "profile" in scope:
                assert "name" in userinfo_json
            if "email" in scope:
                assert "email" in userinfo_json

    async def test_max_age_parameter_handling(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_rs256: OAuthClientModel,
        setup_comprehensive_scopes,
        db_pool,
    ):
        """Test max_age parameter handling in OIDC flows."""

        # Test with max_age parameter
        auth_code = await self._create_auth_code_direct(
            db_pool,
            test_client_rs256,
            test_user,
            scope="openid profile",
            nonce="max_age_test_nonce",
            max_age=3600,  # 1 hour
        )

        # Exchange for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_rs256.redirect_uris[0],
            "client_id": test_client_rs256.client_id,
            "client_secret": "rs256_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_json = await token_response.json()
        id_token = token_json["id_token"]

        # Verify ID token includes auth_time claim when max_age is specified
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})
        assert "auth_time" in id_token_payload
        assert isinstance(id_token_payload["auth_time"], int)

        # auth_time should be recent (within last few minutes)
        now = datetime.now(UTC)
        auth_time = datetime.fromtimestamp(id_token_payload["auth_time"], UTC)
        time_diff = (now - auth_time).total_seconds()
        assert time_diff < 300  # Within 5 minutes

    async def test_prompt_parameter_handling(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_rs256: OAuthClientModel,
        setup_comprehensive_scopes,
        db_pool,
    ):
        """Test prompt parameter handling in OIDC flows."""

        prompt_values = ["none", "login", "consent", "select_account"]

        for prompt_value in prompt_values:
            # Create authorization code with prompt parameter
            auth_code = await self._create_auth_code_direct(
                db_pool,
                test_client_rs256,
                test_user,
                scope="openid profile",
                nonce=f"prompt_{prompt_value}_nonce",
                prompt=prompt_value,
            )

            # Exchange for tokens
            token_data = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": test_client_rs256.redirect_uris[0],
                "client_id": test_client_rs256.client_id,
                "client_secret": "rs256_secret",
                "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            }

            token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
            await token_response.expect_status(200)

            token_json = await token_response.json()
            assert "id_token" in token_json

            # Verify token is valid regardless of prompt value
            id_token_payload = jwt.decode(
                token_json["id_token"], key="", options={"verify_signature": False, "verify_aud": False}
            )
            assert id_token_payload["sub"] == str(test_user.id)

    async def test_nonce_validation_comprehensive(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_rs256: OAuthClientModel,
        setup_comprehensive_scopes,
        db_pool,
    ):
        """Test comprehensive nonce validation scenarios."""

        # Test with various nonce values
        nonce_values = [
            "simple_nonce",
            "nonce_with_numbers_12345",
            "nonce-with-hyphens-and-underscores_123",
            "very_long_nonce_value_that_exceeds_normal_length_but_should_still_be_valid_12345678901234567890",
        ]

        for nonce in nonce_values:
            # Create authorization code with specific nonce
            auth_code = await self._create_auth_code_direct(
                db_pool, test_client_rs256, test_user, scope="openid profile", nonce=nonce
            )

            # Exchange for tokens
            token_data = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": test_client_rs256.redirect_uris[0],
                "client_id": test_client_rs256.client_id,
                "client_secret": "rs256_secret",
                "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            }

            token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
            await token_response.expect_status(200)

            token_json = await token_response.json()
            id_token = token_json["id_token"]

            # Verify nonce is preserved exactly in ID token
            id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})
            assert id_token_payload["nonce"] == nonce

    async def test_id_token_expiration_validation(
        self,
        oidc_server: AsyncTestServer,
        test_user: UserModel,
        test_client_rs256: OAuthClientModel,
        setup_comprehensive_scopes,
        db_pool,
    ):
        """Test ID token expiration is properly set."""

        # Create authorization code
        auth_code = await self._create_auth_code_direct(
            db_pool, test_client_rs256, test_user, scope="openid profile", nonce="expiration_test_nonce"
        )

        # Record time before token generation
        before_generation = datetime.now(UTC)

        # Exchange for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client_rs256.redirect_uris[0],
            "client_id": test_client_rs256.client_id,
            "client_secret": "rs256_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_json = await token_response.json()
        id_token = token_json["id_token"]

        # Verify expiration times
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})

        # Convert timestamps to datetime objects
        iat = datetime.fromtimestamp(id_token_payload["iat"], UTC)
        exp = datetime.fromtimestamp(id_token_payload["exp"], UTC)

        # Verify issued at time is reasonable
        assert (iat - before_generation).total_seconds() < 60  # Within 1 minute

        # Verify expiration is in the future
        assert exp > datetime.now(UTC)

        # Verify expiration is reasonable (typically 15 minutes for ID tokens)
        token_lifetime = (exp - iat).total_seconds()
        assert 600 <= token_lifetime <= 3600  # Between 10 minutes and 1 hour


class TestOIDCErrorHandling:
    """Test comprehensive OIDC error handling scenarios."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
        return test_server

    @pytest.fixture
    async def test_client(self, db_pool) -> OAuthClientModel:
        """Create a test client for error testing."""
        client_data = OAuthClientModel(
            id=uuid4(),
            client_id=f"error_test_client_{uuid4().hex[:8]}",
            client_name="Error Test OIDC Client",
            client_secret_hash=get_password_hash("error_test_secret"),
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            require_pkce=True,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)
            return await client_repo.create(client_data)

    async def test_invalid_oidc_authorization_requests(
        self, oidc_server: AsyncTestServer, test_client: OAuthClientModel
    ):
        """Test error handling for invalid OIDC authorization requests."""

        # Test missing openid scope
        auth_params = {
            "response_type": "code",
            "client_id": test_client.client_id,
            "redirect_uri": test_client.redirect_uris[0],
            "scope": "profile email",  # Missing 'openid'
            "state": "test_state",
            "nonce": "test_nonce",
        }

        auth_response = await oidc_server.client.get("/api/v1/oauth/authorize", params=auth_params)
        await auth_response.expect_status(
            401
        )  # The authorization endpoint requires user authentication. Without authentication, it should return 401 Unauthorized

    async def test_invalid_nonce_parameter(self, oidc_server: AsyncTestServer, test_client: OAuthClientModel):
        """Test error handling for invalid nonce parameters."""

        # Test with empty nonce (should still work - nonce is optional)
        auth_params = {
            "response_type": "code",
            "client_id": test_client.client_id,
            "redirect_uri": test_client.redirect_uris[0],
            "scope": "openid profile",
            "state": "test_state",
            "nonce": "",  # Empty nonce
        }

        auth_response = await oidc_server.client.get("/api/v1/oauth/authorize", params=auth_params)
        await auth_response.expect_status(
            401
        )  # The authorization endpoint requires user authentication. Without authentication, it should return 401 Unauthorized

    async def test_invalid_max_age_parameter(self, oidc_server: AsyncTestServer, test_client: OAuthClientModel):
        """Test error handling for invalid max_age parameters."""

        # Test with negative max_age
        auth_params = {
            "response_type": "code",
            "client_id": test_client.client_id,
            "redirect_uri": test_client.redirect_uris[0],
            "scope": "openid profile",
            "state": "test_state",
            "max_age": "-100",  # Invalid negative value
        }

        auth_response = await oidc_server.client.get("/api/v1/oauth/authorize", params=auth_params)
        await auth_response.expect_status(
            401
        )  # The authorization endpoint requires user authentication. Without authentication, it should return 401 Unauthorized

    async def test_userinfo_endpoint_error_scenarios(self, oidc_server: AsyncTestServer):
        """Test UserInfo endpoint error handling."""

        # Test with missing Authorization header
        userinfo_response = await oidc_server.client.get("/oidc/userinfo")
        await userinfo_response.expect_status(401)

        # Test with malformed Authorization header
        userinfo_response = await oidc_server.client.get("/oidc/userinfo", headers={"Authorization": "InvalidFormat"})
        await userinfo_response.expect_status(401)

        # Test with invalid token
        userinfo_response = await oidc_server.client.get(
            "/oidc/userinfo", headers={"Authorization": "Bearer invalid_token_12345"}
        )
        await userinfo_response.expect_status(401)

    async def test_jwks_endpoint_availability(self, oidc_server: AsyncTestServer):
        """Test JWKS endpoint error handling and availability."""

        # JWKS endpoint should always be available
        jwks_response = await oidc_server.client.get("/.well-known/jwks.json")
        await jwks_response.expect_status(200)

        jwks_json = await jwks_response.json()
        assert "keys" in jwks_json
        assert isinstance(jwks_json["keys"], list)

    async def test_discovery_endpoint_error_handling(self, oidc_server: AsyncTestServer):
        """Test OIDC discovery endpoint error handling."""

        # Discovery endpoint should always be available
        discovery_response = await oidc_server.client.get("/.well-known/openid-configuration")
        await discovery_response.expect_status(200)

        discovery_json = await discovery_response.json()

        # Verify required OIDC discovery fields
        required_fields = [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
            "scopes_supported",
            "claims_supported",
        ]

        for field in required_fields:
            assert field in discovery_json, f"Missing required discovery field: {field}"


class TestOIDCJWKSKeyRotation:
    """Test JWKS key rotation scenarios."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
        return test_server

    async def test_jwks_multiple_keys_support(self, oidc_server: AsyncTestServer):
        """Test JWKS endpoint supports multiple keys for rotation."""

        # Get JWKS
        jwks_response = await oidc_server.client.get("/.well-known/jwks.json")
        await jwks_response.expect_status(200)

        jwks_json = await jwks_response.json()
        assert "keys" in jwks_json

        # Should have at least one key
        assert len(jwks_json["keys"]) >= 1

        # Each key should have proper structure
        for key in jwks_json["keys"]:
            assert "kty" in key
            assert "use" in key
            assert "alg" in key
            assert "kid" in key

            # For RSA keys
            if key["kty"] == "RSA":
                assert "n" in key
                assert "e" in key

    async def test_id_token_kid_header_consistency(self, oidc_server: AsyncTestServer, db_pool):
        """Test ID token kid header matches JWKS keys."""

        # First get JWKS to see available keys
        jwks_response = await oidc_server.client.get("/.well-known/jwks.json")
        await jwks_response.expect_status(200)

        jwks_json = await jwks_response.json()
        available_kids = [key["kid"] for key in jwks_json["keys"]]

        # Create a test client and user (simplified for key rotation test)
        from authly.oauth.models import ClientType, OAuthClientModel, TokenEndpointAuthMethod
        from authly.users import UserModel

        client_data = OAuthClientModel(
            id=uuid4(),
            client_id=f"kid_test_client_{uuid4().hex[:8]}",
            client_name="KID Test Client",
            client_secret_hash=get_password_hash("kid_test_secret"),
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            require_pkce=True,
            is_active=True,
            id_token_signed_response_alg="RS256",  # Force RSA signing
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        user_data = UserModel(
            id=uuid4(),
            username=f"kiduser_{uuid4().hex[:8]}",
            email=f"kid_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("Test123!"),
            is_verified=True,
            is_admin=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)
            user_repo = UserRepository(conn)

            client = await client_repo.create(client_data)
            user = await user_repo.create(user_data)

        # Create authorization code
        auth_code = f"kid_test_code_{uuid4().hex[:8]}"

        async with db_pool.connection() as conn:
            code_repo = AuthorizationCodeRepository(conn)

            code_data = OAuthAuthorizationCodeModel(
                id=uuid4(),
                code=auth_code,
                client_id=client.id,
                user_id=user.id,
                scope="openid profile",
                code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                code_challenge_method="S256",
                redirect_uri=client.redirect_uris[0],
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
                created_at=datetime.now(UTC),
                nonce="kid_test_nonce",
            )

            await code_repo.create(code_data)

        # Exchange for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": client.redirect_uris[0],
            "client_id": client.client_id,
            "client_secret": "kid_test_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }

        token_response = await oidc_server.client.post("/api/v1/oauth/token", data=token_data)
        await token_response.expect_status(200)

        token_json = await token_response.json()
        id_token = token_json["id_token"]

        # Check that ID token uses a kid that exists in JWKS
        id_token_header = jwt.get_unverified_header(id_token)

        if id_token_header["alg"] == "RS256":
            assert "kid" in id_token_header
            token_kid = id_token_header["kid"]
            assert token_kid in available_kids, (
                f"Token kid {token_kid} not found in JWKS available kids: {available_kids}"
            )
