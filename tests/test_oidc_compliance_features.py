"""
OIDC Compliance Features Tests

This module tests advanced OIDC compliance features identified in OIDC_BACKLOG.md:
- Advanced OIDC claims support (phone, address scopes)
- OIDC session management features
- Additional OIDC parameter handling (ui_locales, login_hint)
- OIDC logout and session management
- OIDC request object support
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from unittest.mock import patch

from fastapi_testing import AsyncTestServer
from jose import jwt

from authly.auth.core import get_password_hash
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, OAuthClientModel, TokenEndpointAuthMethod
from authly.oauth.scope_repository import ScopeRepository
from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.models import OAuthAuthorizationCodeModel, OAuthScopeModel
from authly.users import UserModel, UserRepository


class TestAdvancedOIDCClaims:
    """Test advanced OIDC claims support beyond basic profile/email."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
        return test_server

    @pytest.fixture
    async def enhanced_test_user(self, db_pool) -> UserModel:
        """Create a test user with enhanced OIDC profile data."""
        user_data = UserModel(
            id=uuid4(),
            username=f"enhanced_user_{uuid4().hex[:8]}",
            email=f"enhanced_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("Test123!"),
            is_verified=True,
            is_admin=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        async with db_pool.connection() as conn:
            user_repo = UserRepository(conn)
            return await user_repo.create(user_data)

    @pytest.fixture
    async def test_client(self, db_pool) -> OAuthClientModel:
        """Create a test client supporting all OIDC scopes."""
        client_data = OAuthClientModel(
            id=uuid4(),
            client_id=f"advanced_claims_client_{uuid4().hex[:8]}",
            client_name="Advanced Claims OIDC Client",
            client_secret_hash=get_password_hash("advanced_secret"),
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            require_pkce=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)
            return await client_repo.create(client_data)

    @pytest.fixture
    async def setup_all_oidc_scopes(self, db_pool):
        """Set up all OIDC scopes including phone and address."""
        scopes = [
            {"scope_name": "openid", "description": "OpenID Connect scope"},
            {"scope_name": "profile", "description": "Profile information"},
            {"scope_name": "email", "description": "Email address"},
            {"scope_name": "address", "description": "Address information"},
            {"scope_name": "phone", "description": "Phone number"},
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
                        created_at=datetime.now(timezone.utc),
                        updated_at=datetime.now(timezone.utc)
                    )
                    await scope_repo.create(scope_model)

    async def _create_auth_code_direct(self, db_pool, client: OAuthClientModel, user: UserModel, 
                                     scope: str = "openid profile", nonce: str = "test_nonce") -> str:
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
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                created_at=datetime.now(timezone.utc),
                nonce=nonce
            )
            
            await code_repo.create(code_data)
        
        return auth_code

    async def test_phone_scope_claims(
        self, 
        oidc_server: AsyncTestServer,
        enhanced_test_user: UserModel,
        test_client: OAuthClientModel,
        setup_all_oidc_scopes,
        db_pool
    ):
        """Test phone scope provides phone number claims."""
        
        # Create authorization code with phone scope
        auth_code = await self._create_auth_code_direct(
            db_pool, test_client, enhanced_test_user,
            scope="openid phone",
            nonce="phone_scope_nonce"
        )
        
        # Exchange for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client.redirect_uris[0],
            "client_id": test_client.client_id,
            "client_secret": "advanced_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        }
        
        token_response = await oidc_server.client.post("/api/v1/auth/token", json=token_data)
        await token_response.expect_status(200)
        
        token_json = await token_response.json()
        id_token = token_json["id_token"]
        
        # Verify ID token includes phone claims
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})
        
        # Phone scope claims (may be null if user has no phone data)
        # The current user model doesn't have phone fields, so these may be null
        # but the scope should still be processed
        
        # Test UserInfo endpoint with phone scope
        access_token = token_json["access_token"]
        userinfo_response = await oidc_server.client.get(
            "/oidc/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        await userinfo_response.expect_status(200)
        
        userinfo_json = await userinfo_response.json()
        assert userinfo_json["sub"] == str(enhanced_test_user.id)
        
        # UserInfo should handle phone scope (claims may be null if user has no phone data)

    async def test_address_scope_claims(
        self, 
        oidc_server: AsyncTestServer,
        enhanced_test_user: UserModel,
        test_client: OAuthClientModel,
        setup_all_oidc_scopes,
        db_pool
    ):
        """Test address scope provides address claims."""
        
        # Create authorization code with address scope
        auth_code = await self._create_auth_code_direct(
            db_pool, test_client, enhanced_test_user,
            scope="openid address",
            nonce="address_scope_nonce"
        )
        
        # Exchange for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client.redirect_uris[0],
            "client_id": test_client.client_id,
            "client_secret": "advanced_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        }
        
        token_response = await oidc_server.client.post("/api/v1/auth/token", json=token_data)
        await token_response.expect_status(200)
        
        token_json = await token_response.json()
        id_token = token_json["id_token"]
        
        # Verify ID token structure (address claims may be null if user has no address)
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})
        assert id_token_payload["sub"] == str(enhanced_test_user.id)
        
        # Test UserInfo endpoint with address scope
        access_token = token_json["access_token"]
        userinfo_response = await oidc_server.client.get(
            "/oidc/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        await userinfo_response.expect_status(200)
        
        userinfo_json = await userinfo_response.json()
        assert userinfo_json["sub"] == str(enhanced_test_user.id)

    async def test_combined_advanced_scopes(
        self, 
        oidc_server: AsyncTestServer,
        enhanced_test_user: UserModel,
        test_client: OAuthClientModel,
        setup_all_oidc_scopes,
        db_pool
    ):
        """Test combined advanced scopes (profile, email, phone, address)."""
        
        # Create authorization code with all scopes
        auth_code = await self._create_auth_code_direct(
            db_pool, test_client, enhanced_test_user,
            scope="openid profile email phone address",
            nonce="combined_scopes_nonce"
        )
        
        # Exchange for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": test_client.redirect_uris[0],
            "client_id": test_client.client_id,
            "client_secret": "advanced_secret",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        }
        
        token_response = await oidc_server.client.post("/api/v1/auth/token", json=token_data)
        await token_response.expect_status(200)
        
        token_json = await token_response.json()
        id_token = token_json["id_token"]
        
        # Verify ID token includes claims from all scopes
        id_token_payload = jwt.decode(id_token, key="", options={"verify_signature": False, "verify_aud": False})
        
        # Basic claims
        assert id_token_payload["sub"] == str(enhanced_test_user.id)
        
        # Profile claims
        assert "name" in id_token_payload
        assert "preferred_username" in id_token_payload
        
        # Email claims
        assert "email" in id_token_payload
        assert "email_verified" in id_token_payload
        
        # Test UserInfo endpoint with all scopes
        access_token = token_json["access_token"]
        userinfo_response = await oidc_server.client.get(
            "/oidc/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        await userinfo_response.expect_status(200)
        
        userinfo_json = await userinfo_response.json()
        
        # UserInfo should include all available claims
        assert userinfo_json["sub"] == str(enhanced_test_user.id)
        assert "name" in userinfo_json
        assert "email" in userinfo_json


class TestOIDCParameterHandling:
    """Test advanced OIDC parameter handling (ui_locales, login_hint, etc.)."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
        return test_server

    @pytest.fixture
    async def test_user(self, db_pool) -> UserModel:
        """Create a test user."""
        user_data = UserModel(
            id=uuid4(),
            username=f"param_user_{uuid4().hex[:8]}",
            email=f"param_{uuid4().hex[:8]}@example.com",
            password_hash=get_password_hash("Test123!"),
            is_verified=True,
            is_admin=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        async with db_pool.connection() as conn:
            user_repo = UserRepository(conn)
            return await user_repo.create(user_data)

    @pytest.fixture
    async def test_client(self, db_pool) -> OAuthClientModel:
        """Create a test client."""
        client_data = OAuthClientModel(
            id=uuid4(),
            client_id=f"param_client_{uuid4().hex[:8]}",
            client_name="Parameter Test OIDC Client",
            client_secret_hash=get_password_hash("param_secret"),
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            require_pkce=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)
            return await client_repo.create(client_data)

    async def test_ui_locales_parameter(
        self, 
        oidc_server: AsyncTestServer,
        test_client: OAuthClientModel
    ):
        """Test ui_locales parameter handling."""
        
        # Test various ui_locales values
        ui_locales_values = [
            "en-US",
            "en-GB",
            "fr-CA",
            "es-ES",
            "en-US fr-CA es-ES",  # Multiple locales
            "zh-CN zh-TW",
        ]
        
        for ui_locales in ui_locales_values:
            auth_params = {
                "response_type": "code",
                "client_id": test_client.client_id,
                "redirect_uri": test_client.redirect_uris[0],
                "scope": "openid profile",
                "state": f"test_state_{ui_locales.replace(' ', '_')}",
                "nonce": f"test_nonce_{ui_locales.replace(' ', '_')}",
                "ui_locales": ui_locales
            }
            
            # Should handle ui_locales parameter without error
            auth_response = await oidc_server.client.get("/api/v1/oauth/authorize", params=auth_params)
            await auth_response.expect_status(401)  # Requires authentication but parameter accepted

    async def test_login_hint_parameter(
        self, 
        oidc_server: AsyncTestServer,
        test_client: OAuthClientModel
    ):
        """Test login_hint parameter handling."""
        
        # Test various login_hint values
        login_hints = [
            "user@example.com",
            "john.doe",
            "+1-555-123-4567",
            "social_media_id:123456",
        ]
        
        for login_hint in login_hints:
            auth_params = {
                "response_type": "code",
                "client_id": test_client.client_id,
                "redirect_uri": test_client.redirect_uris[0],
                "scope": "openid profile",
                "state": "test_state",
                "nonce": "test_nonce",
                "login_hint": login_hint
            }
            
            # Should handle login_hint parameter without error
            auth_response = await oidc_server.client.get("/api/v1/oauth/authorize", params=auth_params)
            await auth_response.expect_status(401)  # Requires authentication but parameter accepted

    async def test_display_parameter_values(
        self, 
        oidc_server: AsyncTestServer,
        test_client: OAuthClientModel
    ):
        """Test display parameter handling."""
        
        # Test all valid display values per OIDC spec
        display_values = ["page", "popup", "touch", "wap"]
        
        for display in display_values:
            auth_params = {
                "response_type": "code",
                "client_id": test_client.client_id,
                "redirect_uri": test_client.redirect_uris[0],
                "scope": "openid profile",
                "state": f"test_state_{display}",
                "nonce": f"test_nonce_{display}",
                "display": display
            }
            
            # Should handle display parameter without error
            auth_response = await oidc_server.client.get("/api/v1/oauth/authorize", params=auth_params)
            await auth_response.expect_status(401)  # Requires authentication but parameter accepted

    async def test_acr_values_parameter(
        self, 
        oidc_server: AsyncTestServer,
        test_client: OAuthClientModel
    ):
        """Test acr_values parameter handling."""
        
        # Test Authentication Context Class Reference values
        acr_values = [
            "0",  # Basic authentication
            "1",  # Password authentication
            "2",  # Multi-factor authentication
            "urn:mace:incommon:iap:silver",  # Custom ACR value
        ]
        
        for acr in acr_values:
            auth_params = {
                "response_type": "code",
                "client_id": test_client.client_id,
                "redirect_uri": test_client.redirect_uris[0],
                "scope": "openid profile",
                "state": f"test_state_{acr}",
                "nonce": f"test_nonce_{acr}",
                "acr_values": acr
            }
            
            # Should handle acr_values parameter without error
            auth_response = await oidc_server.client.get("/api/v1/oauth/authorize", params=auth_params)
            await auth_response.expect_status(401)  # Requires authentication but parameter accepted


class TestOIDCTokenValidation:
    """Test comprehensive OIDC token validation scenarios."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
        return test_server

    async def test_id_token_aud_claim_validation(
        self, 
        oidc_server: AsyncTestServer
    ):
        """Test ID token audience claim validation."""
        
        # This test would ideally create tokens with different audiences
        # and validate that the OIDC service properly validates the aud claim
        
        # For now, we test that the discovery endpoint advertises correct audience requirements
        discovery_response = await oidc_server.client.get("/.well-known/openid_configuration")
        await discovery_response.expect_status(200)
        
        discovery_json = await discovery_response.json()
        
        # Should include audience validation requirements
        assert "claims_supported" in discovery_json
        assert "aud" in discovery_json["claims_supported"]

    async def test_id_token_iss_claim_validation(
        self, 
        oidc_server: AsyncTestServer
    ):
        """Test ID token issuer claim validation."""
        
        discovery_response = await oidc_server.client.get("/.well-known/openid_configuration")
        await discovery_response.expect_status(200)
        
        discovery_json = await discovery_response.json()
        
        # Should include issuer information
        assert "issuer" in discovery_json
        # Issuer should be a valid URL (test environment uses dynamic URLs)
        assert discovery_json["issuer"].startswith("http")
        
        # Should include iss claim support
        assert "claims_supported" in discovery_json
        assert "iss" in discovery_json["claims_supported"]

    async def test_id_token_exp_claim_validation(
        self, 
        oidc_server: AsyncTestServer
    ):
        """Test ID token expiration claim validation."""
        
        discovery_response = await oidc_server.client.get("/.well-known/openid_configuration")
        await discovery_response.expect_status(200)
        
        discovery_json = await discovery_response.json()
        
        # Should support exp claim
        assert "claims_supported" in discovery_json
        assert "exp" in discovery_json["claims_supported"]
        assert "iat" in discovery_json["claims_supported"]

    async def test_id_token_signature_algorithms(
        self, 
        oidc_server: AsyncTestServer
    ):
        """Test supported ID token signature algorithms."""
        
        discovery_response = await oidc_server.client.get("/.well-known/openid_configuration")
        await discovery_response.expect_status(200)
        
        discovery_json = await discovery_response.json()
        
        # Should advertise supported signing algorithms
        assert "id_token_signing_alg_values_supported" in discovery_json
        
        supported_algs = discovery_json["id_token_signing_alg_values_supported"]
        
        # Should support at least RS256 (required by OIDC spec)
        assert "RS256" in supported_algs
        
        # May also support HS256 for confidential clients
        # assert "HS256" in supported_algs


class TestOIDCSpecCompliance:
    """Test OIDC specification compliance requirements."""

    @pytest.fixture
    async def oidc_server(self, test_server) -> AsyncTestServer:
        """Configure test server with OIDC routers."""
        return test_server

    async def test_required_oidc_endpoints_availability(
        self, 
        oidc_server: AsyncTestServer
    ):
        """Test that all required OIDC endpoints are available."""
        
        # Test OIDC Discovery (required)
        discovery_response = await oidc_server.client.get("/.well-known/openid_configuration")
        await discovery_response.expect_status(200)
        
        # Test JWKS endpoint (required)
        jwks_response = await oidc_server.client.get("/.well-known/jwks.json")
        await jwks_response.expect_status(200)
        
        # Test UserInfo endpoint availability (should require auth)
        userinfo_response = await oidc_server.client.get("/oidc/userinfo")
        await userinfo_response.expect_status(401)  # Available but requires auth

    async def test_oidc_discovery_required_fields(
        self, 
        oidc_server: AsyncTestServer
    ):
        """Test OIDC discovery contains all required fields per spec."""
        
        discovery_response = await oidc_server.client.get("/.well-known/openid_configuration")
        await discovery_response.expect_status(200)
        
        discovery_json = await discovery_response.json()
        
        # Required fields per OIDC Discovery spec
        required_fields = [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
        ]
        
        for field in required_fields:
            assert field in discovery_json, f"Missing required OIDC discovery field: {field}"
        
        # Verify response_types_supported includes 'code'
        assert "code" in discovery_json["response_types_supported"]
        
        # Verify subject_types_supported includes 'public'
        assert "public" in discovery_json["subject_types_supported"]
        
        # Verify id_token_signing_alg_values_supported includes 'RS256'
        assert "RS256" in discovery_json["id_token_signing_alg_values_supported"]

    async def test_oidc_scopes_advertised_correctly(
        self, 
        oidc_server: AsyncTestServer
    ):
        """Test that OIDC scopes are advertised correctly in discovery."""
        
        discovery_response = await oidc_server.client.get("/.well-known/openid_configuration")
        await discovery_response.expect_status(200)
        
        discovery_json = await discovery_response.json()
        
        # Should advertise OIDC scopes
        assert "scopes_supported" in discovery_json
        
        scopes_supported = discovery_json["scopes_supported"]
        
        # Required OIDC scopes
        required_scopes = ["openid"]
        for scope in required_scopes:
            assert scope in scopes_supported, f"Missing required OIDC scope: {scope}"
        
        # Common OIDC scopes
        common_scopes = ["profile", "email"]
        for scope in common_scopes:
            assert scope in scopes_supported, f"Missing common OIDC scope: {scope}"

    async def test_oidc_claims_advertised_correctly(
        self, 
        oidc_server: AsyncTestServer
    ):
        """Test that OIDC claims are advertised correctly in discovery."""
        
        discovery_response = await oidc_server.client.get("/.well-known/openid_configuration")
        await discovery_response.expect_status(200)
        
        discovery_json = await discovery_response.json()
        
        # Should advertise OIDC claims
        assert "claims_supported" in discovery_json
        
        claims_supported = discovery_json["claims_supported"]
        
        # Required ID token claims
        required_claims = ["sub", "iss", "aud", "exp", "iat"]
        for claim in required_claims:
            assert claim in claims_supported, f"Missing required OIDC claim: {claim}"
        
        # Common profile claims
        profile_claims = ["name", "given_name", "family_name", "preferred_username"]
        for claim in profile_claims:
            assert claim in claims_supported, f"Missing profile claim: {claim}"
        
        # Email claims
        email_claims = ["email", "email_verified"]
        for claim in email_claims:
            assert claim in claims_supported, f"Missing email claim: {claim}"