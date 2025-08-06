"""
Tests for OpenID Connect Authorization Endpoint enhancements.

This module tests the enhanced OAuth 2.1 authorization endpoint with OpenID Connect 1.0 support,
including OIDC-specific parameters and validation.
"""

from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import uuid4

import pytest
from psycopg_toolkit import TransactionManager

from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.authorization_service import AuthorizationService
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import (
    ClientType,
    CodeChallengeMethod,
    Display,
    OAuthAuthorizationRequest,
    OAuthClientModel,
    Prompt,
    ResponseMode,
    UserConsentRequest,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.oidc.scopes import OIDCClaimsMapping
from authly.users.models import UserModel


class TestOIDCAuthorizationRequest:
    """Test OpenID Connect authorization request model enhancements."""

    def test_create_basic_oauth_request(self):
        """Test creating basic OAuth 2.1 authorization request."""
        request = OAuthAuthorizationRequest(
            response_type="code",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            code_challenge="test-challenge-123456789012345678901234567890",
            scope="read write",
        )

        assert request.response_type == "code"
        assert request.client_id == "test-client"
        assert request.redirect_uri == "https://example.com/callback"
        assert request.code_challenge == "test-challenge-123456789012345678901234567890"
        assert request.scope == "read write"
        assert request.get_scope_list() == ["read", "write"]
        assert not request.is_oidc_request()

    def test_create_oidc_authorization_request(self):
        """Test creating OpenID Connect authorization request."""
        request = OAuthAuthorizationRequest(
            response_type="code",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            code_challenge="test-challenge-123456789012345678901234567890",
            scope="openid profile email",
            nonce="test-nonce-123",
            response_mode=ResponseMode.QUERY,
            display=Display.PAGE,
            prompt=Prompt.CONSENT,
            max_age=3600,
            ui_locales="en-US es-ES",
            login_hint="user@example.com",
            acr_values="1 2",
        )

        assert request.is_oidc_request()
        assert request.nonce == "test-nonce-123"
        assert request.response_mode == ResponseMode.QUERY
        assert request.display == Display.PAGE
        assert request.prompt == Prompt.CONSENT
        assert request.max_age == 3600
        assert request.ui_locales == "en-US es-ES"
        assert request.get_ui_locales_list() == ["en-US", "es-ES"]
        assert request.login_hint == "user@example.com"
        assert request.acr_values == "1 2"
        assert request.get_acr_values_list() == ["1", "2"]

    def test_validate_oidc_params(self):
        """Test OIDC parameter validation."""
        # Valid parameters
        request = OAuthAuthorizationRequest(
            response_type="code",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            code_challenge="test-challenge-123456789012345678901234567890",
            scope="openid profile",
            max_age=3600,
            prompt=Prompt.CONSENT,
        )

        assert request.validate_oidc_params()

        # Invalid max_age
        request.max_age = -1
        assert not request.validate_oidc_params()

        # Valid prompt=none
        request.max_age = None
        request.prompt = Prompt.NONE
        assert request.validate_oidc_params()

    def test_scope_list_conversion(self):
        """Test scope list conversion utilities."""
        request = OAuthAuthorizationRequest(
            response_type="code",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            code_challenge="test-challenge-123456789012345678901234567890",
            scope="openid profile email address phone",
            ui_locales="en-US fr-FR de-DE",
            acr_values="1 2 3",
        )

        assert request.get_scope_list() == ["openid", "profile", "email", "address", "phone"]
        assert request.get_ui_locales_list() == ["en-US", "fr-FR", "de-DE"]
        assert request.get_acr_values_list() == ["1", "2", "3"]

        # Test empty values
        request.scope = None
        request.ui_locales = None
        request.acr_values = None

        assert request.get_scope_list() == []
        assert request.get_ui_locales_list() == []
        assert request.get_acr_values_list() == []


class TestOIDCUserConsentRequest:
    """Test OpenID Connect user consent request model."""

    def test_create_oidc_consent_request(self):
        """Test creating OIDC user consent request."""
        from uuid import uuid4

        user_id = uuid4()
        consent_request = UserConsentRequest(
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            scope="openid profile email",
            state="test-state",
            code_challenge="test-challenge-123456789012345678901234567890",
            code_challenge_method=CodeChallengeMethod.S256,
            user_id=user_id,
            approved=True,
            approved_scopes=["openid", "profile"],
            # OpenID Connect parameters
            nonce="test-nonce-123",
            response_mode=ResponseMode.QUERY,
            display=Display.PAGE,
            prompt=Prompt.CONSENT,
            max_age=3600,
            ui_locales="en-US",
            login_hint="user@example.com",
            acr_values="1 2",
        )

        assert consent_request.client_id == "test-client"
        assert consent_request.nonce == "test-nonce-123"
        assert consent_request.response_mode == ResponseMode.QUERY
        assert consent_request.display == Display.PAGE
        assert consent_request.prompt == Prompt.CONSENT
        assert consent_request.max_age == 3600
        assert consent_request.ui_locales == "en-US"
        assert consent_request.login_hint == "user@example.com"
        assert consent_request.acr_values == "1 2"
        assert consent_request.user_id == user_id
        assert consent_request.approved
        assert consent_request.approved_scopes == ["openid", "profile"]


class TestOIDCAuthorizationService:
    """Test OpenID Connect authorization service enhancements."""

    async def create_test_client(self, conn, client_id=None):
        """Create a test OAuth client in the database."""
        if client_id is None:
            client_id = f"test-client-{uuid4().hex[:8]}"

        client_repository = ClientRepository(conn)

        test_client = OAuthClientModel(
            id=uuid4(),
            client_id=client_id,
            client_secret_hash="test_hash",
            client_name="Test Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        return await client_repository.create(test_client)

    async def create_test_user(self, conn):
        """Create a test user in the database."""
        from authly.users.repository import UserRepository

        user_repository = UserRepository(conn)

        test_user = UserModel(
            id=uuid4(),
            username=f"testuser-{uuid4().hex[:8]}",
            email=f"test-{uuid4().hex[:8]}@example.com",
            password_hash="test_hash",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=True,
        )

        return await user_repository.create(test_user)

    @pytest.mark.asyncio
    async def test_validate_oidc_authorization_request(self, transaction_manager: TransactionManager):
        """Test OIDC authorization request validation."""
        async with transaction_manager.transaction() as conn:
            # Create test client in database
            test_client = await self.create_test_client(conn)

            # Create real repositories and service
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            authorization_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create OIDC request
            request = OAuthAuthorizationRequest(
                response_type="code",
                client_id=test_client.client_id,
                redirect_uri="https://example.com/callback",
                code_challenge="test-challenge-123456789012345678901234567890",
                scope="openid profile email",
                nonce="test-nonce-123",
                prompt=Prompt.CONSENT,
            )

            # Test validation
            is_valid, error_code, client = await authorization_service.validate_authorization_request(request)

            assert is_valid
            assert error_code is None
            assert client.client_id == test_client.client_id

    @pytest.mark.asyncio
    async def test_validate_oidc_request_without_openid_scope(self, transaction_manager: TransactionManager):
        """Test OIDC request validation without openid scope."""
        async with transaction_manager.transaction() as conn:
            # Create test client in database
            test_client = await self.create_test_client(conn)

            # Create real repositories and service
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            authorization_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create request with openid scope but marked as OIDC (should fail)
            request = OAuthAuthorizationRequest(
                response_type="code",
                client_id=test_client.client_id,
                redirect_uri="https://example.com/callback",
                code_challenge="test-challenge-123456789012345678901234567890",
                scope="profile email",  # Missing openid scope
                nonce="test-nonce-123",  # But has nonce (makes it appear OIDC-like)
            )

            # However, the request validation should still pass since is_oidc_request() returns False
            is_valid, error_code, client = await authorization_service.validate_authorization_request(request)

            assert is_valid  # Should pass because it's not an OIDC request
            assert error_code is None
            assert client.client_id == test_client.client_id

    @pytest.mark.asyncio
    async def test_validate_oidc_request_with_prompt_none(self, transaction_manager: TransactionManager):
        """Test OIDC request validation with prompt=none."""
        async with transaction_manager.transaction() as conn:
            # Create test client in database
            test_client = await self.create_test_client(conn)

            # Create real repositories and service
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            authorization_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create OIDC request with prompt=none
            request = OAuthAuthorizationRequest(
                response_type="code",
                client_id=test_client.client_id,
                redirect_uri="https://example.com/callback",
                code_challenge="test-challenge-123456789012345678901234567890",
                scope="openid profile",
                nonce="test-nonce-123",
                prompt=Prompt.NONE,
            )

            # Test validation
            is_valid, error_code, client = await authorization_service.validate_authorization_request(request)

            assert is_valid
            assert error_code is None
            assert client.client_id == test_client.client_id

    @pytest.mark.asyncio
    async def test_generate_authorization_code_with_oidc_params(self, transaction_manager: TransactionManager):
        """Test authorization code generation with OIDC parameters."""
        async with transaction_manager.transaction() as conn:
            # Create test client in database
            test_client = await self.create_test_client(conn)

            # Create real repositories and service
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            authorization_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create test user in database
            test_user = await self.create_test_user(conn)

            # Create consent request with OIDC parameters
            consent_request = UserConsentRequest(
                client_id=test_client.client_id,
                redirect_uri="https://example.com/callback",
                scope="openid profile email",
                state="test-state",
                code_challenge="test-challenge-123456789012345678901234567890",
                code_challenge_method=CodeChallengeMethod.S256,
                user_id=test_user.id,
                approved=True,
                approved_scopes=["openid", "profile"],
                # OpenID Connect parameters
                nonce="test-nonce-123",
                response_mode=ResponseMode.QUERY,
                display=Display.PAGE,
                prompt=Prompt.CONSENT,
                max_age=3600,
                ui_locales="en-US",
                login_hint="user@example.com",
                acr_values="1 2",
            )

            # Generate authorization code
            auth_code = await authorization_service.generate_authorization_code(consent_request)

            assert auth_code is not None
            assert isinstance(auth_code, str)

            # Verify the authorization code was stored with OIDC parameters
            stored_code = await auth_code_repo.get_by_code(auth_code)
            assert stored_code is not None
            assert stored_code.nonce == "test-nonce-123"
            assert stored_code.response_mode == ResponseMode.QUERY
            assert stored_code.display == Display.PAGE
            assert stored_code.prompt == Prompt.CONSENT
            assert stored_code.max_age == 3600
            assert stored_code.ui_locales == "en-US"
            assert stored_code.login_hint == "user@example.com"
            assert stored_code.acr_values == "1 2"

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_returns_oidc_params(self, transaction_manager: TransactionManager):
        """Test authorization code exchange returns OIDC parameters."""
        async with transaction_manager.transaction() as conn:
            # Create test client in database
            test_client = await self.create_test_client(conn)

            # Create real repositories and service
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            authorization_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create test user in database
            test_user = await self.create_test_user(conn)

            # Create proper PKCE challenge/verifier pair for testing
            import base64
            import hashlib

            code_verifier = "test-verifier-123456789012345678901234567890123456789012345678901234567890"
            code_challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
            )

            # First create a consent request with OIDC parameters
            consent_request = UserConsentRequest(
                client_id=test_client.client_id,
                redirect_uri="https://example.com/callback",
                scope="openid profile email",
                state="test-state",
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                user_id=test_user.id,
                approved=True,
                approved_scopes=["openid", "profile", "email"],
                # OpenID Connect parameters
                nonce="test-nonce-123",
                response_mode=ResponseMode.QUERY,
                display=Display.PAGE,
                prompt=Prompt.CONSENT,
                max_age=3600,
                ui_locales="en-US",
                login_hint="user@example.com",
                acr_values="1 2",
            )

            # Generate authorization code with OIDC parameters
            auth_code = await authorization_service.generate_authorization_code(consent_request)
            assert auth_code is not None
            assert isinstance(auth_code, str)

            # Exchange authorization code
            success, code_data, error = await authorization_service.exchange_authorization_code(
                code=auth_code,
                client_id=test_client.client_id,
                redirect_uri="https://example.com/callback",
                code_verifier=code_verifier,
            )

            assert success
            assert error is None
            assert code_data is not None
            assert code_data["user_id"] == test_user.id
            assert code_data["client_id"] == test_client.client_id
            assert code_data["scope"] == "openid profile email"
            assert code_data["nonce"] == "test-nonce-123"
            assert code_data["max_age"] == 3600
            assert code_data["acr_values"] == "1 2"


class TestOIDCAuthorizationEndpoint:
    """Test OpenID Connect authorization endpoint integration."""

    @pytest.fixture
    def test_user(self):
        """Create test user."""
        user = Mock(spec=UserModel)
        user.id = "test-user-id"
        user.username = "testuser"
        user.email = "test@example.com"
        return user

    def test_authorization_endpoint_with_oidc_params(self, test_user):
        """Test authorization endpoint accepts OIDC parameters."""
        # This would typically be an integration test with a real test client
        # For now, we'll test that the parameter parsing works correctly

        # Simulate query parameters for OIDC request
        params = {
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "https://example.com/callback",
            "code_challenge": "test-challenge-123456789012345678901234567890",
            "scope": "openid profile email",
            "state": "test-state",
            "nonce": "test-nonce-123",
            "response_mode": "query",
            "display": "page",
            "prompt": "consent",
            "max_age": "3600",
            "ui_locales": "en-US fr-FR",
            "login_hint": "user@example.com",
            "acr_values": "1 2",
        }

        # Test that we can create an authorization request from these parameters
        request = OAuthAuthorizationRequest(
            response_type="code",
            client_id=params["client_id"],
            redirect_uri=params["redirect_uri"],
            code_challenge=params["code_challenge"],
            scope=params["scope"],
            state=params["state"],
            nonce=params["nonce"],
            response_mode=ResponseMode(params["response_mode"]),
            display=Display(params["display"]),
            prompt=Prompt(params["prompt"]),
            max_age=int(params["max_age"]),
            ui_locales=params["ui_locales"],
            login_hint=params["login_hint"],
            acr_values=params["acr_values"],
        )

        assert request.is_oidc_request()
        assert request.nonce == "test-nonce-123"
        assert request.response_mode == ResponseMode.QUERY
        assert request.display == Display.PAGE
        assert request.prompt == Prompt.CONSENT
        assert request.max_age == 3600
        assert request.ui_locales == "en-US fr-FR"
        assert request.login_hint == "user@example.com"
        assert request.acr_values == "1 2"

    def test_consent_request_with_oidc_params(self, test_user):
        """Test consent request creation with OIDC parameters."""
        from uuid import uuid4

        # Create consent request with OIDC parameters
        consent_request = UserConsentRequest(
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            scope="openid profile email",
            state="test-state",
            code_challenge="test-challenge-123456789012345678901234567890",
            code_challenge_method=CodeChallengeMethod.S256,
            user_id=uuid4(),
            approved=True,
            approved_scopes=["openid", "profile"],
            # OpenID Connect parameters
            nonce="test-nonce-123",
            response_mode=ResponseMode.QUERY,
            display=Display.PAGE,
            prompt=Prompt.CONSENT,
            max_age=3600,
            ui_locales="en-US",
            login_hint="user@example.com",
            acr_values="1 2",
        )

        # Verify all OIDC parameters are properly set
        assert consent_request.nonce == "test-nonce-123"
        assert consent_request.response_mode == ResponseMode.QUERY
        assert consent_request.display == Display.PAGE
        assert consent_request.prompt == Prompt.CONSENT
        assert consent_request.max_age == 3600
        assert consent_request.ui_locales == "en-US"
        assert consent_request.login_hint == "user@example.com"
        assert consent_request.acr_values == "1 2"


class TestOIDCAuthorizationIntegration:
    """Test OIDC authorization integration with other components."""

    def test_oidc_scopes_integration(self):
        """Test integration with OIDC scopes system."""
        # Test that OIDC authorization request integrates with scopes system
        request = OAuthAuthorizationRequest(
            response_type="code",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            code_challenge="test-challenge-123456789012345678901234567890",
            scope="openid profile email address phone",
        )

        # Check OIDC request detection
        assert request.is_oidc_request()

        # Check scope list
        scopes = request.get_scope_list()
        assert "openid" in scopes
        assert "profile" in scopes
        assert "email" in scopes
        assert "address" in scopes
        assert "phone" in scopes

        # Test claims mapping integration
        claims = OIDCClaimsMapping.get_claims_for_scopes(scopes)
        assert "sub" in claims  # From openid scope
        assert "name" in claims  # From profile scope
        assert "email" in claims  # From email scope
        assert "address" in claims  # From address scope
        assert "phone_number" in claims  # From phone scope

    def test_response_mode_handling(self):
        """Test response mode parameter handling."""
        # Test all supported response modes
        for mode in [ResponseMode.QUERY, ResponseMode.FRAGMENT, ResponseMode.FORM_POST]:
            request = OAuthAuthorizationRequest(
                response_type="code",
                client_id="test-client",
                redirect_uri="https://example.com/callback",
                code_challenge="test-challenge-123456789012345678901234567890",
                scope="openid profile",
                response_mode=mode,
            )

            assert request.response_mode == mode

    def test_display_parameter_handling(self):
        """Test display parameter handling."""
        # Test all supported display values
        for display in [Display.PAGE, Display.POPUP, Display.TOUCH, Display.WAP]:
            request = OAuthAuthorizationRequest(
                response_type="code",
                client_id="test-client",
                redirect_uri="https://example.com/callback",
                code_challenge="test-challenge-123456789012345678901234567890",
                scope="openid profile",
                display=display,
            )

            assert request.display == display

    def test_prompt_parameter_handling(self):
        """Test prompt parameter handling."""
        # Test all supported prompt values
        for prompt in [Prompt.NONE, Prompt.LOGIN, Prompt.CONSENT, Prompt.SELECT_ACCOUNT]:
            request = OAuthAuthorizationRequest(
                response_type="code",
                client_id="test-client",
                redirect_uri="https://example.com/callback",
                code_challenge="test-challenge-123456789012345678901234567890",
                scope="openid profile",
                prompt=prompt,
            )

            assert request.prompt == prompt

            # Test validation with prompt=none
            if prompt == Prompt.NONE:
                assert request.validate_oidc_params()
