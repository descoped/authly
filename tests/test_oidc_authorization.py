"""
Tests for OpenID Connect Authorization Endpoint enhancements.

This module tests the enhanced OAuth 2.1 authorization endpoint with OpenID Connect 1.0 support,
including OIDC-specific parameters and validation.
"""

from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from fastapi.testclient import TestClient

from authly.oauth.authorization_service import AuthorizationService
from authly.oauth.models import (
    CodeChallengeMethod,
    Display,
    OAuthAuthorizationRequest,
    Prompt,
    ResponseMode,
    UserConsentRequest,
)
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
            scope="read write"
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
            acr_values="1 2"
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
            prompt=Prompt.CONSENT
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
            acr_values="1 2 3"
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
            acr_values="1 2"
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
    
    @pytest.fixture
    def authorization_service(self):
        """Create authorization service with mocked dependencies."""
        client_repo = Mock()
        scope_repo = Mock()
        auth_code_repo = Mock()
        return AuthorizationService(client_repo, scope_repo, auth_code_repo)
    
    @pytest.fixture
    def mock_client(self):
        """Create mock OAuth client."""
        client = Mock()
        client.id = "client-uuid"
        client.client_id = "test-client"
        client.is_active = True
        client.is_redirect_uri_allowed.return_value = True
        client.supports_response_type.return_value = True
        return client
    
    @pytest.mark.asyncio
    async def test_validate_oidc_authorization_request(self, authorization_service, mock_client):
        """Test OIDC authorization request validation."""
        authorization_service.client_repo.get_by_client_id = AsyncMock(return_value=mock_client)
        authorization_service.scope_repo.validate_scope_names = AsyncMock(return_value=True)
        
        # Create OIDC request
        request = OAuthAuthorizationRequest(
            response_type="code",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            code_challenge="test-challenge-123456789012345678901234567890",
            scope="openid profile email",
            nonce="test-nonce-123",
            prompt=Prompt.CONSENT
        )
        
        # Test validation
        is_valid, error_code, client = await authorization_service.validate_authorization_request(request)
        
        assert is_valid
        assert error_code is None
        assert client == mock_client
    
    @pytest.mark.asyncio
    async def test_validate_oidc_request_without_openid_scope(self, authorization_service, mock_client):
        """Test OIDC request validation without openid scope."""
        authorization_service.client_repo.get_by_client_id = AsyncMock(return_value=mock_client)
        authorization_service.scope_repo.validate_scope_names = AsyncMock(return_value=True)
        
        # Create request with openid scope but marked as OIDC (should fail)
        request = OAuthAuthorizationRequest(
            response_type="code",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            code_challenge="test-challenge-123456789012345678901234567890",
            scope="profile email",  # Missing openid scope
            nonce="test-nonce-123"  # But has nonce (makes it appear OIDC-like)
        )
        
        # However, the request validation should still pass since is_oidc_request() returns False
        is_valid, error_code, client = await authorization_service.validate_authorization_request(request)
        
        assert is_valid  # Should pass because it's not an OIDC request
        assert error_code is None
        assert client == mock_client
    
    @pytest.mark.asyncio
    async def test_validate_oidc_request_with_prompt_none(self, authorization_service, mock_client):
        """Test OIDC request validation with prompt=none."""
        authorization_service.client_repo.get_by_client_id = AsyncMock(return_value=mock_client)
        authorization_service.scope_repo.validate_scope_names = AsyncMock(return_value=True)
        
        # Create OIDC request with prompt=none
        request = OAuthAuthorizationRequest(
            response_type="code",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            code_challenge="test-challenge-123456789012345678901234567890",
            scope="openid profile",
            nonce="test-nonce-123",
            prompt=Prompt.NONE
        )
        
        # Test validation
        is_valid, error_code, client = await authorization_service.validate_authorization_request(request)
        
        assert is_valid
        assert error_code is None
        assert client == mock_client
    
    @pytest.mark.asyncio
    async def test_generate_authorization_code_with_oidc_params(self, authorization_service):
        """Test authorization code generation with OIDC parameters."""
        from uuid import uuid4
        
        # Mock the repository method
        authorization_service.auth_code_repo.create_authorization_code = AsyncMock(return_value=Mock(code="test-code"))
        authorization_service._get_client_uuid = AsyncMock(return_value=uuid4())
        
        # Create consent request with OIDC parameters
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
            acr_values="1 2"
        )
        
        # Generate authorization code
        auth_code = await authorization_service.generate_authorization_code(consent_request)
        
        assert auth_code is not None
        
        # Verify the repository was called with OIDC parameters
        call_args = authorization_service.auth_code_repo.create_authorization_code.call_args[0][0]
        assert call_args["nonce"] == "test-nonce-123"
        assert call_args["response_mode"] == ResponseMode.QUERY
        assert call_args["display"] == Display.PAGE
        assert call_args["prompt"] == Prompt.CONSENT
        assert call_args["max_age"] == 3600
        assert call_args["ui_locales"] == "en-US"
        assert call_args["login_hint"] == "user@example.com"
        assert call_args["acr_values"] == "1 2"
    
    @pytest.mark.asyncio
    async def test_exchange_authorization_code_returns_oidc_params(self, authorization_service):
        """Test authorization code exchange returns OIDC parameters."""
        from uuid import uuid4
        
        # Mock authorization code with OIDC parameters
        mock_auth_code = Mock()
        mock_auth_code.is_valid.return_value = True
        mock_auth_code.client_id = uuid4()
        mock_auth_code.user_id = uuid4()
        mock_auth_code.scope = "openid profile email"
        mock_auth_code.redirect_uri = "https://example.com/callback"
        mock_auth_code.code_challenge = "test-challenge-123456789012345678901234567890"
        mock_auth_code.nonce = "test-nonce-123"
        mock_auth_code.max_age = 3600
        mock_auth_code.acr_values = "1 2"
        
        # Mock repository methods
        authorization_service.auth_code_repo.get_by_code = AsyncMock(return_value=mock_auth_code)
        authorization_service.auth_code_repo.consume_authorization_code = AsyncMock(return_value=True)
        authorization_service._get_client_uuid = AsyncMock(return_value=mock_auth_code.client_id)
        authorization_service._verify_pkce_challenge = Mock(return_value=True)
        
        # Exchange authorization code
        success, code_data, error = await authorization_service.exchange_authorization_code(
            code="test-code",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            code_verifier="test-verifier"
        )
        
        assert success
        assert error is None
        assert code_data is not None
        assert code_data["user_id"] == mock_auth_code.user_id
        assert code_data["client_id"] == mock_auth_code.client_id
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
            "acr_values": "1 2"
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
            acr_values=params["acr_values"]
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
            acr_values="1 2"
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
            scope="openid profile email address phone"
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
                response_mode=mode
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
                display=display
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
                prompt=prompt
            )
            
            assert request.prompt == prompt
            
            # Test validation with prompt=none
            if prompt == Prompt.NONE:
                assert request.validate_oidc_params()