"""
Tests for OIDC UserInfo endpoint and service.
"""

from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from authly.oidc.userinfo import UserInfoResponse, UserInfoService
from authly.users.models import UserModel


class TestUserInfoService:
    """Test UserInfo service functionality."""

    @pytest.fixture
    def userinfo_service(self):
        """Create UserInfo service instance."""
        return UserInfoService()

    @pytest.fixture
    def sample_user(self):
        """Create sample user for testing."""
        # Create a mock user with OIDC profile attributes
        user = Mock(spec=UserModel)
        user.id = uuid4()
        user.username = "testuser"
        user.email = "test@example.com"
        user.password_hash = "$2b$12$hash"
        user.created_at = datetime.now(timezone.utc)
        user.updated_at = datetime.now(timezone.utc)
        user.is_active = True
        user.is_verified = True
        user.is_admin = False
        # Add OIDC profile fields
        user.given_name = "John"
        user.family_name = "Doe"
        user.picture = "https://example.com/avatar.jpg"
        user.locale = "en-US"
        user.phone_number = "+1234567890"
        user.phone_number_verified = True
        return user

    def test_create_userinfo_response_openid_scope_only(self, userinfo_service, sample_user):
        """Test UserInfo response with only 'openid' scope."""
        granted_scopes = ["openid"]

        response = userinfo_service.create_userinfo_response(sample_user, granted_scopes)

        # Should only include 'sub' claim
        assert response.sub == str(sample_user.id)
        assert response.name is None
        assert response.given_name is None
        assert response.family_name is None
        assert response.email is None
        assert response.email_verified is None
        assert response.phone_number is None
        assert response.phone_number_verified is None
        assert response.picture is None
        assert response.locale is None

    def test_create_userinfo_response_profile_scope(self, userinfo_service, sample_user):
        """Test UserInfo response with 'profile' scope."""
        granted_scopes = ["openid", "profile"]

        response = userinfo_service.create_userinfo_response(sample_user, granted_scopes)

        # Should include profile claims
        assert response.sub == str(sample_user.id)
        assert response.name == "John Doe"
        assert response.given_name == "John"
        assert response.family_name == "Doe"
        assert response.preferred_username == "testuser"
        assert response.picture == "https://example.com/avatar.jpg"
        assert response.locale == "en-US"
        assert response.updated_at == int(sample_user.updated_at.timestamp())

        # Should not include email or phone claims
        assert response.email is None
        assert response.email_verified is None
        assert response.phone_number is None
        assert response.phone_number_verified is None

    def test_create_userinfo_response_email_scope(self, userinfo_service, sample_user):
        """Test UserInfo response with 'email' scope."""
        granted_scopes = ["openid", "email"]

        response = userinfo_service.create_userinfo_response(sample_user, granted_scopes)

        # Should include email claims
        assert response.sub == str(sample_user.id)
        assert response.email == "test@example.com"
        assert response.email_verified is True

        # Should not include profile or phone claims
        assert response.name is None
        assert response.given_name is None
        assert response.phone_number is None
        assert response.phone_number_verified is None

    def test_create_userinfo_response_phone_scope(self, userinfo_service, sample_user):
        """Test UserInfo response with 'phone' scope."""
        granted_scopes = ["openid", "phone"]

        response = userinfo_service.create_userinfo_response(sample_user, granted_scopes)

        # Should include phone claims
        assert response.sub == str(sample_user.id)
        assert response.phone_number == "+1234567890"
        assert response.phone_number_verified is True

        # Should not include profile or email claims
        assert response.name is None
        assert response.given_name is None
        assert response.email is None
        assert response.email_verified is None

    def test_create_userinfo_response_multiple_scopes(self, userinfo_service, sample_user):
        """Test UserInfo response with multiple scopes."""
        granted_scopes = ["openid", "profile", "email", "phone"]

        response = userinfo_service.create_userinfo_response(sample_user, granted_scopes)

        # Should include all claims
        assert response.sub == str(sample_user.id)
        assert response.name == "John Doe"
        assert response.given_name == "John"
        assert response.family_name == "Doe"
        assert response.email == "test@example.com"
        assert response.email_verified is True
        assert response.phone_number == "+1234567890"
        assert response.phone_number_verified is True
        assert response.picture == "https://example.com/avatar.jpg"
        assert response.locale == "en-US"

    def test_create_userinfo_response_minimal_user_data(self, userinfo_service):
        """Test UserInfo response with minimal user data."""
        minimal_user = UserModel(
            id=uuid4(),
            username="minimal",
            email="minimal@example.com",
            password_hash="$2b$12$hash",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=False,
            is_admin=False,
        )

        granted_scopes = ["openid", "profile", "email"]

        response = userinfo_service.create_userinfo_response(minimal_user, granted_scopes)

        # Should handle missing optional fields gracefully
        assert response.sub == str(minimal_user.id)
        assert response.name == "minimal"  # Falls back to username
        assert response.given_name is None
        assert response.family_name is None
        assert response.email == "minimal@example.com"
        assert response.email_verified is False
        assert response.preferred_username == "minimal"

    def test_validate_userinfo_request_valid(self, userinfo_service):
        """Test UserInfo request validation with valid scopes."""
        granted_scopes = ["openid", "profile"]

        result = userinfo_service.validate_userinfo_request(granted_scopes)

        assert result is True

    def test_validate_userinfo_request_missing_openid(self, userinfo_service):
        """Test UserInfo request validation missing 'openid' scope."""
        granted_scopes = ["profile", "email"]

        result = userinfo_service.validate_userinfo_request(granted_scopes)

        assert result is False

    def test_validate_userinfo_request_empty_scopes(self, userinfo_service):
        """Test UserInfo request validation with empty scopes."""
        granted_scopes = []

        result = userinfo_service.validate_userinfo_request(granted_scopes)

        assert result is False

    def test_get_supported_claims(self, userinfo_service):
        """Test getting supported claims for scopes."""
        granted_scopes = ["openid", "profile", "email"]

        claims = userinfo_service.get_supported_claims(granted_scopes)

        # Should include claims from all granted scopes
        assert "sub" in claims
        assert "name" in claims
        assert "given_name" in claims
        assert "family_name" in claims
        assert "email" in claims
        assert "email_verified" in claims

        # Should not include phone claims
        assert "phone_number" not in claims
        assert "phone_number_verified" not in claims

    def test_get_full_name_both_names(self, userinfo_service):
        """Test full name generation with both given and family names."""
        user = Mock()
        user.given_name = "John"
        user.family_name = "Doe"
        user.username = "johndoe"

        result = userinfo_service._get_full_name(user)

        assert result == "John Doe"

    def test_get_full_name_given_only(self, userinfo_service):
        """Test full name generation with only given name."""
        user = Mock()
        user.given_name = "John"
        user.family_name = None
        user.username = "johndoe"

        result = userinfo_service._get_full_name(user)

        assert result == "John"

    def test_get_full_name_family_only(self, userinfo_service):
        """Test full name generation with only family name."""
        user = Mock()
        user.given_name = None
        user.family_name = "Doe"
        user.username = "johndoe"

        result = userinfo_service._get_full_name(user)

        assert result == "Doe"

    def test_get_full_name_fallback_to_username(self, userinfo_service):
        """Test full name generation fallback to username."""
        user = Mock()
        user.given_name = None
        user.family_name = None
        user.username = "johndoe"

        result = userinfo_service._get_full_name(user)

        assert result == "johndoe"


class TestUserInfoEndpoint:
    """Test UserInfo endpoint functionality."""

    @pytest.fixture
    def mock_dependencies(self):
        """Create mock dependencies for testing."""
        mock_user = Mock(spec=UserModel)
        mock_user.id = uuid4()
        mock_user.username = "testuser"
        mock_user.email = "test@example.com"
        mock_user.is_verified = True
        mock_user.updated_at = datetime.now(timezone.utc)

        mock_token_scopes = ["openid", "profile", "email"]
        mock_userinfo_service = Mock(spec=UserInfoService)

        return mock_user, mock_token_scopes, mock_userinfo_service

    @pytest.mark.asyncio
    async def test_userinfo_endpoint_success(self, mock_dependencies):
        """Test successful UserInfo endpoint response."""
        mock_user, mock_token_scopes, mock_userinfo_service = mock_dependencies

        # Setup mocks
        mock_userinfo_service.validate_userinfo_request.return_value = True
        mock_response = UserInfoResponse(
            sub=str(mock_user.id), name="Test User", email="test@example.com", email_verified=True
        )
        mock_userinfo_service.create_userinfo_response.return_value = mock_response

        # Import the endpoint function
        from authly.api.oidc_router import userinfo_endpoint

        # Call endpoint
        result = await userinfo_endpoint(mock_user, mock_token_scopes, mock_userinfo_service)

        # Verify calls
        mock_userinfo_service.validate_userinfo_request.assert_called_once_with(mock_token_scopes)
        mock_userinfo_service.create_userinfo_response.assert_called_once_with(
            user=mock_user, granted_scopes=mock_token_scopes
        )

        # Verify response
        assert result == mock_response

    @pytest.mark.asyncio
    async def test_userinfo_endpoint_missing_openid_scope(self, mock_dependencies):
        """Test UserInfo endpoint with missing 'openid' scope."""
        mock_user, mock_token_scopes, mock_userinfo_service = mock_dependencies

        # Setup mock to return False for validation
        mock_userinfo_service.validate_userinfo_request.return_value = False

        # Import the endpoint function
        from authly.api.oidc_router import userinfo_endpoint

        # Call endpoint and expect HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await userinfo_endpoint(mock_user, mock_token_scopes, mock_userinfo_service)

        # Verify exception
        assert exc_info.value.status_code == 403
        assert "openid" in exc_info.value.detail
        assert "WWW-Authenticate" in exc_info.value.headers

    @pytest.mark.asyncio
    async def test_userinfo_endpoint_service_error(self, mock_dependencies):
        """Test UserInfo endpoint with service error."""
        mock_user, mock_token_scopes, mock_userinfo_service = mock_dependencies

        # Setup mocks
        mock_userinfo_service.validate_userinfo_request.return_value = True
        mock_userinfo_service.create_userinfo_response.side_effect = Exception("Service error")

        # Import the endpoint function
        from authly.api.oidc_router import userinfo_endpoint

        # Call endpoint and expect HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await userinfo_endpoint(mock_user, mock_token_scopes, mock_userinfo_service)

        # Verify exception
        assert exc_info.value.status_code == 500
        assert "Unable to generate UserInfo response" in exc_info.value.detail
