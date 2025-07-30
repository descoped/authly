"""
Tests for OIDC scopes and claims system.

This module tests the OpenID Connect scopes and claims mapping functionality.
"""

import pytest

from authly.core.resource_manager import AuthlyResourceManager
from authly.oidc.scopes import (
    OIDC_SCOPES,
    OIDCClaimsMapping,
    OIDCStandardClaims,
    get_all_oidc_scope_names,
    get_oidc_claims_reference,
    get_oidc_scopes_with_descriptions,
)
from authly.oidc.validation import OIDCScopeProcessor, OIDCValidator, validate_mixed_scopes


class TestOIDCScopes:
    """Test OIDC scopes definitions and mappings."""

    def test_oidc_scopes_structure(self):
        """Test that OIDC scopes are properly structured."""
        # Test that all required scopes are present
        expected_scopes = {"openid", "profile", "email", "address", "phone"}
        assert set(OIDC_SCOPES.keys()) == expected_scopes

        # Test that openid scope is marked as required
        assert OIDC_SCOPES["openid"].required is True

        # Test that other scopes are not required
        for scope_name in ["profile", "email", "address", "phone"]:
            assert OIDC_SCOPES[scope_name].required is False

    def test_oidc_claims_mapping(self):
        """Test OIDC claims mapping functionality."""
        # Test openid scope claims
        openid_claims = OIDC_SCOPES["openid"].claims
        expected_openid_claims = {
            OIDCStandardClaims.SUB,
            OIDCStandardClaims.ISS,
            OIDCStandardClaims.AUD,
            OIDCStandardClaims.EXP,
            OIDCStandardClaims.IAT,
        }
        assert openid_claims == expected_openid_claims

        # Test profile scope claims
        profile_claims = OIDC_SCOPES["profile"].claims
        assert OIDCStandardClaims.NAME in profile_claims
        assert OIDCStandardClaims.PREFERRED_USERNAME in profile_claims

        # Test email scope claims
        email_claims = OIDC_SCOPES["email"].claims
        assert OIDCStandardClaims.EMAIL in email_claims
        assert OIDCStandardClaims.EMAIL_VERIFIED in email_claims

    def test_get_claims_for_scopes(self):
        """Test getting claims for multiple scopes."""
        # Test with openid and profile scopes
        scopes = ["openid", "profile"]
        claims = OIDCClaimsMapping.get_claims_for_scopes(scopes)

        # Should include both openid and profile claims
        assert OIDCStandardClaims.SUB in claims
        assert OIDCStandardClaims.NAME in claims
        assert OIDCStandardClaims.PREFERRED_USERNAME in claims

        # Should not include email claims
        assert OIDCStandardClaims.EMAIL not in claims

    def test_is_oidc_request(self):
        """Test OIDC request detection."""
        # Test with openid scope
        assert OIDCClaimsMapping.is_oidc_request(["openid", "profile"]) is True

        # Test without openid scope
        assert OIDCClaimsMapping.is_oidc_request(["profile", "email"]) is False

        # Test with empty scopes
        assert OIDCClaimsMapping.is_oidc_request([]) is False

    def test_get_required_scopes(self):
        """Test getting required OIDC scopes."""
        required_scopes = OIDCClaimsMapping.get_required_scopes()
        assert required_scopes == ["openid"]

    def test_filter_claims_by_scopes(self):
        """Test filtering claims based on granted scopes."""
        # Sample claims data
        all_claims = {
            OIDCStandardClaims.SUB: "user123",
            OIDCStandardClaims.NAME: "John Doe",
            OIDCStandardClaims.EMAIL: "john@example.com",
            OIDCStandardClaims.PHONE_NUMBER: "+1234567890",
        }

        # Filter by openid and profile scopes
        filtered_claims = OIDCClaimsMapping.filter_claims_by_scopes(all_claims, ["openid", "profile"])

        # Should include sub and name
        assert OIDCStandardClaims.SUB in filtered_claims
        assert OIDCStandardClaims.NAME in filtered_claims

        # Should not include email or phone
        assert OIDCStandardClaims.EMAIL not in filtered_claims
        assert OIDCStandardClaims.PHONE_NUMBER not in filtered_claims


class TestOIDCValidation:
    """Test OIDC validation functionality."""

    def test_validate_oidc_scopes_valid(self):
        """Test validation of valid OIDC scopes."""
        scopes = ["openid", "profile", "email"]
        result = OIDCValidator.validate_oidc_scopes(scopes)

        assert result.is_valid is True
        assert result.is_oidc_request is True
        assert result.validated_scopes == scopes
        assert result.invalid_scopes == []
        assert len(result.errors) == 0

    def test_validate_oidc_scopes_invalid(self):
        """Test validation of invalid OIDC scopes."""
        scopes = ["openid", "invalid_scope"]
        result = OIDCValidator.validate_oidc_scopes(scopes)

        assert result.is_valid is True  # Still valid because openid is present
        assert result.is_oidc_request is True
        assert "openid" in result.validated_scopes
        assert "invalid_scope" in result.invalid_scopes
        assert len(result.warnings) > 0

    def test_validate_oidc_scopes_no_openid(self):
        """Test validation without openid scope."""
        scopes = ["profile", "email"]
        result = OIDCValidator.validate_oidc_scopes(scopes)

        assert result.is_oidc_request is False
        assert len(result.warnings) > 0

    def test_validate_response_type(self):
        """Test response type validation."""
        # Test authorization code flow
        valid, flow, errors = OIDCValidator.validate_response_type("code")
        assert valid is True
        assert flow.value == "authorization_code"
        assert len(errors) == 0

        # Test implicit flow
        valid, flow, errors = OIDCValidator.validate_response_type("id_token")
        assert valid is True
        assert flow.value == "implicit"
        assert len(errors) == 0

        # Test invalid response type
        valid, flow, errors = OIDCValidator.validate_response_type("invalid")
        assert valid is False
        assert flow is None
        assert len(errors) > 0

    def test_validate_nonce(self, initialize_authly: AuthlyResourceManager):
        """Test nonce validation."""
        config = initialize_authly.get_config()

        # Test nonce required for implicit flow
        errors = OIDCValidator.validate_nonce(None, "id_token", config)
        assert len(errors) > 0

        # Test nonce not required for authorization code flow
        errors = OIDCValidator.validate_nonce(None, "code", config)
        assert len(errors) == 0

        # Test valid nonce
        errors = OIDCValidator.validate_nonce("valid_nonce", "id_token", config)
        assert len(errors) == 0

    def test_validate_oidc_request_parameters(self, initialize_authly: AuthlyResourceManager):
        """Test comprehensive OIDC request parameter validation."""
        config = initialize_authly.get_config()

        # Test valid OIDC request
        result = OIDCValidator.validate_oidc_request_parameters(
            scopes=["openid", "profile"], response_type="code", config=config, nonce="test_nonce"
        )

        assert result.is_valid is True
        assert result.is_oidc_request is True
        assert len(result.errors) == 0


class TestOIDCScopeProcessor:
    """Test OIDC scope processing functionality."""

    def test_get_oidc_scope_registration_data(self):
        """Test getting OIDC scope registration data."""
        registration_data = OIDCScopeProcessor.get_oidc_scope_registration_data()

        # Should have data for all OIDC scopes
        assert len(registration_data) == len(OIDC_SCOPES)

        # Each scope should have required fields
        for scope_data in registration_data:
            assert "scope_name" in scope_data
            assert "description" in scope_data
            assert "is_default" in scope_data
            assert "is_active" in scope_data
            assert "scope_type" in scope_data
            assert "claims" in scope_data
            assert "required" in scope_data

    def test_separate_oauth_and_oidc_scopes(self):
        """Test separating OAuth and OIDC scopes."""
        mixed_scopes = ["read", "write", "openid", "profile", "admin:read"]

        oauth_scopes, oidc_scopes = OIDCScopeProcessor.separate_oauth_and_oidc_scopes(mixed_scopes)

        assert "openid" in oidc_scopes
        assert "profile" in oidc_scopes
        assert "read" in oauth_scopes
        assert "write" in oauth_scopes
        assert "admin:read" in oauth_scopes

    def test_validate_scope_combination(self):
        """Test validating combination of OAuth and OIDC scopes."""
        mixed_scopes = ["read", "openid", "profile", "invalid_scope"]

        result = OIDCScopeProcessor.validate_scope_combination(mixed_scopes)

        assert result["is_oidc_request"] is True
        assert "read" in result["oauth_scopes"]
        assert "openid" in result["oidc_scopes"]
        assert "profile" in result["oidc_scopes"]
        assert "invalid_scope" in result["invalid_scopes"]


class TestOIDCUtilityFunctions:
    """Test OIDC utility functions."""

    def test_get_oidc_scopes_with_descriptions(self):
        """Test getting OIDC scopes with descriptions."""
        scopes_with_descriptions = get_oidc_scopes_with_descriptions()

        # Should contain all OIDC scopes
        assert len(scopes_with_descriptions) == len(OIDC_SCOPES)

        # Should have descriptions for all scopes
        for scope_name, description in scopes_with_descriptions.items():
            assert isinstance(description, str)
            assert len(description) > 0

    def test_get_all_oidc_scope_names(self):
        """Test getting all OIDC scope names."""
        scope_names = get_all_oidc_scope_names()

        expected_scopes = {"openid", "profile", "email", "address", "phone"}
        assert set(scope_names) == expected_scopes

    def test_get_oidc_claims_reference(self):
        """Test getting OIDC claims reference."""
        claims_reference = get_oidc_claims_reference()

        # Should contain all OIDC scopes
        assert len(claims_reference) == len(OIDC_SCOPES)

        # Each scope should have required fields
        for scope_name, scope_info in claims_reference.items():
            assert "description" in scope_info
            assert "claims" in scope_info
            assert "required" in scope_info
            assert "default" in scope_info
            assert isinstance(scope_info["claims"], list)

    def test_validate_mixed_scopes(self):
        """Test validating mixed OAuth and OIDC scopes."""
        # Test with OIDC scopes
        scopes = ["openid", "profile", "read", "write"]
        result = validate_mixed_scopes(scopes)

        assert result.is_oidc_request is True
        assert result.is_valid is True

        # Test without OIDC scopes
        scopes = ["read", "write"]
        result = validate_mixed_scopes(scopes)

        assert result.is_oidc_request is False
        assert result.is_valid is True


class TestOIDCIntegration:
    """Test OIDC integration with existing OAuth system."""

    def test_oidc_scope_reserved_patterns(self):
        """Test that OIDC scopes are properly handled by OAuth validation."""
        # This test verifies that the OAuth scope validation recognizes
        # OIDC scopes as reserved patterns

        # Test that "openid" is recognized as reserved
        from authly.oauth.scope_service import ScopeService

        # Create a mock scope service to test validation
        scope_service = ScopeService(None)  # We won't actually use the repository

        # Test that the validation recognizes openid as reserved
        # The _validate_scope_name_format method should log a warning for reserved patterns
        try:
            scope_service._validate_scope_name_format("openid")
            # Should not raise an exception, but should log a warning
        except Exception:
            pytest.fail("OIDC scope validation should not raise exceptions")

    def test_oidc_bootstrap_integration(self):
        """Test that OIDC scopes can be integrated with bootstrap process."""
        from authly.bootstrap.admin_seeding import get_bootstrap_status

        # Test that bootstrap status includes OIDC scope information
        status = get_bootstrap_status()

        assert "total_oidc_scopes" in status
        assert "oidc_scopes" in status
        assert status["total_oidc_scopes"] == len(OIDC_SCOPES)
        assert set(status["oidc_scopes"]) == set(OIDC_SCOPES.keys())
