"""
OpenID Connect (OIDC) 1.0 Validation and Processing Logic.

This module provides validation and processing utilities for OIDC requests,
including scope validation, parameter validation, and flow validation.
"""

import logging
from dataclasses import dataclass
from enum import Enum

from authly.config.config import AuthlyConfig

from .scopes import OIDC_SCOPES, OIDCClaimsMapping

logger = logging.getLogger(__name__)


class OIDCResponseType(Enum):
    """OIDC response types."""

    CODE = "code"
    ID_TOKEN = "id_token"
    TOKEN = "token"
    CODE_ID_TOKEN = "code id_token"
    CODE_TOKEN = "code token"
    ID_TOKEN_TOKEN = "id_token token"
    CODE_ID_TOKEN_TOKEN = "code id_token token"


class OIDCFlow(Enum):
    """OIDC authentication flows."""

    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    HYBRID = "hybrid"


@dataclass
class OIDCValidationResult:
    """
    Result of OIDC validation.

    Attributes:
        is_valid: Whether the validation passed
        is_oidc_request: Whether this is an OIDC request (has 'openid' scope)
        flow_type: The detected OIDC flow type
        validated_scopes: List of valid OIDC scopes
        invalid_scopes: List of invalid scopes
        required_claims: Set of claims required for the validated scopes
        errors: List of validation error messages
        warnings: List of validation warning messages
    """

    is_valid: bool
    is_oidc_request: bool
    flow_type: OIDCFlow | None
    validated_scopes: list[str]
    invalid_scopes: list[str]
    required_claims: set[str]
    errors: list[str]
    warnings: list[str]


class OIDCValidator:
    """
    OpenID Connect validation utilities.

    Provides comprehensive validation for OIDC requests including scopes,
    response types, and flow validation.
    """

    @staticmethod
    def validate_oidc_scopes(requested_scopes: list[str]) -> OIDCValidationResult:
        """
        Validate OIDC scopes and determine flow type.

        Args:
            requested_scopes: List of requested scope names

        Returns:
            OIDCValidationResult with validation details
        """
        errors = []
        warnings = []
        validated_scopes = []
        invalid_scopes = []

        # Check if this is an OIDC request
        is_oidc_request = OIDCClaimsMapping.is_oidc_request(requested_scopes)

        if not is_oidc_request and requested_scopes:
            # Not an OIDC request, but still validate any OIDC scopes
            warnings.append("Request does not include 'openid' scope - not an OIDC request")

        # Validate each scope
        for scope in requested_scopes:
            if scope in OIDC_SCOPES:
                validated_scopes.append(scope)
            else:
                # Check if it's a valid OAuth 2.1 scope (not OIDC)
                if scope not in [
                    "read",
                    "write",
                    "admin:clients:read",
                    "admin:clients:write",
                    "admin:scopes:read",
                    "admin:scopes:write",
                    "admin:users:read",
                    "admin:system:read",
                ]:
                    invalid_scopes.append(scope)
                    warnings.append(f"Scope '{scope}' is not a standard OIDC scope")

        # Validate required scopes for OIDC
        if is_oidc_request:
            required_scopes = OIDCClaimsMapping.get_required_scopes()
            missing_required = set(required_scopes) - set(validated_scopes)
            if missing_required:
                errors.append(f"Missing required OIDC scopes: {', '.join(missing_required)}")

        # Determine flow type (simplified - based on scopes for now)
        flow_type = None
        if is_oidc_request:
            flow_type = OIDCFlow.AUTHORIZATION_CODE  # Default for scope-based detection

        # Get required claims
        required_claims = OIDCClaimsMapping.get_claims_for_scopes(validated_scopes)

        is_valid = len(errors) == 0

        return OIDCValidationResult(
            is_valid=is_valid,
            is_oidc_request=is_oidc_request,
            flow_type=flow_type,
            validated_scopes=validated_scopes,
            invalid_scopes=invalid_scopes,
            required_claims=required_claims,
            errors=errors,
            warnings=warnings,
        )

    @staticmethod
    def validate_response_type(response_type: str) -> tuple[bool, OIDCFlow | None, list[str]]:
        """
        Validate OIDC response type and determine flow.

        Args:
            response_type: Space-separated response type values

        Returns:
            Tuple of (is_valid, flow_type, errors)
        """
        errors = []

        # Parse response type
        response_type.split()

        # Validate response type combinations
        if response_type == OIDCResponseType.CODE.value:
            flow_type = OIDCFlow.AUTHORIZATION_CODE
        elif response_type == OIDCResponseType.ID_TOKEN.value or response_type == OIDCResponseType.ID_TOKEN_TOKEN.value:
            flow_type = OIDCFlow.IMPLICIT
        elif response_type in [
            OIDCResponseType.CODE_ID_TOKEN.value,
            OIDCResponseType.CODE_TOKEN.value,
            OIDCResponseType.CODE_ID_TOKEN_TOKEN.value,
        ]:
            flow_type = OIDCFlow.HYBRID
        else:
            errors.append(f"Unsupported response type: {response_type}")
            flow_type = None

        is_valid = len(errors) == 0
        return is_valid, flow_type, errors

    @staticmethod
    def validate_nonce(nonce: str | None, response_type: str, config: AuthlyConfig) -> list[str]:
        """
        Validate nonce parameter for OIDC requests.

        Args:
            nonce: Nonce value from request
            response_type: Response type from request
            config: Configuration object

        Returns:
            List of validation errors
        """
        errors = []

        # Nonce is required for implicit and hybrid flows
        response_types = response_type.split()
        requires_nonce = any(rt in response_types for rt in ["id_token", "token"])

        if requires_nonce and not nonce:
            errors.append("Nonce parameter is required for implicit and hybrid flows")

        if nonce and len(nonce) > config.nonce_max_length:
            errors.append(f"Nonce parameter is too long (max {config.nonce_max_length} characters)")

        return errors

    @staticmethod
    def validate_oidc_request_parameters(
        scopes: list[str],
        response_type: str,
        config: AuthlyConfig,
        nonce: str | None = None,
        max_age: int | None = None,
        claims: str | None = None,
    ) -> OIDCValidationResult:
        """
        Comprehensive validation of OIDC request parameters.

        Args:
            scopes: List of requested scopes
            response_type: OIDC response type
            config: Configuration object
            nonce: Nonce value (optional)
            max_age: Maximum authentication age (optional)
            claims: Claims parameter (optional)

        Returns:
            OIDCValidationResult with comprehensive validation
        """
        # Start with scope validation
        scope_result = OIDCValidator.validate_oidc_scopes(scopes)

        # Validate response type
        rt_valid, flow_type, rt_errors = OIDCValidator.validate_response_type(response_type)
        scope_result.errors.extend(rt_errors)

        # Update flow type from response type validation
        if flow_type:
            scope_result.flow_type = flow_type

        # Validate nonce
        nonce_errors = OIDCValidator.validate_nonce(nonce, response_type, config)
        scope_result.errors.extend(nonce_errors)

        # Validate max_age
        if max_age is not None:
            if max_age < 0:
                scope_result.errors.append("max_age parameter must be non-negative")
            elif max_age > 86400:  # 24 hours
                scope_result.warnings.append("max_age parameter is very large (>24 hours)")

        # Validate claims parameter (if provided)
        if claims:
            try:
                import json

                claims_obj = json.loads(claims)
                if not isinstance(claims_obj, dict):
                    scope_result.errors.append("claims parameter must be a JSON object")
            except json.JSONDecodeError:
                scope_result.errors.append("claims parameter must be valid JSON")

        # Update validity based on all validations
        scope_result.is_valid = len(scope_result.errors) == 0

        return scope_result


class OIDCScopeProcessor:
    """
    OpenID Connect scope processing utilities.

    Handles scope registration, retrieval, and integration with the
    existing OAuth 2.1 scope system.
    """

    @staticmethod
    def get_oidc_scope_registration_data() -> list[dict[str, any]]:
        """
        Get OIDC scope data for registration in the database.

        Returns:
            List of scope data dictionaries for database registration
        """
        scope_data = []

        for scope_name, scope_def in OIDC_SCOPES.items():
            scope_data.append(
                {
                    "scope_name": scope_name,
                    "description": scope_def.description,
                    "is_default": scope_def.default,
                    "is_active": True,
                    "scope_type": "oidc",  # Add type to distinguish from OAuth scopes
                    "claims": list(scope_def.claims),  # Store claims for reference
                    "required": scope_def.required,
                }
            )

        return scope_data

    @staticmethod
    def merge_oauth_and_oidc_scopes(oauth_scopes: list[str], oidc_scopes: list[str]) -> list[str]:
        """
        Merge OAuth 2.1 and OIDC scopes into a single list.

        Args:
            oauth_scopes: List of OAuth 2.1 scope names
            oidc_scopes: List of OIDC scope names

        Returns:
            Combined list of unique scope names
        """
        all_scopes = set(oauth_scopes + oidc_scopes)
        return list(all_scopes)

    @staticmethod
    def separate_oauth_and_oidc_scopes(scopes: list[str]) -> tuple[list[str], list[str]]:
        """
        Separate mixed scopes into OAuth and OIDC scopes.

        Args:
            scopes: Mixed list of scope names

        Returns:
            Tuple of (oauth_scopes, oidc_scopes)
        """
        oauth_scopes = []
        oidc_scopes = []

        for scope in scopes:
            if scope in OIDC_SCOPES:
                oidc_scopes.append(scope)
            else:
                oauth_scopes.append(scope)

        return oauth_scopes, oidc_scopes

    @staticmethod
    def validate_scope_combination(scopes: list[str]) -> dict[str, any]:
        """
        Validate combination of OAuth and OIDC scopes.

        Args:
            scopes: List of mixed scope names

        Returns:
            Validation result dictionary
        """
        oauth_scopes, oidc_scopes = OIDCScopeProcessor.separate_oauth_and_oidc_scopes(scopes)

        # Validate OIDC scopes
        oidc_result = OIDCValidator.validate_oidc_scopes(oidc_scopes)

        # Simple validation for OAuth scopes (basic known scopes)
        known_oauth_scopes = {
            "read",
            "write",
            "admin:clients:read",
            "admin:clients:write",
            "admin:scopes:read",
            "admin:scopes:write",
            "admin:users:read",
            "admin:system:read",
        }

        valid_oauth_scopes = []
        invalid_oauth_scopes = []

        for scope in oauth_scopes:
            if scope in known_oauth_scopes:
                valid_oauth_scopes.append(scope)
            else:
                invalid_oauth_scopes.append(scope)

        # Combine invalid scopes from both OAuth and OIDC
        all_invalid_scopes = oidc_result.invalid_scopes + invalid_oauth_scopes

        # Combine errors and warnings
        all_errors = oidc_result.errors[:]
        all_warnings = oidc_result.warnings[:]

        if invalid_oauth_scopes:
            all_warnings.extend([f"Unknown OAuth scope: {scope}" for scope in invalid_oauth_scopes])

        return {
            "is_valid": oidc_result.is_valid and len(invalid_oauth_scopes) == 0,
            "is_oidc_request": oidc_result.is_oidc_request,
            "oauth_scopes": valid_oauth_scopes,
            "oidc_scopes": oidc_scopes,
            "validated_oidc_scopes": oidc_result.validated_scopes,
            "invalid_scopes": all_invalid_scopes,
            "required_claims": oidc_result.required_claims,
            "errors": all_errors,
            "warnings": all_warnings,
        }


# Utility functions for integration with existing OAuth system
def register_oidc_scopes_with_oauth_system():
    """
    Register OIDC scopes with the existing OAuth 2.1 scope system.

    This function provides the integration point between OIDC scopes
    and the existing OAuth scope management system.
    """
    return OIDCScopeProcessor.get_oidc_scope_registration_data()


def validate_mixed_scopes(scopes: list[str]) -> OIDCValidationResult:
    """
    Validate mixed OAuth and OIDC scopes.

    Args:
        scopes: List of mixed scope names

    Returns:
        OIDCValidationResult with validation details
    """
    oauth_scopes, oidc_scopes = OIDCScopeProcessor.separate_oauth_and_oidc_scopes(scopes)

    # For now, focus on OIDC validation
    # OAuth scope validation is handled by the existing OAuth system
    if oidc_scopes:
        return OIDCValidator.validate_oidc_scopes(oidc_scopes)
    else:
        # No OIDC scopes, return minimal result
        return OIDCValidationResult(
            is_valid=True,
            is_oidc_request=False,
            flow_type=None,
            validated_scopes=[],
            invalid_scopes=[],
            required_claims=set(),
            errors=[],
            warnings=[],
        )
