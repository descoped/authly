"""
OpenID Connect (OIDC) 1.0 Scopes and Claims System.

This module defines the standard OIDC scopes and their associated claims
according to the OpenID Connect Core 1.0 specification.

Standard OIDC Scopes:
- openid: Required for OIDC flows, provides 'sub' claim
- profile: User profile information (name, family_name, given_name, etc.)
- email: Email address and verification status
- address: Physical mailing address
- phone: Phone number and verification status

Claims Mapping:
Each scope maps to specific claims that will be included in ID tokens
and available via the UserInfo endpoint.
"""

from dataclasses import dataclass
from enum import Enum


class OIDCScope(Enum):
    """Standard OpenID Connect scope identifiers."""

    OPENID = "openid"
    PROFILE = "profile"
    EMAIL = "email"
    ADDRESS = "address"
    PHONE = "phone"


@dataclass
class OIDCScopeDefinition:
    """
    Definition of an OIDC scope with its associated claims.

    Attributes:
        scope_name: The scope identifier (e.g., "openid", "profile")
        description: Human-readable description of the scope
        claims: Set of claims that this scope provides access to
        required: Whether this scope is required for OIDC flows
        default: Whether this scope should be granted by default
    """

    scope_name: str
    description: str
    claims: set[str]
    required: bool = False
    default: bool = False


# Standard OIDC Claims according to OpenID Connect Core 1.0 specification
# https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims


class OIDCStandardClaims:
    """Standard OpenID Connect claims definitions."""

    # Essential claims (always available)
    SUB = "sub"  # Subject identifier
    ISS = "iss"  # Issuer identifier
    AUD = "aud"  # Audience
    EXP = "exp"  # Expiration time
    IAT = "iat"  # Issued at time

    # Profile scope claims
    NAME = "name"
    FAMILY_NAME = "family_name"
    GIVEN_NAME = "given_name"
    MIDDLE_NAME = "middle_name"
    NICKNAME = "nickname"
    PREFERRED_USERNAME = "preferred_username"
    PROFILE = "profile"
    PICTURE = "picture"
    WEBSITE = "website"
    GENDER = "gender"
    BIRTHDATE = "birthdate"
    ZONEINFO = "zoneinfo"
    LOCALE = "locale"
    UPDATED_AT = "updated_at"

    # Email scope claims
    EMAIL = "email"
    EMAIL_VERIFIED = "email_verified"

    # Address scope claims
    ADDRESS = "address"

    # Phone scope claims
    PHONE_NUMBER = "phone_number"
    PHONE_NUMBER_VERIFIED = "phone_number_verified"


# OIDC Scope to Claims Mapping
OIDC_SCOPES: dict[str, OIDCScopeDefinition] = {
    OIDCScope.OPENID.value: OIDCScopeDefinition(
        scope_name="openid",
        description="OpenID Connect authentication scope (required for OIDC flows)",
        claims={
            OIDCStandardClaims.SUB,
            OIDCStandardClaims.ISS,
            OIDCStandardClaims.AUD,
            OIDCStandardClaims.EXP,
            OIDCStandardClaims.IAT,
        },
        required=True,
        default=False,  # Must be explicitly requested
    ),
    OIDCScope.PROFILE.value: OIDCScopeDefinition(
        scope_name="profile",
        description="Access to user profile information (name, username, picture, etc.)",
        claims={
            OIDCStandardClaims.NAME,
            OIDCStandardClaims.FAMILY_NAME,
            OIDCStandardClaims.GIVEN_NAME,
            OIDCStandardClaims.MIDDLE_NAME,
            OIDCStandardClaims.NICKNAME,
            OIDCStandardClaims.PREFERRED_USERNAME,
            OIDCStandardClaims.PROFILE,
            OIDCStandardClaims.PICTURE,
            OIDCStandardClaims.WEBSITE,
            OIDCStandardClaims.GENDER,
            OIDCStandardClaims.BIRTHDATE,
            OIDCStandardClaims.ZONEINFO,
            OIDCStandardClaims.LOCALE,
            OIDCStandardClaims.UPDATED_AT,
        },
        required=False,
        default=False,
    ),
    OIDCScope.EMAIL.value: OIDCScopeDefinition(
        scope_name="email",
        description="Access to user email address and verification status",
        claims={
            OIDCStandardClaims.EMAIL,
            OIDCStandardClaims.EMAIL_VERIFIED,
        },
        required=False,
        default=False,
    ),
    OIDCScope.ADDRESS.value: OIDCScopeDefinition(
        scope_name="address",
        description="Access to user physical mailing address",
        claims={
            OIDCStandardClaims.ADDRESS,
        },
        required=False,
        default=False,
    ),
    OIDCScope.PHONE.value: OIDCScopeDefinition(
        scope_name="phone",
        description="Access to user phone number and verification status",
        claims={
            OIDCStandardClaims.PHONE_NUMBER,
            OIDCStandardClaims.PHONE_NUMBER_VERIFIED,
        },
        required=False,
        default=False,
    ),
}


class OIDCClaimsMapping:
    """
    OpenID Connect claims mapping and validation utilities.

    This class provides methods to map scopes to claims, validate
    scope requests, and extract claims for ID tokens and UserInfo responses.
    """

    @staticmethod
    def get_claims_for_scopes(scopes: list[str]) -> set[str]:
        """
        Get all claims that should be included for the given scopes.

        Args:
            scopes: List of requested scope names

        Returns:
            Set of claim names that should be included
        """
        claims = set()

        for scope in scopes:
            if scope in OIDC_SCOPES:
                claims.update(OIDC_SCOPES[scope].claims)

        return claims

    @staticmethod
    def validate_oidc_scopes(scopes: list[str]) -> dict[str, bool]:
        """
        Validate OIDC scopes and return validation results.

        Args:
            scopes: List of scope names to validate

        Returns:
            Dictionary mapping scope names to validation results
        """
        validation_results = {}

        for scope in scopes:
            validation_results[scope] = scope in OIDC_SCOPES

        return validation_results

    @staticmethod
    def is_oidc_request(scopes: list[str]) -> bool:
        """
        Check if a scope request is an OpenID Connect request.

        An OIDC request must include the 'openid' scope.

        Args:
            scopes: List of requested scope names

        Returns:
            True if this is an OIDC request (contains 'openid' scope)
        """
        return OIDCScope.OPENID.value in scopes

    @staticmethod
    def get_required_scopes() -> list[str]:
        """
        Get list of required OIDC scopes.

        Returns:
            List of scope names that are required for OIDC flows
        """
        return [scope_def.scope_name for scope_def in OIDC_SCOPES.values() if scope_def.required]

    @staticmethod
    def get_default_scopes() -> list[str]:
        """
        Get list of default OIDC scopes.

        Returns:
            List of scope names that are granted by default
        """
        return [scope_def.scope_name for scope_def in OIDC_SCOPES.values() if scope_def.default]

    @staticmethod
    def get_scope_description(scope_name: str) -> str | None:
        """
        Get description for a specific OIDC scope.

        Args:
            scope_name: Name of the scope

        Returns:
            Description of the scope, or None if not found
        """
        scope_def = OIDC_SCOPES.get(scope_name)
        return scope_def.description if scope_def else None

    @staticmethod
    def get_claims_for_scope(scope_name: str) -> set[str]:
        """
        Get claims associated with a specific scope.

        Args:
            scope_name: Name of the scope

        Returns:
            Set of claim names for the scope
        """
        scope_def = OIDC_SCOPES.get(scope_name)
        return scope_def.claims if scope_def else set()

    @staticmethod
    def filter_claims_by_scopes(claims: dict[str, any], scopes: list[str]) -> dict[str, any]:
        """
        Filter claims based on granted scopes.

        Args:
            claims: Dictionary of all available claims
            scopes: List of granted scope names

        Returns:
            Dictionary of claims filtered by scopes
        """
        allowed_claims = OIDCClaimsMapping.get_claims_for_scopes(scopes)

        return {claim_name: claim_value for claim_name, claim_value in claims.items() if claim_name in allowed_claims}


def get_oidc_scopes_with_descriptions() -> dict[str, str]:
    """
    Get OIDC scopes with their descriptions.

    Returns:
        Dictionary mapping scope names to descriptions
    """
    return {scope_name: scope_def.description for scope_name, scope_def in OIDC_SCOPES.items()}


def get_all_oidc_scope_names() -> list[str]:
    """
    Get all OIDC scope names.

    Returns:
        List of all OIDC scope names
    """
    return list(OIDC_SCOPES.keys())


def get_oidc_claims_reference() -> dict[str, dict[str, any]]:
    """
    Get comprehensive OIDC claims reference.

    Returns:
        Dictionary with detailed information about each scope and its claims
    """
    reference = {}

    for scope_name, scope_def in OIDC_SCOPES.items():
        reference[scope_name] = {
            "description": scope_def.description,
            "claims": list(scope_def.claims),
            "required": scope_def.required,
            "default": scope_def.default,
        }

    return reference


# Example usage and validation
if __name__ == "__main__":
    # Example: Get claims for profile and email scopes
    scopes = ["openid", "profile", "email"]
    claims = OIDCClaimsMapping.get_claims_for_scopes(scopes)
    print(f"Claims for scopes {scopes}: {claims}")

    # Example: Check if request is OIDC
    is_oidc = OIDCClaimsMapping.is_oidc_request(scopes)
    print(f"Is OIDC request: {is_oidc}")

    # Example: Get scope descriptions
    descriptions = get_oidc_scopes_with_descriptions()
    print(f"OIDC scopes: {descriptions}")
