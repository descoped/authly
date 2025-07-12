"""
OpenID Connect UserInfo Endpoint Implementation.

This module implements the OIDC UserInfo endpoint according to the
OpenID Connect Core 1.0 specification. The UserInfo endpoint returns
user claims based on the access token and granted scopes.

Based on:
- OpenID Connect Core 1.0 Section 5.3
- RFC 6750 (OAuth 2.0 Bearer Token Usage)
"""

import logging
from typing import Dict, List, Optional, Set

from pydantic import BaseModel, Field

from authly.oidc.scopes import OIDCClaimsMapping
from authly.users.models import UserModel

logger = logging.getLogger(__name__)


class UserInfoResponse(BaseModel):
    """
    OIDC UserInfo response model.

    This model represents the response from the UserInfo endpoint,
    containing user claims filtered by the granted scopes.

    All fields are optional except 'sub' which is required by OIDC spec.
    """

    # Required claim - subject identifier
    sub: str = Field(..., description="Subject identifier")

    # Profile scope claims
    name: Optional[str] = Field(None, description="Full name")
    given_name: Optional[str] = Field(None, description="Given name (first name)")
    family_name: Optional[str] = Field(None, description="Family name (last name)")
    middle_name: Optional[str] = Field(None, description="Middle name")
    nickname: Optional[str] = Field(None, description="Nickname")
    preferred_username: Optional[str] = Field(None, description="Preferred username")
    profile: Optional[str] = Field(None, description="Profile page URL")
    picture: Optional[str] = Field(None, description="Profile picture URL")
    website: Optional[str] = Field(None, description="Website URL")
    gender: Optional[str] = Field(None, description="Gender")
    birthdate: Optional[str] = Field(None, description="Birthdate (YYYY-MM-DD)")
    zoneinfo: Optional[str] = Field(None, description="Time zone")
    locale: Optional[str] = Field(None, description="Locale")
    updated_at: Optional[int] = Field(None, description="Time the information was last updated")

    # Email scope claims
    email: Optional[str] = Field(None, description="Email address")
    email_verified: Optional[bool] = Field(None, description="Email verification status")

    # Phone scope claims
    phone_number: Optional[str] = Field(None, description="Phone number")
    phone_number_verified: Optional[bool] = Field(None, description="Phone number verification status")

    # Address scope claims
    address: Optional[Dict] = Field(None, description="Address information")


class UserInfoService:
    """
    Service for OIDC UserInfo endpoint operations.

    This service handles the business logic for generating UserInfo responses
    based on user data and granted scopes according to OIDC specifications.
    """

    def create_userinfo_response(self, user: UserModel, granted_scopes: List[str]) -> UserInfoResponse:
        """
        Create UserInfo response based on user data and granted scopes.

        Args:
            user: User model containing user data
            granted_scopes: List of scopes granted to the access token

        Returns:
            UserInfoResponse: User claims filtered by granted scopes
        """
        logger.debug(f"Creating UserInfo response for user {user.id} with scopes {granted_scopes}")

        # Always include subject identifier (required by OIDC)
        userinfo = UserInfoResponse(sub=str(user.id))

        # Filter and add claims based on granted scopes
        if "profile" in granted_scopes:
            self._add_profile_claims(userinfo, user)

        if "email" in granted_scopes:
            self._add_email_claims(userinfo, user)

        if "phone" in granted_scopes:
            self._add_phone_claims(userinfo, user)

        if "address" in granted_scopes:
            self._add_address_claims(userinfo, user)

        logger.info(f"Generated UserInfo response for user {user.id}")
        return userinfo

    def _add_profile_claims(self, userinfo: UserInfoResponse, user: UserModel) -> None:
        """Add profile-related claims to UserInfo response."""
        userinfo.name = self._get_full_name(user)
        userinfo.given_name = getattr(user, "given_name", None)
        userinfo.family_name = getattr(user, "family_name", None)
        userinfo.middle_name = getattr(user, "middle_name", None)
        userinfo.nickname = getattr(user, "nickname", None)
        userinfo.preferred_username = getattr(user, "preferred_username", None) or user.username
        userinfo.profile = getattr(user, "profile", None)
        userinfo.picture = getattr(user, "picture", None)
        userinfo.website = getattr(user, "website", None)
        userinfo.gender = getattr(user, "gender", None)
        userinfo.birthdate = getattr(user, "birthdate", None)
        userinfo.zoneinfo = getattr(user, "zoneinfo", None)
        userinfo.locale = getattr(user, "locale", None)

        # Updated at timestamp
        if hasattr(user, "updated_at") and user.updated_at:
            userinfo.updated_at = int(user.updated_at.timestamp())

    def _add_email_claims(self, userinfo: UserInfoResponse, user: UserModel) -> None:
        """Add email-related claims to UserInfo response."""
        userinfo.email = user.email
        userinfo.email_verified = user.is_verified

    def _add_phone_claims(self, userinfo: UserInfoResponse, user: UserModel) -> None:
        """Add phone-related claims to UserInfo response."""
        userinfo.phone_number = getattr(user, "phone_number", None)
        userinfo.phone_number_verified = getattr(user, "phone_number_verified", False)

    def _add_address_claims(self, userinfo: UserInfoResponse, user: UserModel) -> None:
        """Add address-related claims to UserInfo response."""
        userinfo.address = getattr(user, "address", None)

    def _get_full_name(self, user: UserModel) -> Optional[str]:
        """
        Generate full name from user data.

        Args:
            user: User model

        Returns:
            Full name string or None if no name components available
        """
        given_name = getattr(user, "given_name", None)
        family_name = getattr(user, "family_name", None)

        if given_name and family_name:
            return f"{given_name} {family_name}"
        elif given_name:
            return given_name
        elif family_name:
            return family_name
        else:
            # Fall back to username if no name components
            return user.username

    def validate_userinfo_request(self, granted_scopes: List[str]) -> bool:
        """
        Validate UserInfo request.

        Args:
            granted_scopes: List of granted scopes

        Returns:
            True if request is valid, False otherwise
        """
        # UserInfo endpoint requires the 'openid' scope
        if "openid" not in granted_scopes:
            logger.warning("UserInfo request without 'openid' scope")
            return False

        return True

    def get_supported_claims(self, granted_scopes: List[str]) -> Set[str]:
        """
        Get supported claims based on granted scopes.

        Args:
            granted_scopes: List of granted scopes

        Returns:
            Set of supported claim names
        """
        return OIDCClaimsMapping.get_claims_for_scopes(granted_scopes)
