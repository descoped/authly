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
    name: str | None = Field(None, description="Full name")
    given_name: str | None = Field(None, description="Given name (first name)")
    family_name: str | None = Field(None, description="Family name (last name)")
    middle_name: str | None = Field(None, description="Middle name")
    nickname: str | None = Field(None, description="Nickname")
    preferred_username: str | None = Field(None, description="Preferred username")
    profile: str | None = Field(None, description="Profile page URL")
    picture: str | None = Field(None, description="Profile picture URL")
    website: str | None = Field(None, description="Website URL")
    gender: str | None = Field(None, description="Gender")
    birthdate: str | None = Field(None, description="Birthdate (YYYY-MM-DD)")
    zoneinfo: str | None = Field(None, description="Time zone")
    locale: str | None = Field(None, description="Locale")
    updated_at: int | None = Field(None, description="Time the information was last updated")

    # Email scope claims
    email: str | None = Field(None, description="Email address")
    email_verified: bool | None = Field(None, description="Email verification status")

    # Phone scope claims
    phone_number: str | None = Field(None, description="Phone number")
    phone_number_verified: bool | None = Field(None, description="Phone number verification status")

    # Address scope claims
    address: dict | None = Field(None, description="Address information")


class UserInfoUpdateRequest(BaseModel):
    """
    OIDC UserInfo update request model.

    This model represents the request body for updating user information
    via the UserInfo endpoint. Only OIDC standard claims are allowed.
    """

    # Profile scope claims (updatable by user)
    name: str | None = Field(None, description="Full name")
    given_name: str | None = Field(None, description="Given name (first name)")
    family_name: str | None = Field(None, description="Family name (last name)")
    middle_name: str | None = Field(None, description="Middle name")
    nickname: str | None = Field(None, description="Nickname")
    preferred_username: str | None = Field(None, description="Preferred username")
    profile: str | None = Field(None, description="Profile page URL")
    picture: str | None = Field(None, description="Profile picture URL")
    website: str | None = Field(None, description="Website URL")
    gender: str | None = Field(None, description="Gender")
    birthdate: str | None = Field(None, description="Birthdate (YYYY-MM-DD)")
    zoneinfo: str | None = Field(None, description="Time zone")
    locale: str | None = Field(None, description="Locale")

    # Phone scope claims (updatable by user)
    phone_number: str | None = Field(None, description="Phone number")

    # Address scope claims (updatable by user)
    address: dict | None = Field(None, description="Address information")

    # NOTE: email, email_verified, phone_number_verified are NOT updatable by users
    # for security reasons - these require admin or verification processes


class UserInfoService:
    """
    Service for OIDC UserInfo endpoint operations.

    This service handles the business logic for generating UserInfo responses
    based on user data and granted scopes according to OIDC specifications.
    """

    def create_userinfo_response(self, user: UserModel, granted_scopes: list[str]) -> UserInfoResponse:
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

    def _get_full_name(self, user: UserModel) -> str | None:
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

    def validate_userinfo_request(self, granted_scopes: list[str]) -> bool:
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

    def get_supported_claims(self, granted_scopes: list[str]) -> set[str]:
        """
        Get supported claims based on granted scopes.

        Args:
            granted_scopes: List of granted scopes

        Returns:
            Set of supported claim names
        """
        return OIDCClaimsMapping.get_claims_for_scopes(granted_scopes)

    def validate_userinfo_update_request(
        self, granted_scopes: list[str], update_request: "UserInfoUpdateRequest"
    ) -> dict[str, str]:
        """
        Validate UserInfo update request and return only allowed fields.

        Args:
            granted_scopes: List of granted scopes
            update_request: Update request containing new values

        Returns:
            Dict of validated update fields based on scopes
        """
        # UserInfo update requires the 'openid' scope
        if "openid" not in granted_scopes:
            logger.warning("UserInfo update request without 'openid' scope")
            raise ValueError("UserInfo update requires 'openid' scope")

        # Get allowed claims based on scopes
        allowed_claims = self.get_supported_claims(granted_scopes)

        # Extract only the allowed fields from the update request
        update_data = {}
        for field, value in update_request.model_dump(exclude_unset=True).items():
            if value is not None and field in allowed_claims:
                update_data[field] = value
            elif value is not None:
                logger.warning(f"Attempted to update claim '{field}' without required scope")

        logger.info(f"UserInfo update validated: {len(update_data)} fields allowed")
        return update_data
