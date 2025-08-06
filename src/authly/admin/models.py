"""
Admin Response Models for Authly.

This module provides specialized response models for admin operations,
including enhanced user information with admin-only fields and filtering capabilities.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AdminUserResponse(BaseModel):
    """
    Enhanced user response model for admin operations.

    This model includes all user fields including admin-only fields
    that are not exposed in regular user operations.
    """

    # Core user identity fields
    id: UUID
    username: str
    email: str
    created_at: datetime
    updated_at: datetime
    last_login: datetime | None = None

    # Administrative fields (admin-only)
    is_active: bool = True
    is_verified: bool = False
    is_admin: bool = False
    requires_password_change: bool = False

    # OIDC Standard Claims - Profile scope
    given_name: str | None = Field(None, description="OIDC: Given name (first name)")
    family_name: str | None = Field(None, description="OIDC: Family name (last name)")
    middle_name: str | None = Field(None, description="OIDC: Middle name")
    nickname: str | None = Field(None, description="OIDC: Casual name")
    preferred_username: str | None = Field(None, description="OIDC: Preferred username for display")
    profile: str | None = Field(None, description="OIDC: Profile page URL")
    picture: str | None = Field(None, description="OIDC: Profile picture URL")
    website: str | None = Field(None, description="OIDC: Personal website URL")
    gender: str | None = Field(None, description="OIDC: Gender")
    birthdate: str | None = Field(None, description="OIDC: Birthdate in YYYY-MM-DD format")
    zoneinfo: str | None = Field(None, description="OIDC: Time zone identifier")
    locale: str | None = Field(None, description="OIDC: Preferred locale")

    # OIDC Standard Claims - Phone scope
    phone_number: str | None = Field(None, description="OIDC: Phone number")
    phone_number_verified: bool | None = Field(None, description="OIDC: Phone verification status")

    # OIDC Standard Claims - Address scope
    address: dict[str, Any] | None = Field(None, description="OIDC: Structured address claim")

    # Admin-specific metadata
    active_sessions: int | None = Field(None, description="Number of active sessions for this user")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "john.doe",
                "email": "john.doe@example.com",
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
                "last_login": "2023-01-01T12:00:00Z",
                "is_active": True,
                "is_verified": True,
                "is_admin": False,
                "requires_password_change": False,
                "given_name": "John",
                "family_name": "Doe",
                "middle_name": "William",
                "nickname": "Johnny",
                "preferred_username": "john_doe",
                "profile": "https://example.com/john.doe",
                "picture": "https://example.com/john.doe/picture.jpg",
                "website": "https://johndoe.com",
                "gender": "male",
                "birthdate": "1990-01-01",
                "zoneinfo": "America/New_York",
                "locale": "en-US",
                "phone_number": "+1-555-123-4567",
                "phone_number_verified": True,
                "address": {
                    "formatted": "1234 Main St\nAnytown, ST 12345\nUSA",
                    "street_address": "1234 Main St",
                    "locality": "Anytown",
                    "region": "ST",
                    "postal_code": "12345",
                    "country": "USA",
                },
            }
        }


class AdminUserListResponse(BaseModel):
    """
    Paginated list response for admin user operations.

    This model provides structured pagination information along with
    the list of users for admin interfaces.
    """

    users: list[AdminUserResponse] = Field(..., description="List of users")
    total_count: int = Field(..., description="Total number of users matching criteria")
    page_info: dict[str, Any] = Field(..., description="Pagination information")
    filters_applied: dict[str, Any] | None = Field(None, description="Applied filters")

    class Config:
        json_schema_extra = {
            "example": {
                "users": [
                    {
                        "id": "123e4567-e89b-12d3-a456-426614174000",
                        "username": "john.doe",
                        "email": "john.doe@example.com",
                        "created_at": "2023-01-01T00:00:00Z",
                        "updated_at": "2023-01-01T00:00:00Z",
                        "is_active": True,
                        "is_verified": True,
                        "is_admin": False,
                    }
                ],
                "total_count": 150,
                "page_info": {
                    "skip": 0,
                    "limit": 25,
                    "has_next": True,
                    "has_previous": False,
                    "current_page": 1,
                    "total_pages": 6,
                },
                "filters_applied": {"is_active": True, "is_verified": None},
            }
        }


class AdminUserFilters(BaseModel):
    """
    Filter model for admin user queries.

    This model defines the available filters that administrators
    can use when querying user lists.
    """

    # Text search filters
    username: str | None = Field(None, description="Filter by username (partial match)")
    email: str | None = Field(None, description="Filter by email (partial match)")
    given_name: str | None = Field(None, description="Filter by given name (partial match)")
    family_name: str | None = Field(None, description="Filter by family name (partial match)")

    # Boolean status filters
    is_active: bool | None = Field(None, description="Filter by active status")
    is_verified: bool | None = Field(None, description="Filter by verification status")
    is_admin: bool | None = Field(None, description="Filter by admin status")
    requires_password_change: bool | None = Field(None, description="Filter by password change requirement")

    # Date range filters
    created_after: datetime | None = Field(None, description="Filter users created after this date")
    created_before: datetime | None = Field(None, description="Filter users created before this date")
    last_login_after: datetime | None = Field(None, description="Filter users with last login after this date")
    last_login_before: datetime | None = Field(None, description="Filter users with last login before this date")

    # OIDC profile filters
    locale: str | None = Field(None, description="Filter by locale")
    zoneinfo: str | None = Field(None, description="Filter by timezone")

    class Config:
        json_schema_extra = {
            "example": {
                "username": "john",
                "email": "@example.com",
                "is_active": True,
                "is_verified": None,
                "is_admin": False,
                "created_after": "2023-01-01T00:00:00Z",
                "created_before": "2023-12-31T23:59:59Z",
                "locale": "en-US",
            }
        }


class AdminUserCreateRequest(BaseModel):
    """
    Enhanced user creation request for admin operations.

    This model allows administrators to create users with
    additional fields not available to regular user registration.
    """

    # Required fields
    username: str = Field(..., min_length=3, max_length=32, description="Unique username")
    email: str = Field(..., description="Unique email address")
    password: str | None = Field(
        None, min_length=8, description="User password (leave empty to generate temporary password)"
    )

    # Password generation option
    generate_temp_password: bool = Field(
        False, description="Generate secure temporary password and force password change"
    )

    # Admin-controllable fields
    is_active: bool = Field(True, description="Account active status")
    is_verified: bool = Field(False, description="Email verification status")
    is_admin: bool = Field(False, description="Admin privileges flag")
    requires_password_change: bool = Field(False, description="Force password change on next login")

    # OIDC Profile fields (optional)
    given_name: str | None = Field(None, description="Given name (first name)")
    family_name: str | None = Field(None, description="Family name (last name)")
    middle_name: str | None = Field(None, description="Middle name")
    nickname: str | None = Field(None, description="Casual name")
    preferred_username: str | None = Field(None, description="Preferred display username")
    profile: str | None = Field(None, description="Profile page URL")
    picture: str | None = Field(None, description="Profile picture URL")
    website: str | None = Field(None, description="Personal website URL")
    gender: str | None = Field(None, description="Gender")
    birthdate: str | None = Field(None, description="Birthdate in YYYY-MM-DD format")
    zoneinfo: str | None = Field(None, description="Time zone identifier")
    locale: str | None = Field(None, description="Preferred locale")
    phone_number: str | None = Field(None, description="Phone number")
    phone_number_verified: bool | None = Field(None, description="Phone verification status")
    address: dict[str, Any] | None = Field(None, description="Structured address")


class AdminSessionResponse(BaseModel):
    """
    Session information response for admin operations.

    This model provides detailed session information including
    token details, client information, and activity data.
    """

    # Session identification
    session_id: UUID = Field(..., description="Unique session identifier (token ID)")
    token_jti: str = Field(..., description="JWT token identifier")
    token_type: str = Field(..., description="Token type (access/refresh)")

    # Session metadata
    created_at: datetime = Field(..., description="Session creation timestamp")
    expires_at: datetime = Field(..., description="Session expiration timestamp")
    last_activity: datetime = Field(..., description="Last activity timestamp")
    is_active: bool = Field(..., description="Whether session is currently active")

    # Client and scope information
    client_id: UUID | None = Field(None, description="OAuth client ID")
    scope: str | None = Field(None, description="Granted scopes")

    # Security information
    is_expired: bool = Field(..., description="Whether session is expired")
    is_invalidated: bool = Field(..., description="Whether session was invalidated")
    invalidated_at: datetime | None = Field(None, description="When session was invalidated")

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": "123e4567-e89b-12d3-a456-426614174000",
                "token_jti": "abc123def456ghi789",
                "token_type": "access",
                "created_at": "2023-01-01T00:00:00Z",
                "expires_at": "2023-01-01T01:00:00Z",
                "last_activity": "2023-01-01T00:30:00Z",
                "is_active": True,
                "client_id": "456e7890-e12b-34d5-a678-901234567890",
                "scope": "openid profile email",
                "is_expired": False,
                "is_invalidated": False,
                "invalidated_at": None,
            }
        }


class AdminSessionListResponse(BaseModel):
    """
    Paginated list response for admin session operations.

    This model provides structured pagination information along with
    the list of sessions for admin interfaces.
    """

    sessions: list[AdminSessionResponse] = Field(..., description="List of user sessions")
    total_count: int = Field(..., description="Total number of sessions for the user")
    active_count: int = Field(..., description="Number of currently active sessions")
    page_info: dict[str, Any] = Field(..., description="Pagination information")

    class Config:
        json_schema_extra = {
            "example": {
                "sessions": [
                    {
                        "session_id": "123e4567-e89b-12d3-a456-426614174000",
                        "token_jti": "abc123def456ghi789",
                        "token_type": "access",
                        "created_at": "2023-01-01T00:00:00Z",
                        "expires_at": "2023-01-01T01:00:00Z",
                        "last_activity": "2023-01-01T00:30:00Z",
                        "is_active": True,
                        "is_expired": False,
                        "is_invalidated": False,
                    }
                ],
                "total_count": 15,
                "active_count": 3,
                "page_info": {
                    "skip": 0,
                    "limit": 25,
                    "has_next": False,
                    "has_previous": False,
                    "current_page": 1,
                    "total_pages": 1,
                },
            }
        }


class AdminUserCreateResponse(AdminUserResponse):
    """
    Enhanced user creation response for admin operations.

    Extends AdminUserResponse to include temporary password when generated.
    """

    temporary_password: str | None = Field(
        None, description="Generated temporary password (only included when generated)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "john.doe",
                "email": "john.doe@example.com",
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
                "is_active": True,
                "is_verified": False,
                "is_admin": False,
                "requires_password_change": True,
                "temporary_password": "TempPass123!",
                "active_sessions": 0,
            }
        }


class AdminUserUpdateRequest(BaseModel):
    """
    Enhanced user update request for admin operations.

    This model allows administrators to update any user field
    including admin-only fields.
    """

    # Identity fields
    username: str | None = Field(None, min_length=3, max_length=32, description="Username")
    email: str | None = Field(None, description="Email address")
    password: str | None = Field(None, min_length=8, description="New password")

    # Admin-controllable fields
    is_active: bool | None = Field(None, description="Account active status")
    is_verified: bool | None = Field(None, description="Email verification status")
    is_admin: bool | None = Field(None, description="Admin privileges flag")
    requires_password_change: bool | None = Field(None, description="Force password change flag")

    # OIDC Profile fields
    given_name: str | None = Field(None, description="Given name")
    family_name: str | None = Field(None, description="Family name")
    middle_name: str | None = Field(None, description="Middle name")
    nickname: str | None = Field(None, description="Casual name")
    preferred_username: str | None = Field(None, description="Preferred display username")
    profile: str | None = Field(None, description="Profile page URL")
    picture: str | None = Field(None, description="Profile picture URL")
    website: str | None = Field(None, description="Personal website URL")
    gender: str | None = Field(None, description="Gender")
    birthdate: str | None = Field(None, description="Birthdate")
    zoneinfo: str | None = Field(None, description="Time zone")
    locale: str | None = Field(None, description="Preferred locale")
    phone_number: str | None = Field(None, description="Phone number")
    phone_number_verified: bool | None = Field(None, description="Phone verification status")
    address: dict[str, Any] | None = Field(None, description="Structured address")


class AdminSessionResponse(BaseModel):
    """
    Session information response for admin operations.

    This model provides detailed session information including
    token details, client information, and activity data.
    """

    # Session identification
    session_id: UUID = Field(..., description="Unique session identifier (token ID)")
    token_jti: str = Field(..., description="JWT token identifier")
    token_type: str = Field(..., description="Token type (access/refresh)")

    # Session metadata
    created_at: datetime = Field(..., description="Session creation timestamp")
    expires_at: datetime = Field(..., description="Session expiration timestamp")
    last_activity: datetime = Field(..., description="Last activity timestamp")
    is_active: bool = Field(..., description="Whether session is currently active")

    # Client and scope information
    client_id: UUID | None = Field(None, description="OAuth client ID")
    scope: str | None = Field(None, description="Granted scopes")

    # Security information
    is_expired: bool = Field(..., description="Whether session is expired")
    is_invalidated: bool = Field(..., description="Whether session was invalidated")
    invalidated_at: datetime | None = Field(None, description="When session was invalidated")

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": "123e4567-e89b-12d3-a456-426614174000",
                "token_jti": "abc123def456ghi789",
                "token_type": "access",
                "created_at": "2023-01-01T00:00:00Z",
                "expires_at": "2023-01-01T01:00:00Z",
                "last_activity": "2023-01-01T00:30:00Z",
                "is_active": True,
                "client_id": "456e7890-e12b-34d5-a678-901234567890",
                "scope": "openid profile email",
                "is_expired": False,
                "is_invalidated": False,
                "invalidated_at": None,
            }
        }
