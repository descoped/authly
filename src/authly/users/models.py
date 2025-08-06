from datetime import date, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class UserModel(BaseModel):
    # Core user identity fields
    id: UUID
    username: str
    email: str
    password_hash: str
    created_at: datetime
    updated_at: datetime
    last_login: datetime | None = None
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
    zoneinfo: str | None = Field(None, description="OIDC: Time zone identifier (e.g., America/New_York)")
    locale: str | None = Field(None, description="OIDC: Preferred locale (e.g., en-US)")

    # OIDC Standard Claims - Phone scope
    phone_number: str | None = Field(None, description="OIDC: Phone number")
    phone_number_verified: bool | None = Field(None, description="OIDC: Phone number verification status")

    # OIDC Standard Claims - Address scope (structured claim)
    address: dict[str, Any] | None = Field(None, description="OIDC: Structured address claim")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "john.doe",
                "email": "john.doe@example.com",
                "password_hash": "$2b$12$...",
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
                "last_login": "2023-01-01T00:00:00Z",
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

    @field_validator("birthdate", mode="before")
    @classmethod
    def validate_birthdate(cls, v: str | date | None) -> str | None:
        """
        Convert birthdate to OIDC-compliant string format.

        Accepts:
        - None (returns None)
        - String in YYYY-MM-DD format (returns as-is)
        - Python date object (converts to YYYY-MM-DD string)

        Returns:
        - None or string in YYYY-MM-DD format
        """
        if v is None:
            return None
        if isinstance(v, str):
            return v
        if isinstance(v, date):
            return v.strftime("%Y-%m-%d")
        # If it's neither string nor date, let Pydantic handle the validation error
        return v
