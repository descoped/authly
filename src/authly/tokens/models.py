from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"


class TokenModel(BaseModel):
    """Model representing a token in the system"""

    id: UUID
    user_id: UUID
    token_jti: str = Field(..., min_length=32, max_length=64)  # JWT ID from token
    token_type: TokenType
    token_value: str  # The actual JWT token value
    invalidated: bool = False
    invalidated_at: Optional[datetime] = None
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # OAuth 2.1 fields (matches database schema)
    client_id: Optional[UUID] = None  # For OAuth flows
    scope: Optional[str] = None  # Space-separated scopes


class TokenPairResponse(BaseModel):
    """Response model for token pair creation (access + refresh tokens) with optional ID token for OIDC"""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int  # Access token expiration in seconds
    id_token: Optional[str] = None  # ID token for OpenID Connect flows
