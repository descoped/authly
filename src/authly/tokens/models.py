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
    created_by_ip: Optional[str] = None  # IP address that created the token
    user_agent: Optional[str] = None  # User agent that created the token

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "user_id": "123e4567-e89b-12d3-a456-426614174001",
                "token_jti": "a1b2c3d4e5f6...",
                "token_type": "access",
                "token_value": "eyJhbGciOiJIUzI1NiIs...",
                "invalidated": False,
                "invalidated_at": None,
                "expires_at": "2024-02-11T12:00:00Z",
                "created_at": "2024-02-11T10:00:00Z",
                "created_by_ip": "192.168.1.1",
                "user_agent": "Mozilla/5.0..."
            }
        }
