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
