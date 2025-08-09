"""
Authentication models for browser-based session management.

This module provides session management for browser-based OAuth flows,
enabling the Authorization Code flow to work with a login UI.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class SessionModel(BaseModel):
    """
    Browser session model for maintaining user authentication state.

    This enables browser-based OAuth flows by maintaining a session
    between login and authorization consent.
    """

    session_id: str = Field(..., description="Unique session identifier")
    user_id: UUID = Field(..., description="Associated user ID")
    username: str = Field(..., description="Username for display")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Session creation timestamp")
    expires_at: datetime = Field(..., description="Session expiration timestamp")
    ip_address: str | None = Field(None, description="Client IP address")
    user_agent: str | None = Field(None, description="Client user agent")

    # Security features
    csrf_token: str = Field(..., description="CSRF protection token")
    is_active: bool = Field(default=True, description="Session active status")

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat(), UUID: lambda v: str(v)}


class LoginRequest(BaseModel):
    """Login request model for authentication."""

    username: str = Field(..., min_length=1, max_length=50, description="Username or email")
    password: str = Field(..., min_length=1, description="User password")
    remember_me: bool = Field(default=False, description="Extended session duration")

    # OAuth flow parameters (optional, for redirecting after login)
    redirect_uri: str | None = Field(None, description="OAuth redirect after login")
    state: str | None = Field(None, description="OAuth state parameter")
