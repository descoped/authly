"""
Authentication package for browser-based login flows.

This package provides session-based authentication to enable
browser OAuth flows like Authorization Code with PKCE.
"""

from authly.authentication.models import LoginRequest, SessionModel
from authly.authentication.repository import SessionRepository
from authly.authentication.router import auth_router
from authly.authentication.service import AuthenticationService

__all__ = [
    "AuthenticationService",
    "LoginRequest",
    "SessionModel",
    "SessionRepository",
    "auth_router",
]
