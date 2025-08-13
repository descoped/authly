"""
Authentication dependencies for browser and API flows.

This module provides FastAPI dependencies that support both
session-based (browser) and token-based (API) authentication.
"""

import logging
from uuid import UUID

from fastapi import Cookie, Depends, HTTPException, Request, status
from jose import JWTError

from authly.api.auth_dependencies import oauth2_scheme_optional
from authly.api.users_dependencies import get_user_repository
from authly.authentication.service import AuthenticationService
from authly.config import AuthlyConfig
from authly.core.dependencies import get_config
from authly.tokens import TokenService, get_token_service
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)

# Cookie configuration (must match router.py)
COOKIE_NAME = "authly_session"


async def get_current_user_flexible(
    request: Request,  # pylint: disable=unused-argument
    token: str | None = Depends(oauth2_scheme_optional),
    session_cookie: str | None = Cookie(None, alias=COOKIE_NAME),
    user_repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
    config: AuthlyConfig = Depends(get_config),
) -> UserModel | None:
    """
    Get current user from either session cookie or Bearer token.

    This dependency supports both browser-based (session) and API-based (Bearer token)
    authentication methods, allowing the OAuth authorization endpoint to work with both.

    Priority:
    1. Check for session cookie (browser flow)
    2. Check for Bearer token (API flow)
    3. Return None if neither present

    Args:
        request: FastAPI request object
        token: Optional Bearer token from Authorization header
        session_cookie: Optional session cookie
        user_repo: User repository
        token_service: Token service for validation
        config: Authly configuration

    Returns:
        UserModel if authenticated, None otherwise
    """
    # First, try session-based authentication (browser flow)
    if session_cookie:
        try:
            from authly.core.backend_factory import get_session_backend

            backend = await get_session_backend()
            auth_service = AuthenticationService(backend)
            session_data = await auth_service.get_user_from_session(session_cookie)

            if session_data:
                # Get full user model
                user = await user_repo.get_by_id(UUID(session_data["id"]))
                if user and user.is_active:
                    logger.debug(f"User {user.username} authenticated via session")
                    return user
        except (ValueError, KeyError, AttributeError, TypeError) as e:
            logger.debug(f"Session authentication failed: {e!s}")

    # Second, try token-based authentication (API flow)
    if token:
        try:
            from authly.auth import decode_token

            payload = decode_token(token, config.secret_key, config.algorithm)
            user_id_str = payload.get("sub")
            if not user_id_str:
                raise ValueError("Invalid token: missing subject")

            jti = payload.get("jti")
            if jti is not None and not await token_service.is_token_valid(jti):
                raise ValueError("Token has been revoked")

            user_id = UUID(user_id_str)
            user = await user_repo.get_by_id(user_id)
            if user and user.is_active:
                logger.debug(f"User {user.username} authenticated via Bearer token")
                return user
        except (ValueError, JWTError, KeyError, AttributeError, TypeError) as e:
            logger.debug(f"Token authentication failed: {e!s}")

    # No authentication method succeeded
    return None


async def require_authenticated_user(user: UserModel | None = Depends(get_current_user_flexible)) -> UserModel:
    """
    Require an authenticated user from either session or token.

    Raises HTTPException if no user is authenticated.

    Args:
        user: User from flexible authentication

    Returns:
        Authenticated user model

    Raises:
        HTTPException: 401 if not authenticated
    """
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_session_csrf_token(session_cookie: str | None = Cookie(None, alias=COOKIE_NAME)) -> str | None:
    """
    Get CSRF token from current session.

    Args:
        session_cookie: Session cookie

    Returns:
        CSRF token if session exists, None otherwise
    """
    if not session_cookie:
        return None

    try:
        from authly.core.backend_factory import get_session_backend

        backend = await get_session_backend()
        auth_service = AuthenticationService(backend)
        session_data = await auth_service.get_user_from_session(session_cookie)
        return session_data.get("csrf_token") if session_data else None
    except (ValueError, KeyError, AttributeError, TypeError, ImportError):
        return None
