"""
Authentication service for browser-based login flows.

This module provides the business logic for user authentication
and session management in browser contexts.
"""

import logging
from uuid import UUID

from authly.auth.core import verify_password
from authly.authentication.models import LoginRequest, SessionModel
from authly.authentication.repository import SessionRepository
from authly.users.repository import UserRepository


# Define exceptions locally
class AuthenticationError(Exception):
    """Authentication failed error."""

    pass


logger = logging.getLogger(__name__)


class AuthenticationService:
    """
    Service for handling browser-based authentication.

    This service manages login, logout, and session validation for
    browser-based OAuth flows.
    """

    def __init__(self, backend):
        """Initialize authentication service with backend."""
        self.backend = backend
        self.session_repo = SessionRepository(backend) if backend else None

    async def login(
        self, request: LoginRequest, ip_address: str | None = None, user_agent: str | None = None
    ) -> tuple[SessionModel, str]:
        """
        Authenticate user and create a session.

        Args:
            request: Login request with credentials
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            Tuple of (session model, session cookie value)

        Raises:
            AuthenticationError: If credentials are invalid
        """
        try:
            # Get database connection and authenticate user
            from authly.core.dependencies import get_resource_manager

            resource_manager = get_resource_manager()
            pool = resource_manager.get_pool()
            async with pool.connection() as conn:
                user_repo = UserRepository(conn)
                # Find user by username or email
                user = await user_repo.get_by_username(request.username)
                if not user:
                    user = await user_repo.get_by_email(request.username)

                if not user:
                    logger.warning(f"Failed login attempt for username: {request.username}")
                    raise AuthenticationError("Invalid username or password")

                # Verify password
                if not verify_password(request.password, user.password_hash):
                    logger.warning(f"Invalid password for user: {user.username}")
                    raise AuthenticationError("Invalid username or password")

                if not user.is_active:
                    logger.warning(f"Login attempt for inactive user: {user.username}")
                    raise AuthenticationError("Account is not active")

            # Determine session duration
            duration_minutes = 1440 if request.remember_me else 30  # 24 hours or 30 minutes

            # Create session
            session = await self.session_repo.create_session(
                user_id=user.id,
                username=user.username,
                duration_minutes=duration_minutes,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            logger.info(f"User {user.username} logged in successfully (session: {session.session_id[:8]}...)")

            # Update last login
            async with pool.connection() as conn:
                user_repo = UserRepository(conn)
                await user_repo.update_last_login(user.id)

            return session, session.session_id

        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Login error: {e!s}")
            raise AuthenticationError("Authentication failed") from e

    async def logout(self, session_id: str) -> bool:
        """
        Log out a user by invalidating their session.

        Args:
            session_id: Session identifier

        Returns:
            True if logout was successful
        """
        try:
            session = await self.session_repo.get_session(session_id)
            if session:
                logger.info(f"User {session.username} logged out (session: {session_id[:8]}...)")

            return await self.session_repo.invalidate_session(session_id)

        except Exception as e:
            logger.error(f"Logout error: {e!s}")
            return False

    async def validate_session(
        self, session_id: str, csrf_token: str | None = None, check_csrf: bool = False
    ) -> SessionModel | None:
        """
        Validate a session and optionally check CSRF token.

        Args:
            session_id: Session identifier
            csrf_token: CSRF token to validate
            check_csrf: Whether to check CSRF token

        Returns:
            Session model if valid, None otherwise
        """
        try:
            session = await self.session_repo.get_session(session_id)
            if not session:
                return None

            # Check CSRF token if required
            if check_csrf and csrf_token != session.csrf_token:
                logger.warning(f"CSRF token mismatch for session: {session_id[:8]}...")
                return None

            # Extend session on activity (sliding expiration)
            await self.session_repo.extend_session(session_id)

            return session

        except Exception as e:
            logger.error(f"Session validation error: {e!s}")
            return None

    async def get_user_from_session(self, session_id: str) -> dict | None:
        """
        Get user information from a session.

        Args:
            session_id: Session identifier

        Returns:
            User information dictionary if session is valid
        """
        try:
            session = await self.validate_session(session_id)
            if not session:
                return None

            # Get full user information
            from authly.core.dependencies import get_resource_manager

            resource_manager = get_resource_manager()
            pool = resource_manager.get_pool()
            async with pool.connection() as conn:
                user_repo = UserRepository(conn)
                user = await user_repo.get_by_id(session.user_id)

                if not user or not user.is_active:
                    return None

                return {
                    "id": str(user.id),
                    "username": user.username,
                    "email": user.email,
                    "is_admin": user.is_admin,
                    "session_id": session.session_id,
                    "csrf_token": session.csrf_token,
                }

        except Exception as e:
            logger.error(f"Error getting user from session: {e!s}")
            return None

    async def logout_all_sessions(self, user_id: UUID) -> int:
        """
        Log out all sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            Number of sessions invalidated
        """
        try:
            count = await self.session_repo.invalidate_user_sessions(user_id)
            logger.info(f"Invalidated {count} sessions for user {user_id}")
            return count

        except Exception as e:
            logger.error(f"Error logging out all sessions: {e!s}")
            return 0
