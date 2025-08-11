"""
Session repository for browser-based authentication.

This module handles session storage and retrieval using the SessionBackend
abstraction which can be either memory-based or Redis-based.
"""

import base64
import json
import secrets
from datetime import datetime, timedelta
from uuid import UUID

from authly.authentication.models import SessionModel
from authly.monitoring.metrics import DatabaseTimer


# Define exceptions locally
class OperationError(Exception):
    """Operation failed error."""

    pass


class SessionRepository:
    """
    Repository for managing browser sessions using SessionBackend.

    SPECIAL CASE: This repository does NOT inherit from BaseRepository because:
    - It manages ephemeral session state, not persistent database entities
    - Uses specialized storage backends (memory/Redis) instead of PostgreSQL
    - Sessions have different lifecycle patterns (TTL-based expiry vs CRUD)
    - Requires real-time performance characteristics not suited for DB transactions

    Sessions are stored using the backend abstraction which handles
    both memory and Redis storage transparently.

    This is an intentional architectural decision, not an oversight.
    """

    SESSION_PREFIX = "session:"
    USER_SESSIONS_PREFIX = "user_sessions:"

    def __init__(self, backend):
        """Initialize session repository with backend."""
        self.backend = backend

    async def create_session(
        self,
        user_id: UUID,
        username: str,
        duration_minutes: int = 30,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> SessionModel:
        """
        Create a new browser session.

        Args:
            user_id: User ID for the session
            username: Username for display
            duration_minutes: Session duration in minutes
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            Created session model
        """
        with DatabaseTimer("session_create"):
            try:
                # Generate secure session ID and CSRF token
                session_id = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8")
                csrf_token = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("utf-8")

                # Calculate expiration
                from datetime import UTC

                now = datetime.now(UTC)
                expires_at = now + timedelta(minutes=duration_minutes)

                # Create session model
                session = SessionModel(
                    session_id=session_id,
                    user_id=user_id,
                    username=username,
                    created_at=now,
                    expires_at=expires_at,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    csrf_token=csrf_token,
                    is_active=True,
                )

                # Store in backend with TTL
                session_key = f"{self.SESSION_PREFIX}{session_id}"
                session_data = session.model_dump_json()
                ttl_seconds = duration_minutes * 60

                # Store the session
                success = await self.backend.set_session(session_key, {"data": session_data}, ttl_seconds)

                if not success:
                    raise OperationError("Failed to store session")

                # Track user's active sessions (store in a separate key)
                user_sessions_key = f"{self.USER_SESSIONS_PREFIX}{user_id}"
                existing = await self.backend.get_session(user_sessions_key)

                sessions = set(existing.get("sessions", [])) if existing else set()

                sessions.add(session_id)
                await self.backend.set_session(user_sessions_key, {"sessions": list(sessions)}, ttl_seconds)

                return session

            except Exception as e:
                raise OperationError(f"Failed to create session: {e!s}") from e

    async def get_session(self, session_id: str) -> SessionModel | None:
        """
        Retrieve a session by ID.

        Args:
            session_id: Session identifier

        Returns:
            Session model if found and valid, None otherwise
        """
        with DatabaseTimer("session_get"):
            try:
                session_key = f"{self.SESSION_PREFIX}{session_id}"
                result = await self.backend.get_session(session_key)

                if not result:
                    return None

                # Parse session data
                session_data = result.get("data")
                if not session_data:
                    return None

                try:
                    session = SessionModel.model_validate_json(session_data)
                except (json.JSONDecodeError, ValueError):
                    # Session data is corrupted, delete it
                    await self.backend.delete_session(session_key)
                    return None

                # Check if session is expired
                from datetime import UTC

                if session.expires_at < datetime.now(UTC):
                    await self.invalidate_session(session_id)
                    return None

                # Check if session is active
                if not session.is_active:
                    return None

                return session

            except Exception:
                return None

    async def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate a session.

        Args:
            session_id: Session identifier

        Returns:
            True if invalidated, False if not found
        """
        with DatabaseTimer("session_invalidate"):
            try:
                session_key = f"{self.SESSION_PREFIX}{session_id}"

                # Get session to find user_id
                result = await self.backend.get_session(session_key)
                if result:
                    session_data = result.get("data")
                    if session_data:
                        try:
                            session_dict = json.loads(session_data)
                            user_id = session_dict.get("user_id")

                            # Remove from user's active sessions
                            if user_id:
                                user_sessions_key = f"{self.USER_SESSIONS_PREFIX}{user_id}"
                                existing = await self.backend.get_session(user_sessions_key)
                                if existing:
                                    sessions = set(existing.get("sessions", []))
                                    sessions.discard(session_id)
                                    if sessions:
                                        # Update the list
                                        await self.backend.set_session(
                                            user_sessions_key,
                                            {"sessions": list(sessions)},
                                            3600,  # 1 hour TTL
                                        )
                                    else:
                                        # No more sessions, delete the key
                                        await self.backend.delete_session(user_sessions_key)
                        except json.JSONDecodeError:
                            # Session data is corrupted, just delete it
                            pass

                # Delete the session
                result = await self.backend.delete_session(session_key)
                return result

            except Exception as e:
                raise OperationError(f"Failed to invalidate session: {e!s}") from e

    async def invalidate_user_sessions(self, user_id: UUID) -> int:
        """
        Invalidate all sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            Number of sessions invalidated
        """
        with DatabaseTimer("session_invalidate_user"):
            try:
                user_sessions_key = f"{self.USER_SESSIONS_PREFIX}{user_id}"
                result = await self.backend.get_session(user_sessions_key)

                if not result:
                    return 0

                sessions = result.get("sessions", [])
                count = 0

                # Delete each session
                for session_id in sessions:
                    session_key = f"{self.SESSION_PREFIX}{session_id}"
                    if await self.backend.delete_session(session_key):
                        count += 1

                # Delete the user sessions tracking key
                await self.backend.delete_session(user_sessions_key)

                return count

            except Exception:
                return 0

    async def extend_session(self, session_id: str, duration_minutes: int = 30) -> bool:
        """
        Extend a session's expiration time.

        Args:
            session_id: Session identifier
            duration_minutes: Additional minutes to extend

        Returns:
            True if extended, False if not found
        """
        with DatabaseTimer("session_extend"):
            try:
                # Get existing session
                session = await self.get_session(session_id)
                if not session:
                    return False

                # Calculate new expiration
                from datetime import UTC

                new_expires_at = datetime.now(UTC) + timedelta(minutes=duration_minutes)
                session.expires_at = new_expires_at

                # Update in backend
                session_key = f"{self.SESSION_PREFIX}{session_id}"
                session_data = session.model_dump_json()
                ttl_seconds = duration_minutes * 60

                success = await self.backend.set_session(session_key, {"data": session_data}, ttl_seconds)

                # Also extend user sessions tracking
                if success:
                    user_sessions_key = f"{self.USER_SESSIONS_PREFIX}{session.user_id}"
                    existing = await self.backend.get_session(user_sessions_key)
                    if existing:
                        await self.backend.set_session(user_sessions_key, existing, ttl_seconds)

                return success

            except Exception:
                return False
