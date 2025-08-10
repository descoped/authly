"""
Real-world tests for session repository with memory backend.

These tests use the memory session backend since Redis is not yet implemented.
Tests follow Authly's testing philosophy of no mocking unless absolutely necessary.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from authly.authentication.models import SessionModel
from authly.authentication.repository import SessionRepository


@pytest.fixture
async def session_repo(initialize_authly) -> SessionRepository:
    """Create a real session repository with memory backend."""
    from authly.core.backend_factory import get_session_backend

    backend = await get_session_backend()
    return SessionRepository(backend)


class TestSessionRepository:
    """Test SessionRepository with memory backend operations."""

    @pytest.mark.asyncio
    async def test_create_session_success(self, session_repo: SessionRepository):
        """Test successful session creation in memory."""
        user_id = uuid4()

        session = await session_repo.create_session(
            user_id=user_id, username="testuser", duration_minutes=30, ip_address="127.0.0.1", user_agent="TestAgent"
        )

        # Verify session properties
        assert session.user_id == user_id
        assert session.username == "testuser"
        assert session.ip_address == "127.0.0.1"
        assert session.user_agent == "TestAgent"
        assert session.is_active is True
        assert len(session.session_id) > 0
        assert len(session.csrf_token) > 0

        # Verify expiration is set correctly
        expected_expiry = datetime.now(UTC) + timedelta(minutes=30)
        actual_expiry = session.expires_at
        # Allow 5 second tolerance for test execution time
        assert abs((expected_expiry - actual_expiry).total_seconds()) < 5

    @pytest.mark.asyncio
    async def test_create_session_with_custom_duration(self, session_repo: SessionRepository):
        """Test session creation with custom 24-hour duration."""
        user_id = uuid4()

        session = await session_repo.create_session(
            user_id=user_id,
            username="testuser",
            duration_minutes=1440,  # 24 hours
        )

        # Verify expiration is set correctly for 24 hours
        expected_expiry = datetime.now(UTC) + timedelta(minutes=1440)
        actual_expiry = session.expires_at

        # Allow 5 second tolerance for test execution time
        assert abs((expected_expiry - actual_expiry).total_seconds()) < 5

    @pytest.mark.asyncio
    async def test_get_session_exists(self, session_repo: SessionRepository):
        """Test retrieving an existing valid session from memory."""
        user_id = uuid4()

        # Create a session
        created_session = await session_repo.create_session(user_id=user_id, username="testuser", duration_minutes=30)

        # Retrieve it
        retrieved_session = await session_repo.get_session(created_session.session_id)

        assert retrieved_session is not None
        assert retrieved_session.session_id == created_session.session_id
        assert retrieved_session.username == "testuser"
        assert retrieved_session.user_id == user_id
        assert retrieved_session.is_active is True

    @pytest.mark.asyncio
    async def test_get_session_not_found(self, session_repo: SessionRepository):
        """Test retrieving a non-existent session."""
        session = await session_repo.get_session("nonexistent_session_id")
        assert session is None

    @pytest.mark.asyncio
    async def test_get_session_expired(self, session_repo: SessionRepository):
        """Test that expired sessions are automatically cleaned up."""
        user_id = uuid4()

        # Create a session with very short duration
        # For memory backend, we need to manually set an expired session
        # since we can't manipulate time easily
        session = await session_repo.create_session(
            user_id=user_id,
            username="testuser",
            duration_minutes=1,  # 1 minute
        )

        # Manually expire it by updating the backend directly
        session_key = f"{session_repo.SESSION_PREFIX}{session.session_id}"

        # Create an expired session
        expired_session = SessionModel(
            session_id=session.session_id,
            user_id=user_id,
            username="testuser",
            created_at=datetime.now(UTC) - timedelta(hours=1),
            expires_at=datetime.now(UTC) - timedelta(minutes=1),  # Expired
            csrf_token=session.csrf_token,
            is_active=True,
        )

        # Update the session in backend with expired data
        await session_repo.backend.set_session(session_key, {"data": expired_session.model_dump_json()}, 60)

        # Try to get the expired session - should return None
        retrieved = await session_repo.get_session(session.session_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_get_session_inactive(self, session_repo: SessionRepository):
        """Test retrieving an inactive session."""
        user_id = uuid4()

        # Create an active session first
        session = await session_repo.create_session(user_id=user_id, username="testuser", duration_minutes=30)

        # Manually set it as inactive
        session_key = f"{session_repo.SESSION_PREFIX}{session.session_id}"

        inactive_session = SessionModel(
            session_id=session.session_id,
            user_id=user_id,
            username="testuser",
            created_at=session.created_at,
            expires_at=session.expires_at,
            csrf_token=session.csrf_token,
            is_active=False,  # Inactive
        )

        await session_repo.backend.set_session(session_key, {"data": inactive_session.model_dump_json()}, 30 * 60)

        # Try to get the inactive session - should return None
        retrieved = await session_repo.get_session(session.session_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_invalidate_session_exists(self, session_repo: SessionRepository):
        """Test invalidating an existing session."""
        user_id = uuid4()

        # Create a session
        session = await session_repo.create_session(user_id=user_id, username="testuser", duration_minutes=30)

        # Invalidate it
        result = await session_repo.invalidate_session(session.session_id)
        assert result is True

        # Verify it's gone
        retrieved = await session_repo.get_session(session.session_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_invalidate_session_not_found(self, session_repo: SessionRepository):
        """Test invalidating a non-existent session."""
        result = await session_repo.invalidate_session("nonexistent_session")
        # With memory backend, delete returns False for non-existent keys
        assert result is False

    @pytest.mark.asyncio
    async def test_invalidate_user_sessions(self, session_repo: SessionRepository):
        """Test invalidating all sessions for a user."""
        user_id = uuid4()

        # Create multiple sessions for the same user
        session1 = await session_repo.create_session(user_id=user_id, username="testuser", duration_minutes=30)
        session2 = await session_repo.create_session(user_id=user_id, username="testuser", duration_minutes=30)
        session3 = await session_repo.create_session(user_id=user_id, username="testuser", duration_minutes=30)

        # Invalidate all user sessions
        count = await session_repo.invalidate_user_sessions(user_id)

        assert count == 3

        # Verify all sessions are gone
        assert await session_repo.get_session(session1.session_id) is None
        assert await session_repo.get_session(session2.session_id) is None
        assert await session_repo.get_session(session3.session_id) is None

    @pytest.mark.asyncio
    async def test_invalidate_user_sessions_none_found(self, session_repo: SessionRepository):
        """Test invalidating sessions when user has none."""
        user_id = uuid4()

        # Invalidate sessions for user with no sessions
        count = await session_repo.invalidate_user_sessions(user_id)

        assert count == 0

    @pytest.mark.asyncio
    async def test_extend_session_exists(self, session_repo: SessionRepository):
        """Test extending an existing session's TTL."""
        user_id = uuid4()

        # Create a session
        session = await session_repo.create_session(user_id=user_id, username="testuser", duration_minutes=30)

        # Extend it
        result = await session_repo.extend_session(session.session_id, duration_minutes=60)
        assert result is True

        # Verify it's still accessible and has new expiration
        retrieved = await session_repo.get_session(session.session_id)
        assert retrieved is not None

        # Check that expiration was extended
        new_expiry = retrieved.expires_at
        # Should be extended by approximately 30 minutes from now (60 min total)
        expected_new_expiry = datetime.now(UTC) + timedelta(minutes=60)
        assert abs((expected_new_expiry - new_expiry).total_seconds()) < 5

    @pytest.mark.asyncio
    async def test_extend_session_not_found(self, session_repo: SessionRepository):
        """Test extending a non-existent session."""
        result = await session_repo.extend_session("nonexistent", duration_minutes=60)
        assert result is False

    def test_session_key_prefixes(self, session_repo: SessionRepository):
        """Test that correct key prefixes are used."""
        assert session_repo.SESSION_PREFIX == "session:"
        assert session_repo.USER_SESSIONS_PREFIX == "user_sessions:"

    @pytest.mark.asyncio
    async def test_multiple_user_sessions_tracking(self, session_repo: SessionRepository):
        """Test that user sessions are properly tracked."""
        user_id = uuid4()

        # Create multiple sessions
        sessions = []
        for i in range(3):
            session = await session_repo.create_session(user_id=user_id, username=f"testuser{i}", duration_minutes=30)
            sessions.append(session)

        # All sessions should be retrievable
        for session in sessions:
            retrieved = await session_repo.get_session(session.session_id)
            assert retrieved is not None
            assert retrieved.session_id == session.session_id

        # Invalidate one session
        await session_repo.invalidate_session(sessions[0].session_id)

        # First session should be gone
        assert await session_repo.get_session(sessions[0].session_id) is None

        # Other sessions should still exist
        assert await session_repo.get_session(sessions[1].session_id) is not None
        assert await session_repo.get_session(sessions[2].session_id) is not None
