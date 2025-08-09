"""
Real-world tests for authentication service using actual database and Redis.

These tests use real components with testcontainers for PostgreSQL and Redis,
following Authly's testing philosophy of no mocking unless absolutely necessary.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from psycopg_toolkit import TransactionManager

from authly.auth.core import get_password_hash
from authly.authentication.models import LoginRequest
from authly.authentication.service import AuthenticationError, AuthenticationService
from authly.users.models import UserModel
from authly.users.repository import UserRepository
from authly.users.service import UserService


@pytest.fixture
async def test_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a real test user in the database."""
    user_id = uuid4()
    user_model = UserModel(
        id=user_id,
        username=f"testuser_{user_id.hex[:8]}",
        email=f"test_{user_id.hex[:8]}@example.com",
        password_hash=get_password_hash("TestPassword123!"),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        is_active=True,
        is_verified=True,
        is_admin=False,
    )

    async with transaction_manager.transaction() as conn:
        repo = UserRepository(conn)
        return await repo.create(user_model)


@pytest.fixture
async def inactive_user(transaction_manager: TransactionManager) -> UserModel:
    """Create an inactive test user in the database."""
    user_id = uuid4()
    user_model = UserModel(
        id=user_id,
        username=f"inactiveuser_{user_id.hex[:8]}",
        email=f"inactive_{user_id.hex[:8]}@example.com",
        password_hash=get_password_hash("TestPassword123!"),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        is_active=False,
        is_verified=True,
        is_admin=False,
    )

    async with transaction_manager.transaction() as conn:
        repo = UserRepository(conn)
        return await repo.create(user_model)


@pytest.fixture
async def auth_service(initialize_authly) -> AuthenticationService:
    """Create a real authentication service with backend."""
    from authly.core.backend_factory import get_session_backend

    backend = await get_session_backend()
    return AuthenticationService(backend)


@pytest.fixture
async def user_service(transaction_manager: TransactionManager) -> UserService:
    """Create a real user service."""
    async with transaction_manager.transaction() as conn:
        repo = UserRepository(conn)
        return UserService(repo)


class TestAuthenticationService:
    """Test AuthenticationService with real database and Redis."""

    @pytest.mark.asyncio
    async def test_login_success(self, auth_service: AuthenticationService, test_user: UserModel):
        """Test successful login with valid credentials."""
        request = LoginRequest(username=test_user.username, password="TestPassword123!")

        session, session_id = await auth_service.login(request, ip_address="127.0.0.1", user_agent="TestAgent")

        assert session is not None
        assert session.user_id == test_user.id
        assert session.username == test_user.username
        assert session.is_active is True
        assert session.ip_address == "127.0.0.1"
        assert session.user_agent == "TestAgent"
        assert len(session_id) > 0
        assert len(session.csrf_token) > 0

    @pytest.mark.asyncio
    async def test_login_with_remember_me(self, auth_service: AuthenticationService, test_user: UserModel):
        """Test login with remember me option extends session duration."""
        request = LoginRequest(username=test_user.username, password="TestPassword123!", remember_me=True)

        session, _ = await auth_service.login(request)

        # Check that session expires in approximately 24 hours (1440 minutes)
        time_diff = (session.expires_at - session.created_at).total_seconds()
        assert 86000 < time_diff < 87000  # ~24 hours with some tolerance

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, auth_service: AuthenticationService):
        """Test login with invalid credentials."""
        request = LoginRequest(username="nonexistent", password="WrongPassword")

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.login(request)

        assert "Invalid username or password" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_login_inactive_user(self, auth_service: AuthenticationService, inactive_user: UserModel):
        """Test login with inactive user account."""
        request = LoginRequest(username=inactive_user.username, password="TestPassword123!")

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.login(request)

        assert "Account is not active" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_logout_existing_session(self, auth_service: AuthenticationService, test_user: UserModel):
        """Test logging out with existing session."""
        # First create a session
        request = LoginRequest(username=test_user.username, password="TestPassword123!")
        session, session_id = await auth_service.login(request)

        # Now logout
        result = await auth_service.logout(session_id)

        assert result is True

        # Verify session is no longer valid
        validated = await auth_service.validate_session(session_id)
        assert validated is None

    @pytest.mark.asyncio
    async def test_logout_nonexistent_session(self, auth_service: AuthenticationService):
        """Test logging out with non-existent session."""
        result = await auth_service.logout("nonexistent_session_id")
        assert result is False

    @pytest.mark.asyncio
    async def test_validate_session_valid(self, auth_service: AuthenticationService, test_user: UserModel):
        """Test validating a valid session."""
        # Create a session
        request = LoginRequest(username=test_user.username, password="TestPassword123!")
        session, session_id = await auth_service.login(request)

        # Validate it
        validated = await auth_service.validate_session(session_id)

        assert validated is not None
        assert validated.session_id == session.session_id
        assert validated.username == test_user.username

    @pytest.mark.asyncio
    async def test_validate_session_with_csrf_check(self, auth_service: AuthenticationService, test_user: UserModel):
        """Test validating session with CSRF token check."""
        # Create a session
        request = LoginRequest(username=test_user.username, password="TestPassword123!")
        session, session_id = await auth_service.login(request)

        # Validate with correct CSRF token
        validated = await auth_service.validate_session(session_id, csrf_token=session.csrf_token, check_csrf=True)
        assert validated is not None

        # Validate with incorrect CSRF token
        validated = await auth_service.validate_session(session_id, csrf_token="wrong_token", check_csrf=True)
        assert validated is None

    @pytest.mark.asyncio
    async def test_get_user_from_session_valid(self, auth_service: AuthenticationService, test_user: UserModel):
        """Test getting user from valid session."""
        # Create a session
        request = LoginRequest(username=test_user.username, password="TestPassword123!")
        session, session_id = await auth_service.login(request)

        # Get user from session
        user_data = await auth_service.get_user_from_session(session_id)

        assert user_data is not None
        assert user_data["id"] == str(test_user.id)
        assert user_data["username"] == test_user.username
        assert user_data["email"] == test_user.email
        assert user_data["is_admin"] == test_user.is_admin
        assert user_data["session_id"] == session_id
        assert user_data["csrf_token"] == session.csrf_token

    @pytest.mark.asyncio
    async def test_get_user_from_session_invalid(self, auth_service: AuthenticationService):
        """Test getting user from invalid session."""
        user_data = await auth_service.get_user_from_session("invalid_session_id")
        assert user_data is None

    @pytest.mark.asyncio
    async def test_logout_all_sessions(self, auth_service: AuthenticationService, test_user: UserModel):
        """Test logging out all sessions for a user."""
        # Create multiple sessions
        request = LoginRequest(username=test_user.username, password="TestPassword123!")

        session1, session_id1 = await auth_service.login(request)
        session2, session_id2 = await auth_service.login(request)
        session3, session_id3 = await auth_service.login(request)

        # Logout all sessions
        count = await auth_service.logout_all_sessions(test_user.id)

        assert count >= 3  # At least the 3 we created

        # Verify all sessions are invalid
        assert await auth_service.validate_session(session_id1) is None
        assert await auth_service.validate_session(session_id2) is None
        assert await auth_service.validate_session(session_id3) is None
