"""
Tests for authentication models.
"""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from authly.authentication.models import LoginRequest, SessionModel


class TestSessionModel:
    """Test SessionModel validation and serialization."""

    def test_session_model_creation(self):
        """Test creating a valid session model."""
        user_id = uuid4()
        session = SessionModel(
            session_id="test_session_123",
            user_id=user_id,
            username="testuser",
            expires_at=datetime.utcnow() + timedelta(minutes=30),
            csrf_token="csrf_token_123",
            ip_address="127.0.0.1",
            user_agent="Mozilla/5.0",
        )

        assert session.session_id == "test_session_123"
        assert session.user_id == user_id
        assert session.username == "testuser"
        assert session.is_active is True
        assert session.csrf_token == "csrf_token_123"
        assert session.ip_address == "127.0.0.1"
        assert session.user_agent == "Mozilla/5.0"

    def test_session_model_defaults(self):
        """Test session model with default values."""
        user_id = uuid4()
        expires_at = datetime.utcnow() + timedelta(minutes=30)

        session = SessionModel(
            session_id="test_session",
            user_id=user_id,
            username="testuser",
            expires_at=expires_at,
            csrf_token="csrf_token",
        )

        assert session.is_active is True
        assert session.ip_address is None
        assert session.user_agent is None
        assert session.created_at is not None

    def test_session_model_json_serialization(self):
        """Test session model JSON serialization."""
        user_id = uuid4()
        expires_at = datetime.utcnow() + timedelta(minutes=30)

        session = SessionModel(
            session_id="test_session",
            user_id=user_id,
            username="testuser",
            expires_at=expires_at,
            csrf_token="csrf_token",
        )

        json_data = session.model_dump_json()
        assert isinstance(json_data, str)
        assert "test_session" in json_data
        assert "testuser" in json_data
        assert str(user_id) in json_data

    def test_session_model_dict_conversion(self):
        """Test session model to dict conversion."""
        user_id = uuid4()
        expires_at = datetime.utcnow() + timedelta(minutes=30)

        session = SessionModel(
            session_id="test_session",
            user_id=user_id,
            username="testuser",
            expires_at=expires_at,
            csrf_token="csrf_token",
        )

        session_dict = session.model_dump()
        assert session_dict["session_id"] == "test_session"
        assert session_dict["user_id"] == user_id
        assert session_dict["username"] == "testuser"
        assert session_dict["csrf_token"] == "csrf_token"
        assert session_dict["is_active"] is True


class TestLoginRequest:
    """Test LoginRequest model validation."""

    def test_login_request_basic(self):
        """Test basic login request creation."""
        request = LoginRequest(username="testuser", password="testpass123")

        assert request.username == "testuser"
        assert request.password == "testpass123"
        assert request.remember_me is False
        assert request.redirect_uri is None
        assert request.state is None

    def test_login_request_with_remember_me(self):
        """Test login request with remember me option."""
        request = LoginRequest(username="testuser", password="testpass123", remember_me=True)

        assert request.remember_me is True

    def test_login_request_with_oauth_params(self):
        """Test login request with OAuth redirect parameters."""
        request = LoginRequest(
            username="testuser",
            password="testpass123",
            redirect_uri="/api/v1/oauth/authorize?client_id=test",
            state="random_state_123",
        )

        assert request.redirect_uri == "/api/v1/oauth/authorize?client_id=test"
        assert request.state == "random_state_123"

    def test_login_request_validation_empty_username(self):
        """Test login request validation with empty username."""
        with pytest.raises(ValueError):
            LoginRequest(
                username="",  # Empty username should fail
                password="testpass123",
            )

    def test_login_request_validation_empty_password(self):
        """Test login request validation with empty password."""
        with pytest.raises(ValueError):
            LoginRequest(
                username="testuser",
                password="",  # Empty password should fail
            )

    def test_login_request_validation_long_username(self):
        """Test login request validation with username exceeding max length."""
        with pytest.raises(ValueError):
            LoginRequest(
                username="a" * 51,  # Exceeds 50 char limit
                password="testpass123",
            )
