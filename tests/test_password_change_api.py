"""
Integration tests for password change functionality.
"""

import pytest
from fastapi import status

from authly.api.password_change import PasswordChangeRequest, PasswordChangeResponse


class TestPasswordChangeAPI:
    """Test password change API endpoints."""

    def test_password_change_request_model(self):
        """Test PasswordChangeRequest model validation."""
        # Valid request
        request = PasswordChangeRequest(current_password="OldPassword123!", new_password="NewPassword456!")
        assert request.current_password == "OldPassword123!"
        assert request.new_password == "NewPassword456!"

        # Test minimum length validation for new_password (not current_password)
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            PasswordChangeRequest(current_password="OldPassword123!", new_password="short")

    def test_password_change_response_model(self):
        """Test PasswordChangeResponse model."""
        response = PasswordChangeResponse(message="Password successfully changed", requires_password_change=False)
        assert response.message == "Password successfully changed"
        assert response.requires_password_change is False

    def test_token_response_with_password_change_flag(self):
        """Test TokenResponse includes requires_password_change field."""
        from authly.api.auth_router import TokenResponse

        # Without password change requirement
        response = TokenResponse(
            access_token="token123", refresh_token="refresh123", token_type="bearer", expires_in=3600
        )
        assert response.requires_password_change is None

        # With password change requirement
        response = TokenResponse(
            access_token="token123",
            refresh_token="refresh123",
            token_type="bearer",
            expires_in=3600,
            requires_password_change=True,
        )
        assert response.requires_password_change is True
