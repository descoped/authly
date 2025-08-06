"""
Test bootstrap password functionality with real database transactions.
"""

import os
from unittest.mock import patch

import pytest
from psycopg_toolkit import TransactionManager

from authly.bootstrap.admin_seeding import bootstrap_admin_user
from authly.users.repository import UserRepository


class TestBootstrapPasswordSecurity:
    """Test bootstrap password security with real database transactions."""

    @pytest.mark.asyncio
    async def test_bootstrap_with_environment_password(self, transaction_manager: TransactionManager):
        """Test bootstrap uses environment variable password when set."""
        async with transaction_manager.transaction() as conn:
            # Ensure no admin user exists initially
            user_repository = UserRepository(conn)
            existing_admin = await user_repository.get_by_username("admin")
            if existing_admin:
                await user_repository.delete(existing_admin.id)

            with patch.dict(os.environ, {"AUTHLY_ADMIN_PASSWORD": "EnvPassword123!"}):
                result = await bootstrap_admin_user(conn)

                # Verify environment password was used
                assert result is not None
                assert result.username == "admin"
                assert result.is_admin is True
                assert result.requires_password_change is True  # Always true for bootstrap
                assert result.is_active is True

                # Verify user was actually created in database
                created_user = await user_repository.get_by_username("admin")
                assert created_user is not None
                assert created_user.requires_password_change is True

    @pytest.mark.asyncio
    async def test_bootstrap_generates_secure_password(self, transaction_manager: TransactionManager):
        """Test bootstrap generates secure password when no env var set."""
        async with transaction_manager.transaction() as conn:
            # Ensure no admin user exists initially
            user_repository = UserRepository(conn)
            existing_admin = await user_repository.get_by_username("admin")
            if existing_admin:
                await user_repository.delete(existing_admin.id)

            # Ensure no environment password
            with patch.dict(os.environ, {}, clear=True), patch("authly.bootstrap.admin_seeding.logger") as mock_logger:
                result = await bootstrap_admin_user(conn)

                # Verify password was generated and logged
                assert result is not None
                assert result.username == "admin"
                assert result.is_admin is True
                assert result.requires_password_change is True

                # Check that warning was logged with generated password
                warning_calls = [
                    call for call in mock_logger.warning.call_args_list if "SECURE PASSWORD GENERATED" in str(call)
                ]
                assert len(warning_calls) > 0

                # Verify user was actually created in database
                created_user = await user_repository.get_by_username("admin")
                assert created_user is not None
                assert created_user.requires_password_change is True

    @pytest.mark.asyncio
    async def test_bootstrap_always_requires_password_change(self, transaction_manager: TransactionManager):
        """Test bootstrap admin always requires password change."""
        async with transaction_manager.transaction() as conn:
            user_repository = UserRepository(conn)

            # Test with environment password
            # Clean up any existing admin user
            existing_admin = await user_repository.get_by_username("admin")
            if existing_admin:
                await user_repository.delete(existing_admin.id)

            with patch.dict(os.environ, {"AUTHLY_ADMIN_PASSWORD": "TestPass123!"}):
                result = await bootstrap_admin_user(conn)
                assert result.requires_password_change is True

                # Clean up for next test
                await user_repository.delete(result.id)

            # Test with generated password
            with patch.dict(os.environ, {}, clear=True):
                result = await bootstrap_admin_user(conn)
                assert result.requires_password_change is True

    def test_no_hardcoded_admin_password(self):
        """Verify no hardcoded Admin123! password exists."""
        # Read the admin_seeding.py file
        import inspect

        import authly.bootstrap.admin_seeding

        source = inspect.getsource(authly.bootstrap.admin_seeding)

        # Check that Admin123! is not in the source
        assert "Admin123!" not in source, "Hardcoded Admin123! password found in source!"

        # Also check the specific line where it used to be
        assert 'os.getenv("AUTHLY_ADMIN_PASSWORD", "Admin123!")' not in source

        # Verify proper pattern is used
        assert 'os.getenv("AUTHLY_ADMIN_PASSWORD")' in source
