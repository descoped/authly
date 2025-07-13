"""
Tests for bootstrap development mode functionality.

This module tests the AUTHLY_BOOTSTRAP_DEV_MODE feature that allows
development and CI environments to use predictable admin credentials
without requiring password changes.
"""

import os
from unittest.mock import patch

import pytest

from authly.bootstrap.admin_seeding import bootstrap_admin_user


class TestBootstrapDevMode:
    """Test bootstrap development mode override functionality."""

    @pytest.mark.asyncio
    async def test_dev_mode_disabled_by_default(self, transaction_manager):
        """Test that development mode is disabled by default (production security)."""
        async with transaction_manager.transaction() as conn:
            # Clear any existing environment variables
            with patch.dict(os.environ, {}, clear=True):
                # Set a password but no dev mode flag
                os.environ["AUTHLY_ADMIN_PASSWORD"] = "TestDevPassword123!"

                admin_user = await bootstrap_admin_user(conn, username="devtest_default", email="dev1@test.com")

                # Should require password change even with provided password
                assert admin_user is not None
                assert admin_user.requires_password_change is True

    @pytest.mark.asyncio
    async def test_dev_mode_with_provided_password(self, transaction_manager):
        """Test development mode allows fixed password without change requirement."""
        async with transaction_manager.transaction() as conn:
            with patch.dict(os.environ, {}, clear=True):
                # Enable dev mode and provide password
                os.environ["AUTHLY_BOOTSTRAP_DEV_MODE"] = "true"
                os.environ["AUTHLY_ADMIN_PASSWORD"] = "TestDevPassword123!"

                admin_user = await bootstrap_admin_user(conn, username="devtest_mode", email="dev2@test.com")

                # Should NOT require password change in dev mode
                assert admin_user is not None
                assert admin_user.requires_password_change is False
                assert admin_user.username == "devtest_mode"
                assert admin_user.is_admin is True

    @pytest.mark.asyncio
    async def test_dev_mode_with_generated_password_still_requires_change(self, transaction_manager):
        """Test that even in dev mode, generated passwords require change."""
        async with transaction_manager.transaction() as conn:
            with patch.dict(os.environ, {}, clear=True):
                # Enable dev mode but don't provide password (will be generated)
                os.environ["AUTHLY_BOOTSTRAP_DEV_MODE"] = "true"
                # Don't set AUTHLY_ADMIN_PASSWORD - should generate one

                admin_user = await bootstrap_admin_user(conn, username="devtest_generated", email="dev3@test.com")

                # Generated passwords always require change, even in dev mode
                assert admin_user is not None
                assert admin_user.requires_password_change is True

    @pytest.mark.asyncio
    async def test_dev_mode_false_string_value(self, transaction_manager):
        """Test that AUTHLY_BOOTSTRAP_DEV_MODE=false explicitly disables dev mode."""
        async with transaction_manager.transaction() as conn:
            with patch.dict(os.environ, {}, clear=True):
                # Explicitly set dev mode to false
                os.environ["AUTHLY_BOOTSTRAP_DEV_MODE"] = "false"
                os.environ["AUTHLY_ADMIN_PASSWORD"] = "TestDevPassword123!"

                admin_user = await bootstrap_admin_user(conn, username="devtest_false", email="dev4@test.com")

                # Should require password change (production mode)
                assert admin_user is not None
                assert admin_user.requires_password_change is True

    @pytest.mark.asyncio
    async def test_dev_mode_case_insensitive(self, transaction_manager):
        """Test that dev mode flag is case insensitive."""
        async with transaction_manager.transaction() as conn:
            with patch.dict(os.environ, {}, clear=True):
                # Test various case combinations
                os.environ["AUTHLY_BOOTSTRAP_DEV_MODE"] = "TRUE"
                os.environ["AUTHLY_ADMIN_PASSWORD"] = "TestDevPassword123!"

                admin_user = await bootstrap_admin_user(conn, username="devtest1", email="dev5@test.com")

                assert admin_user is not None
                assert admin_user.requires_password_change is False

        async with transaction_manager.transaction() as conn:
            with patch.dict(os.environ, {}, clear=True):
                os.environ["AUTHLY_BOOTSTRAP_DEV_MODE"] = "True"
                os.environ["AUTHLY_ADMIN_PASSWORD"] = "TestDevPassword123!"

                admin_user = await bootstrap_admin_user(conn, username="devtest2_case", email="dev6@test.com")

                assert admin_user is not None
                assert admin_user.requires_password_change is False

    @pytest.mark.asyncio
    async def test_production_security_with_provided_password(self, transaction_manager):
        """Test that production mode still requires password change even with provided password."""
        async with transaction_manager.transaction() as conn:
            with patch.dict(os.environ, {}, clear=True):
                # Production mode (default) with provided password
                os.environ["AUTHLY_ADMIN_PASSWORD"] = "TestProdPassword123!"
                # No AUTHLY_BOOTSTRAP_DEV_MODE set (defaults to false)

                admin_user = await bootstrap_admin_user(conn, username="prodtest_secure", email="dev7@test.com")

                # Even with provided password, production mode requires change
                assert admin_user is not None
                assert admin_user.requires_password_change is True
                assert admin_user.username == "prodtest_secure"
                assert admin_user.is_admin is True
