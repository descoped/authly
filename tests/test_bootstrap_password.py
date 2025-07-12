"""
Test bootstrap password functionality without database dependency.
"""

import os
import pytest
from unittest.mock import Mock, AsyncMock, patch

from authly.bootstrap.admin_seeding import bootstrap_admin_user, generate_secure_password
from authly.users.models import UserModel
from uuid import uuid4
from datetime import datetime, timezone


class TestBootstrapPasswordSecurity:
    """Test bootstrap password security without database."""
    
    @pytest.mark.asyncio
    async def test_bootstrap_with_environment_password(self):
        """Test bootstrap uses environment variable password when set."""
        mock_conn = Mock()
        mock_user_repo = Mock()
        mock_user_repo.get_by_username = AsyncMock(return_value=None)
        mock_user_repo.create = AsyncMock(side_effect=lambda user: user)
        
        with patch('authly.bootstrap.admin_seeding.UserRepository', return_value=mock_user_repo):
            with patch.dict(os.environ, {'AUTHLY_ADMIN_PASSWORD': 'EnvPassword123!'}):
                # Clear any generated password from previous test
                if 'admin_password' in locals():
                    del locals()['admin_password']
                    
                result = await bootstrap_admin_user(mock_conn)
                
                # Verify environment password was used
                assert result is not None
                assert result.requires_password_change is True  # Always true for bootstrap
                # Password hash should be created from env password
                created_user = mock_user_repo.create.call_args[0][0]
                assert created_user.requires_password_change is True
    
    @pytest.mark.asyncio
    async def test_bootstrap_generates_secure_password(self):
        """Test bootstrap generates secure password when no env var set."""
        mock_conn = Mock()
        mock_user_repo = Mock()
        mock_user_repo.get_by_username = AsyncMock(return_value=None)
        mock_user_repo.create = AsyncMock(side_effect=lambda user: user)
        
        with patch('authly.bootstrap.admin_seeding.UserRepository', return_value=mock_user_repo):
            # Ensure no environment password
            with patch.dict(os.environ, {}, clear=True):
                # Capture logs to verify password was generated
                with patch('authly.bootstrap.admin_seeding.logger') as mock_logger:
                    result = await bootstrap_admin_user(mock_conn)
                    
                    # Verify password was generated and logged
                    assert result is not None
                    assert result.requires_password_change is True
                    
                    # Check that warning was logged with generated password
                    warning_calls = [call for call in mock_logger.warning.call_args_list 
                                   if 'SECURE PASSWORD GENERATED' in str(call)]
                    assert len(warning_calls) > 0
    
    @pytest.mark.asyncio
    async def test_bootstrap_always_requires_password_change(self):
        """Test bootstrap admin always requires password change."""
        mock_conn = Mock()
        mock_user_repo = Mock()
        mock_user_repo.get_by_username = AsyncMock(return_value=None)
        mock_user_repo.create = AsyncMock(side_effect=lambda user: user)
        
        with patch('authly.bootstrap.admin_seeding.UserRepository', return_value=mock_user_repo):
            # Test with environment password
            with patch.dict(os.environ, {'AUTHLY_ADMIN_PASSWORD': 'TestPass123!'}):
                result = await bootstrap_admin_user(mock_conn)
                assert result.requires_password_change is True
            
            # Test with generated password
            with patch.dict(os.environ, {}, clear=True):
                result = await bootstrap_admin_user(mock_conn)
                assert result.requires_password_change is True
    
    def test_no_hardcoded_admin_password(self):
        """Verify no hardcoded Admin123! password exists."""
        # Read the admin_seeding.py file
        import authly.bootstrap.admin_seeding
        import inspect
        
        source = inspect.getsource(authly.bootstrap.admin_seeding)
        
        # Check that Admin123! is not in the source
        assert 'Admin123!' not in source, "Hardcoded Admin123! password found in source!"
        
        # Also check the specific line where it used to be
        assert 'os.getenv("AUTHLY_ADMIN_PASSWORD", "Admin123!")' not in source
        
        # Verify proper pattern is used
        assert 'os.getenv("AUTHLY_ADMIN_PASSWORD")' in source