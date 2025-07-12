"""
Unit tests for password security enhancements.

Tests the secure password generation and requires_password_change functionality
without requiring database connections.
"""

import pytest
import string
import re

from authly.bootstrap.admin_seeding import generate_secure_password
from authly.users.models import UserModel
from uuid import uuid4
from datetime import datetime, timezone


class TestSecurePasswordGeneration:
    """Test secure password generation functionality."""
    
    def test_generate_secure_password_length(self):
        """Test generated password has correct length."""
        password = generate_secure_password(16)
        assert len(password) == 16
        
        password = generate_secure_password(20)
        assert len(password) == 20
        
        # Test minimum length enforcement
        password = generate_secure_password(8)
        assert len(password) == 16  # Should enforce minimum
    
    def test_generate_secure_password_complexity(self):
        """Test generated password meets complexity requirements."""
        # Generate multiple passwords to ensure consistency
        for _ in range(10):
            password = generate_secure_password()
            
            # Check for at least one uppercase
            assert any(c in string.ascii_uppercase for c in password), \
                f"Password '{password}' missing uppercase"
            
            # Check for at least one lowercase
            assert any(c in string.ascii_lowercase for c in password), \
                f"Password '{password}' missing lowercase"
            
            # Check for at least one digit
            assert any(c in string.digits for c in password), \
                f"Password '{password}' missing digit"
            
            # Check for at least one special character
            special_chars = "!@#$%^&*()-_=+"
            assert any(c in special_chars for c in password), \
                f"Password '{password}' missing special character"
    
    def test_generate_secure_password_randomness(self):
        """Test that generated passwords are unique."""
        passwords = set()
        for _ in range(100):
            password = generate_secure_password()
            assert password not in passwords, "Duplicate password generated"
            passwords.add(password)
        
        # All 100 passwords should be unique
        assert len(passwords) == 100
    
    def test_generate_secure_password_valid_characters(self):
        """Test generated passwords only contain valid characters."""
        valid_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        
        for _ in range(10):
            password = generate_secure_password()
            assert all(c in valid_chars for c in password), \
                f"Password '{password}' contains invalid characters"


class TestUserModelPasswordChange:
    """Test UserModel with requires_password_change field."""
    
    def test_user_model_default_requires_password_change(self):
        """Test UserModel defaults requires_password_change to False."""
        user = UserModel(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.requires_password_change is False
    
    def test_user_model_explicit_requires_password_change(self):
        """Test UserModel with explicit requires_password_change."""
        user = UserModel(
            id=uuid4(),
            username="admin",
            email="admin@localhost",
            password_hash="hashed_password",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_admin=True,
            requires_password_change=True
        )
        
        assert user.requires_password_change is True
        assert user.is_admin is True


class TestPasswordValidation:
    """Test password validation logic."""
    
    def test_password_meets_requirements(self):
        """Test that generated passwords meet all requirements."""
        # Requirements: min 8 chars (enforced as 16), mixed case, digits, special
        password = generate_secure_password()
        
        # Length check
        assert len(password) >= 16
        
        # Complexity pattern
        pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+]).+$')
        assert pattern.match(password), f"Password '{password}' doesn't meet complexity requirements"