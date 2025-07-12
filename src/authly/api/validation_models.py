"""
Dynamic validation models that use configuration values.

This module provides factory functions to create Pydantic models with
validation constraints based on configuration values rather than hardcoded values.
"""

from typing import Optional
from pydantic import BaseModel, Field, constr


def get_username_type():
    """Get username string type with config-based constraints."""
    try:
        from authly import get_config
        config = get_config()
        min_length = config.username_min_length
        max_length = config.username_max_length
    except RuntimeError:
        # Fallback for tests without full Authly initialization
        min_length = 1
        max_length = 50
    
    return constr(min_length=min_length, max_length=max_length)


def get_password_type():
    """Get password string type with config-based constraints."""
    try:
        from authly import get_config
        config = get_config()
        min_length = config.password_min_length
    except RuntimeError:
        # Fallback for tests without full Authly initialization
        min_length = 8
    
    return constr(min_length=min_length)


def create_user_create_model():
    """Create UserCreate model with config-based validation."""
    username_type = get_username_type()
    password_type = get_password_type()
    
    class UserCreate(BaseModel):
        username: username_type
        email: str
        password: password_type
    
    return UserCreate


def create_user_update_model():
    """Create UserUpdate model with config-based validation."""
    username_type = get_username_type()
    password_type = get_password_type()
    
    class UserUpdate(BaseModel):
        username: Optional[username_type] = None
        email: Optional[str] = None
        password: Optional[password_type] = None
        is_active: Optional[bool] = None
        is_verified: Optional[bool] = None
        is_admin: Optional[bool] = None
    
    return UserUpdate


def create_password_change_request_model():
    """Create PasswordChangeRequest model with config-based validation."""
    password_type = get_password_type()
    
    class PasswordChangeRequest(BaseModel):
        current_password: password_type = Field(..., description="Current password")
        new_password: password_type = Field(..., description="New password")
    
    return PasswordChangeRequest