"""
Dynamic validation models with fallback configuration values.

This module provides factory functions to create Pydantic models with
validation constraints. Since these are called at import time, they use
sensible defaults and can be overridden at runtime through dependency injection.
"""

from pydantic import BaseModel, constr


def get_username_type():
    """Get username string type with sensible default constraints.

    Uses default constraints since this is called at import time.
    Runtime validation can be handled through FastAPI dependencies.
    """
    # Use sensible defaults for import-time model creation
    min_length = 1
    max_length = 50

    return constr(min_length=min_length, max_length=max_length)


def get_password_type():
    """Get password string type with sensible default constraints.

    Uses default constraints since this is called at import time.
    Runtime validation can be handled through FastAPI dependencies.
    """
    # Use sensible defaults for import-time model creation
    min_length = 8

    return constr(min_length=min_length)


def create_user_create_model():
    """Create UserCreate model with default validation constraints.

    Uses sensible defaults since this is called at import time.
    Configuration-specific validation should be handled in FastAPI endpoints.
    """
    username_type = get_username_type()
    password_type = get_password_type()

    class UserCreate(BaseModel):
        username: username_type
        email: str
        password: password_type
        is_admin: bool | None = False

    return UserCreate


def create_user_update_model():
    """Create UserUpdate model with optional fields."""
    username_type = get_username_type()
    password_type = get_password_type()

    class UserUpdate(BaseModel):
        username: username_type | None = None
        email: str | None = None
        password: password_type | None = None
        is_admin: bool | None = None

    return UserUpdate


def create_password_change_model():
    """Create PasswordChange model with validation."""
    password_type = get_password_type()

    class PasswordChange(BaseModel):
        current_password: str
        new_password: password_type

    return PasswordChange


def create_password_reset_model():
    """Create PasswordReset model with validation."""
    password_type = get_password_type()

    class PasswordReset(BaseModel):
        token: str
        new_password: password_type

    return PasswordReset


def create_password_change_request_model():
    """Create PasswordChangeRequest model with validation."""
    password_type = get_password_type()

    class PasswordChangeRequest(BaseModel):
        current_password: str
        new_password: password_type

    return PasswordChangeRequest
