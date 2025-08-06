"""
Password change endpoint for Authly authentication service.

This module implements secure password change functionality with
support for mandatory password changes on first login.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from authly.api.users_dependencies import get_current_user, get_user_repository
from authly.api.validation_models import create_password_change_request_model
from authly.auth import get_password_hash, verify_password
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)

# Create model with config-based validation
PasswordChangeRequest = create_password_change_request_model()


class PasswordChangeResponse(BaseModel):
    """Response model for password change."""

    message: str = Field(..., description="Success message")
    requires_password_change: bool = Field(..., description="Whether further password change is required")


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/change-password", response_model=PasswordChangeResponse)
async def change_password(
    request: PasswordChangeRequest,
    current_user: UserModel = Depends(get_current_user),
    user_repo: UserRepository = Depends(get_user_repository),
) -> PasswordChangeResponse:
    """
    Change user password.

    This endpoint allows authenticated users to change their password.
    Users with requires_password_change=True must use this endpoint
    before accessing other protected resources.

    Args:
        request: Password change request with current and new passwords
        current_user: Currently authenticated user
        user_repo: User repository instance

    Returns:
        Success response with updated password change requirement status

    Raises:
        HTTPException: If current password is incorrect or update fails
    """
    try:
        # Verify current password
        if not verify_password(request.current_password, current_user.password_hash):
            logger.warning(f"Password change failed for user {current_user.username}: incorrect current password")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")

        # Validate new password is different from current
        if request.current_password == request.new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different from current password"
            )

        # Update password and clear requires_password_change flag
        update_data = {"password_hash": get_password_hash(request.new_password), "requires_password_change": False}

        await user_repo.update(current_user.id, update_data)

        logger.info(f"Password successfully changed for user {current_user.username}")

        return PasswordChangeResponse(message="Password successfully changed", requires_password_change=False)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error changing password for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not change password"
        ) from e


@router.get("/password-status", response_model=dict)
async def get_password_status(
    current_user: UserModel = Depends(get_current_user),
) -> dict:
    """
    Check if current user requires password change.

    This endpoint can be used by clients to check if the user
    needs to change their password before accessing other resources.

    Args:
        current_user: Currently authenticated user

    Returns:
        Dictionary with password change requirement status
    """
    return {"requires_password_change": current_user.requires_password_change, "username": current_user.username}
