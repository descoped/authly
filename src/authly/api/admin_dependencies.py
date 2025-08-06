"""
Admin Authentication Dependencies for Authly authentication service.

This module provides authentication and authorization dependencies for admin API endpoints,
implementing the two-layer security model:
1. Intrinsic User Authority (is_admin flag)
2. Scoped Permissions (OAuth admin scopes)
"""

import logging
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from authly.api.users_dependencies import get_current_user
from authly.core.dependencies import get_config
from authly.users.models import UserModel

if TYPE_CHECKING:
    from authly.config import AuthlyConfig

logger = logging.getLogger(__name__)

# OAuth2 scheme for admin API
admin_bearer = HTTPBearer(scheme_name="AdminBearer")

# Admin scope definitions - registered during system initialization
ADMIN_SCOPES = {
    "admin:clients:read": "Read OAuth client configurations",
    "admin:clients:write": "Create and modify OAuth clients",
    "admin:scopes:read": "Read OAuth scope definitions",
    "admin:scopes:write": "Create and modify OAuth scopes",
    "admin:users:read": "Read user accounts",
    "admin:users:write": "Create and modify user accounts",
    "admin:system:read": "Read system status and configuration",
    "admin:system:write": "Modify system configuration",
}


async def require_admin_user(current_user: UserModel = Depends(get_current_user)) -> UserModel:
    """
    Require intrinsic admin authority.

    This dependency validates that the current user has the is_admin flag set,
    which represents intrinsic administrative capability at the database level.
    This is the first layer of the two-layer security model.

    Args:
        current_user: Current authenticated user from JWT token

    Returns:
        UserModel with verified admin authority

    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_admin:
        logger.warning(f"Admin access denied for non-admin user: {current_user.username} (user_id: {current_user.id})")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required. User must have admin authority.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    logger.info(f"Admin authority verified for user: {current_user.username}")
    return current_user


def require_admin_scope(required_scope: str):
    """
    Factory function to create admin scope validation dependency.

    This creates a dependency that validates both intrinsic admin authority
    and specific OAuth scopes. This is the second layer of the two-layer
    security model.

    Args:
        required_scope: The admin scope required (e.g., "admin:clients:write")

    Returns:
        FastAPI dependency function that validates scope permissions
    """

    async def validate_admin_scope(
        admin_user: UserModel = Depends(require_admin_user),
        credentials: HTTPAuthorizationCredentials = Depends(admin_bearer),
        config: "AuthlyConfig" = Depends(get_config),
    ) -> UserModel:
        """
        Validate admin scope permissions.

        This dependency validates that the admin user's token contains
        the required scope for the operation.

        Args:
            admin_user: Verified admin user from require_admin_user
            credentials: HTTP Bearer token credentials

        Returns:
            UserModel with verified admin authority and scope permissions

        Raises:
            HTTPException: If scope validation fails
        """
        # Validate the required scope exists
        if required_scope not in ADMIN_SCOPES:
            logger.error(f"Unknown admin scope requested: {required_scope}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unknown admin scope: {required_scope}"
            )

        try:
            # Decode and validate JWT token
            payload = jwt.decode(credentials.credentials, config.secret_key, algorithms=[config.algorithm])

            # Extract scopes from token (OAuth 2.1 uses "scope" as space-separated string)
            scope_string = payload.get("scope", "")
            token_scopes = scope_string.split() if scope_string else []

            # Validate required scope is present
            if required_scope not in token_scopes:
                logger.warning(
                    f"Admin scope denied for user {admin_user.username}: "
                    f"required '{required_scope}', has {token_scopes}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required admin scope: {required_scope}",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            logger.info(f"Admin scope validated for user {admin_user.username}: scope '{required_scope}'")

            return admin_user

        except HTTPException:
            # Let HTTPExceptions pass through
            raise
        except JWTError as e:
            logger.warning(f"JWT validation failed for admin scope check: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except Exception as e:
            logger.error(f"Admin scope validation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Admin scope validation failed"
            ) from None

    return validate_admin_scope


async def get_admin_scopes() -> dict[str, str]:
    """
    Get all available admin scopes and their descriptions.

    Returns:
        Dictionary mapping scope names to descriptions
    """
    return ADMIN_SCOPES.copy()


async def validate_admin_scopes(scopes: list[str]) -> list[str]:
    """
    Validate that the provided scopes are valid admin scopes.

    Args:
        scopes: List of scope names to validate

    Returns:
        List of valid scope names

    Raises:
        HTTPException: If any scope is invalid
    """
    invalid_scopes = [scope for scope in scopes if scope not in ADMIN_SCOPES]

    if invalid_scopes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid admin scopes: {', '.join(invalid_scopes)}"
        )

    return scopes


# Convenience dependencies for common admin operations
require_admin_client_read = require_admin_scope("admin:clients:read")
require_admin_client_write = require_admin_scope("admin:clients:write")
require_admin_scope_read = require_admin_scope("admin:scopes:read")
require_admin_scope_write = require_admin_scope("admin:scopes:write")
require_admin_user_read = require_admin_scope("admin:users:read")
require_admin_user_write = require_admin_scope("admin:users:write")
require_admin_system_read = require_admin_scope("admin:system:read")
require_admin_system_write = require_admin_scope("admin:system:write")
