"""
Admin permission checking with caching support.

This module provides cached permission checks for admin operations
to improve performance by avoiding repeated database queries.
"""

import logging
from uuid import UUID

from authly.admin.cache import AdminCacheService
from authly.users.models import UserModel

logger = logging.getLogger(__name__)


class AdminPermissionService:
    """
    Service for checking admin permissions with caching.

    Provides fast permission checks by caching results of common
    permission queries like "can admin modify user".
    """

    def __init__(self, cache_service: AdminCacheService | None = None):
        """
        Initialize permission service.

        Args:
            cache_service: Optional cache service for performance
        """
        self.cache = cache_service or AdminCacheService()

    async def can_modify_user(self, admin: UserModel, target_user_id: UUID, action: str = "modify") -> bool:
        """
        Check if admin can modify a target user with caching.

        Args:
            admin: Admin user performing the action
            target_user_id: ID of user being modified
            action: Type of modification (modify, delete, etc.)

        Returns:
            True if admin can perform the action
        """
        # Admin must have is_admin flag
        if not admin.is_admin:
            return False

        # Check cache first
        cached_result = await self.cache.check_permission(admin_id=admin.id, target_id=target_user_id, action=action)

        if cached_result is not None:
            logger.debug(
                f"Permission cache hit: admin={admin.id}, target={target_user_id}, "
                f"action={action}, allowed={cached_result}"
            )
            return cached_result

        # For now, admins can modify any user except for specific business rules
        # These rules are enforced in the validation layer
        allowed = True

        # Special case: cannot remove own admin status
        if action == "remove_admin" and admin.id == target_user_id:
            allowed = False

        # Cache the result
        await self.cache.set_permission(admin_id=admin.id, target_id=target_user_id, action=action, allowed=allowed)

        logger.debug(f"Permission check: admin={admin.id}, target={target_user_id}, action={action}, allowed={allowed}")

        return allowed

    async def can_delete_user(self, admin: UserModel, target_user_id: UUID) -> bool:
        """
        Check if admin can delete a target user.

        Args:
            admin: Admin user performing deletion
            target_user_id: ID of user to delete

        Returns:
            True if admin can delete the user
        """
        return await self.can_modify_user(admin, target_user_id, "delete")

    async def can_update_user(self, admin: UserModel, target_user_id: UUID, update_fields: set | None = None) -> bool:
        """
        Check if admin can update a target user.

        Args:
            admin: Admin user performing update
            target_user_id: ID of user to update
            update_fields: Optional set of fields being updated

        Returns:
            True if admin can update the user
        """
        # Check if updating admin status
        if update_fields and "is_admin" in update_fields and admin.id == target_user_id:
            # Cannot remove own admin status
            return await self.can_modify_user(admin, target_user_id, "remove_admin")

        return await self.can_modify_user(admin, target_user_id, "update")

    async def can_reset_password(self, admin: UserModel, target_user_id: UUID) -> bool:
        """
        Check if admin can reset a user's password.

        Args:
            admin: Admin user performing reset
            target_user_id: ID of user whose password to reset

        Returns:
            True if admin can reset the password
        """
        return await self.can_modify_user(admin, target_user_id, "reset_password")

    async def can_manage_sessions(self, admin: UserModel, target_user_id: UUID) -> bool:
        """
        Check if admin can manage a user's sessions.

        Args:
            admin: Admin user performing session management
            target_user_id: ID of user whose sessions to manage

        Returns:
            True if admin can manage sessions
        """
        return await self.can_modify_user(admin, target_user_id, "manage_sessions")

    async def invalidate_admin_permissions(self, admin_id: UUID):
        """
        Invalidate all cached permissions for an admin.

        Called when admin privileges change.

        Args:
            admin_id: ID of admin whose permissions to invalidate
        """
        await self.cache.invalidate_permissions(admin_id)
        logger.info(f"Invalidated permission cache for admin: {admin_id}")
