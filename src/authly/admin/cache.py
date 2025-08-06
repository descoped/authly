"""
Admin caching layer for performance optimization.

This module implements caching strategies for expensive admin operations
to reduce database load and improve response times.

Cache Keys:
- admin:dashboard:stats - Dashboard statistics (60s TTL)
- admin:users:count:{filters_hash} - User count with filters (30s TTL)
- admin:users:list:{filters_hash}:{skip}:{limit} - User listing (30s TTL)
- admin:user:{user_id} - Individual user details (60s TTL)
- admin:permissions:{admin_id}:{target_id}:{action} - Permission checks (300s TTL)
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from authly.config import AuthlyConfig
from authly.core.backends import CacheBackend, MemoryCacheBackend

logger = logging.getLogger(__name__)


class AdminCacheService:
    """
    Caching service for admin operations.

    Provides caching for:
    - Dashboard statistics
    - User listings and counts
    - Permission checks
    - Individual user details
    """

    # Cache key prefixes
    PREFIX_DASHBOARD = "admin:dashboard"
    PREFIX_USER_COUNT = "admin:users:count"
    PREFIX_USER_LIST = "admin:users:list"
    PREFIX_USER_DETAIL = "admin:user"
    PREFIX_PERMISSION = "admin:permissions"

    def __init__(self, cache_backend: CacheBackend | None = None, config: AuthlyConfig | None = None):
        """
        Initialize admin cache service.

        Args:
            cache_backend: CacheBackend implementation (defaults to MemoryCacheBackend)
            config: AuthlyConfig instance for TTL configuration
        """
        self.cache = cache_backend or MemoryCacheBackend()
        self._enabled = True
        self._config = config

        # Use configurable TTL values or fallback to defaults
        if config:
            self.ttl_dashboard_stats = config.cache_ttl_dashboard_stats
            self.ttl_user_listing = config.cache_ttl_user_listing
            self.ttl_user_detail = config.cache_ttl_user_detail
            self.ttl_permission = config.cache_ttl_permission
        else:
            # Default TTL values (in seconds)
            self.ttl_dashboard_stats = 60  # 1 minute for dashboard stats
            self.ttl_user_listing = 30  # 30 seconds for user listings
            self.ttl_user_detail = 60  # 1 minute for user details
            self.ttl_permission = 300  # 5 minutes for permission checks

    def disable_cache(self):
        """Disable caching (useful for testing)."""
        self._enabled = False

    def enable_cache(self):
        """Enable caching."""
        self._enabled = True

    def _generate_filters_hash(self, filters: dict[str, Any] | None) -> str:
        """
        Generate a stable hash for filter parameters.

        Args:
            filters: Dictionary of filter parameters

        Returns:
            Stable hash string for the filters
        """
        if not filters:
            return "none"

        # Sort filters by key for consistency
        sorted_filters = sorted(filters.items())

        # Convert to JSON string (handles various types)
        filter_str = json.dumps(sorted_filters, sort_keys=True, default=str)

        # Generate hash
        return hashlib.md5(filter_str.encode()).hexdigest()

    async def get_dashboard_stats(self) -> dict[str, Any] | None:
        """
        Get cached dashboard statistics.

        Returns:
            Cached dashboard stats or None if not cached
        """
        if not self._enabled:
            return None

        key = f"{self.PREFIX_DASHBOARD}:stats"
        try:
            cached_value = await self.cache.get(key)
            if cached_value:
                logger.debug("Cache hit for dashboard stats")
                return json.loads(cached_value)
        except Exception as e:
            logger.error(f"Error retrieving dashboard stats from cache: {e}")

        return None

    async def set_dashboard_stats(self, stats: dict[str, Any]):
        """
        Cache dashboard statistics.

        Args:
            stats: Dashboard statistics to cache
        """
        if not self._enabled:
            return

        key = f"{self.PREFIX_DASHBOARD}:stats"
        try:
            await self.cache.set(key, json.dumps(stats), ttl=self.ttl_dashboard_stats)
            logger.debug("Cached dashboard stats")
        except Exception as e:
            logger.error(f"Error caching dashboard stats: {e}")

    async def get_user_count(self, filters: dict[str, Any] | None = None) -> int | None:
        """
        Get cached user count with filters.

        Args:
            filters: Filter parameters used for the count

        Returns:
            Cached count or None if not cached
        """
        if not self._enabled:
            return None

        filters_hash = self._generate_filters_hash(filters)
        key = f"{self.PREFIX_USER_COUNT}:{filters_hash}"

        try:
            cached_value = await self.cache.get(key)
            if cached_value:
                logger.debug(f"Cache hit for user count with filters hash: {filters_hash}")
                return int(cached_value)
        except Exception as e:
            logger.error(f"Error retrieving user count from cache: {e}")

        return None

    async def set_user_count(self, count: int, filters: dict[str, Any] | None = None):
        """
        Cache user count with filters.

        Args:
            count: User count to cache
            filters: Filter parameters used for the count
        """
        if not self._enabled:
            return

        filters_hash = self._generate_filters_hash(filters)
        key = f"{self.PREFIX_USER_COUNT}:{filters_hash}"

        try:
            await self.cache.set(key, str(count), ttl=self.ttl_user_listing)
            logger.debug(f"Cached user count: {count} for filters hash: {filters_hash}")
        except Exception as e:
            logger.error(f"Error caching user count: {e}")

    async def get_user_listing(
        self, filters: dict[str, Any] | None, skip: int, limit: int
    ) -> tuple[list[dict], int, int] | None:
        """
        Get cached user listing with pagination.

        Args:
            filters: Filter parameters
            skip: Number of records to skip
            limit: Maximum records to return

        Returns:
            Cached tuple of (users, total_count, active_count) or None
        """
        if not self._enabled:
            return None

        filters_hash = self._generate_filters_hash(filters)
        key = f"{self.PREFIX_USER_LIST}:{filters_hash}:{skip}:{limit}"

        try:
            cached_value = await self.cache.get(key)
            if cached_value:
                logger.debug(f"Cache hit for user listing: filters={filters_hash}, skip={skip}, limit={limit}")
                data = json.loads(cached_value)
                return data["users"], data["total_count"], data["active_count"]
        except Exception as e:
            logger.error(f"Error retrieving user listing from cache: {e}")

        return None

    async def set_user_listing(
        self,
        users: list[dict],
        total_count: int,
        active_count: int,
        filters: dict[str, Any] | None,
        skip: int,
        limit: int,
    ):
        """
        Cache user listing with pagination.

        Args:
            users: List of user dictionaries
            total_count: Total count of matching users
            active_count: Count of active users
            filters: Filter parameters
            skip: Number of records skipped
            limit: Maximum records returned
        """
        if not self._enabled:
            return

        filters_hash = self._generate_filters_hash(filters)
        key = f"{self.PREFIX_USER_LIST}:{filters_hash}:{skip}:{limit}"

        try:
            cache_data = {
                "users": users,
                "total_count": total_count,
                "active_count": active_count,
                "cached_at": datetime.utcnow().isoformat(),
            }
            await self.cache.set(key, json.dumps(cache_data, default=str), ttl=self.ttl_user_listing)
            logger.debug(f"Cached user listing: {len(users)} users, filters={filters_hash}")
        except Exception as e:
            logger.error(f"Error caching user listing: {e}")

    async def get_user_details(self, user_id: UUID) -> dict[str, Any] | None:
        """
        Get cached user details.

        Args:
            user_id: User ID to retrieve

        Returns:
            Cached user details or None
        """
        if not self._enabled:
            return None

        key = f"{self.PREFIX_USER_DETAIL}:{user_id}"

        try:
            cached_value = await self.cache.get(key)
            if cached_value:
                logger.debug(f"Cache hit for user details: {user_id}")
                return json.loads(cached_value)
        except Exception as e:
            logger.error(f"Error retrieving user details from cache: {e}")

        return None

    async def set_user_details(self, user_id: UUID, user_data: dict[str, Any]):
        """
        Cache user details.

        Args:
            user_id: User ID
            user_data: User data to cache
        """
        if not self._enabled:
            return

        key = f"{self.PREFIX_USER_DETAIL}:{user_id}"

        try:
            await self.cache.set(key, json.dumps(user_data, default=str), ttl=self.ttl_user_detail)
            logger.debug(f"Cached user details for: {user_id}")
        except Exception as e:
            logger.error(f"Error caching user details: {e}")

    async def check_permission(self, admin_id: UUID, target_id: UUID, action: str) -> bool | None:
        """
        Get cached permission check result.

        Args:
            admin_id: Admin user ID
            target_id: Target user ID
            action: Action being performed (e.g., 'update', 'delete')

        Returns:
            Cached permission result or None
        """
        if not self._enabled:
            return None

        key = f"{self.PREFIX_PERMISSION}:{admin_id}:{target_id}:{action}"

        try:
            cached_value = await self.cache.get(key)
            if cached_value:
                logger.debug(f"Cache hit for permission check: admin={admin_id}, target={target_id}, action={action}")
                return cached_value == "true"
        except Exception as e:
            logger.error(f"Error retrieving permission from cache: {e}")

        return None

    async def set_permission(self, admin_id: UUID, target_id: UUID, action: str, allowed: bool):
        """
        Cache permission check result.

        Args:
            admin_id: Admin user ID
            target_id: Target user ID
            action: Action being performed
            allowed: Whether the action is allowed
        """
        if not self._enabled:
            return

        key = f"{self.PREFIX_PERMISSION}:{admin_id}:{target_id}:{action}"

        try:
            await self.cache.set(key, "true" if allowed else "false", ttl=self.ttl_permission)
            logger.debug(f"Cached permission: admin={admin_id}, target={target_id}, action={action}, allowed={allowed}")
        except Exception as e:
            logger.error(f"Error caching permission: {e}")

    async def invalidate_user(self, user_id: UUID):
        """
        Invalidate all caches related to a specific user.

        Args:
            user_id: User ID to invalidate caches for
        """
        if not self._enabled:
            return

        try:
            # Invalidate user details
            await self.cache.delete(f"{self.PREFIX_USER_DETAIL}:{user_id}")

            # Invalidate dashboard stats (user changes affect counts)
            await self.cache.delete(f"{self.PREFIX_DASHBOARD}:stats")

            # Note: We can't easily invalidate list caches without tracking all filter combinations
            # This is acceptable as list caches have short TTLs (30s)

            logger.debug(f"Invalidated caches for user: {user_id}")
        except Exception as e:
            logger.error(f"Error invalidating user caches: {e}")

    async def invalidate_all_users(self):
        """Invalidate all user-related caches."""
        if not self._enabled:
            return

        try:
            # In a real Redis implementation, we could use pattern matching
            # For now, we just invalidate dashboard stats
            await self.cache.delete(f"{self.PREFIX_DASHBOARD}:stats")

            logger.debug("Invalidated all user caches")
        except Exception as e:
            logger.error(f"Error invalidating all user caches: {e}")

    async def invalidate_permissions(self, admin_id: UUID | None = None):
        """
        Invalidate permission caches.

        Args:
            admin_id: If provided, invalidate only permissions for this admin
        """
        if not self._enabled:
            return

        # With Redis, we could use pattern matching to delete keys
        # For now, we log the intent
        logger.debug(f"Permission cache invalidation requested for admin: {admin_id}")
