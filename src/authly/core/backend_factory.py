"""Backend factory for creating appropriate backend implementations.

This module provides factory functions that create the right backend
implementations based on configuration and resource availability.
"""

import logging
from typing import TYPE_CHECKING

from authly.core.backends import (
    CacheBackend,
    MemoryCacheBackend,
    MemoryRateLimitBackend,
    MemorySessionBackend,
    RateLimitBackend,
    SessionBackend,
)

# Try to import Redis backends, but don't fail if they're not available
try:
    from authly.core.backends import (
        RedisCacheBackend,
        RedisRateLimitBackend,
        RedisSessionBackend,
    )

    REDIS_BACKENDS_AVAILABLE = True
except ImportError:
    # Define dummy classes to avoid NameError
    RedisCacheBackend = None
    RedisRateLimitBackend = None
    RedisSessionBackend = None
    REDIS_BACKENDS_AVAILABLE = False

if TYPE_CHECKING:
    from authly.core.resource_manager import AuthlyResourceManager

logger = logging.getLogger(__name__)


class BackendFactory:
    """Factory for creating backend implementations based on configuration."""

    def __init__(self, resource_manager: "AuthlyResourceManager"):
        """Initialize factory with resource manager.

        Args:
            resource_manager: The resource manager instance
        """
        self.resource_manager = resource_manager
        self.config = resource_manager.get_config()
        # Cache backend instances to ensure they're shared
        self._rate_limit_backend = None
        self._cache_backend = None
        self._session_backend = None

    async def create_rate_limit_backend(self) -> RateLimitBackend:
        """Create rate limiting backend.

        Returns:
            RateLimitBackend implementation (Redis or memory)
        """
        # Return cached instance if available
        if self._rate_limit_backend is not None:
            return self._rate_limit_backend

        if self.config.redis_rate_limit_enabled and self.resource_manager.redis_available:
            if REDIS_BACKENDS_AVAILABLE and RedisRateLimitBackend is not None:
                try:
                    redis_client = self.resource_manager.get_redis_client()
                    logger.info("Using Redis rate limiting backend")
                    self._rate_limit_backend = RedisRateLimitBackend(redis_client)
                    return self._rate_limit_backend
                except Exception as e:
                    logger.error(f"Failed to create Redis rate limit backend: {e}, falling back to memory")
            else:
                logger.warning("Redis rate limiting requested but Redis backends not available, falling back to memory")

        logger.info("Using memory rate limiting backend")
        self._rate_limit_backend = MemoryRateLimitBackend()
        return self._rate_limit_backend

    async def create_cache_backend(self) -> CacheBackend:
        """Create caching backend.

        Returns:
            CacheBackend implementation (Redis or memory)
        """
        # Return cached instance if available
        if self._cache_backend is not None:
            return self._cache_backend

        if self.config.redis_cache_enabled and self.resource_manager.redis_available:
            if REDIS_BACKENDS_AVAILABLE and RedisCacheBackend is not None:
                try:
                    redis_client = self.resource_manager.get_redis_client()
                    logger.info("Using Redis caching backend")
                    self._cache_backend = RedisCacheBackend(redis_client)
                    return self._cache_backend
                except Exception as e:
                    logger.error(f"Failed to create Redis cache backend: {e}, falling back to memory")
            else:
                logger.warning("Redis caching requested but Redis backends not available, falling back to memory")

        logger.info("Using memory caching backend")
        self._cache_backend = MemoryCacheBackend()
        return self._cache_backend

    async def create_session_backend(self) -> SessionBackend:
        """Create session storage backend.

        Returns:
            SessionBackend implementation (Redis or memory)
        """
        # Return cached instance if available
        if self._session_backend is not None:
            return self._session_backend

        if self.config.redis_session_enabled and self.resource_manager.redis_available:
            if REDIS_BACKENDS_AVAILABLE and RedisSessionBackend is not None:
                try:
                    redis_client = self.resource_manager.get_redis_client()
                    logger.info("Using Redis session backend")
                    self._session_backend = RedisSessionBackend(redis_client)
                    return self._session_backend
                except Exception as e:
                    logger.error(f"Failed to create Redis session backend: {e}, falling back to memory")
            else:
                logger.warning("Redis sessions requested but Redis backends not available, falling back to memory")

        logger.info("Using memory session backend")
        self._session_backend = MemorySessionBackend()
        return self._session_backend


# Global factory instance (will be initialized by dependency injection)
_backend_factory: BackendFactory | None = None


def initialize_backend_factory(resource_manager: "AuthlyResourceManager") -> None:
    """Initialize global backend factory.

    Args:
        resource_manager: The resource manager instance
    """
    global _backend_factory
    _backend_factory = BackendFactory(resource_manager)
    logger.info("Backend factory initialized")


def get_backend_factory() -> BackendFactory:
    """Get the global backend factory instance.

    Returns:
        BackendFactory instance

    Raises:
        RuntimeError: If factory not initialized
    """
    if _backend_factory is None:
        raise RuntimeError("Backend factory not initialized. Call initialize_backend_factory() first.")
    return _backend_factory


# Convenience functions for direct backend access


async def get_rate_limit_backend() -> RateLimitBackend:
    """Get rate limiting backend instance.

    Returns:
        RateLimitBackend implementation
    """
    factory = get_backend_factory()
    return await factory.create_rate_limit_backend()


async def get_cache_backend() -> CacheBackend:
    """Get caching backend instance.

    Returns:
        CacheBackend implementation
    """
    factory = get_backend_factory()
    return await factory.create_cache_backend()


async def get_session_backend() -> SessionBackend:
    """Get session storage backend instance.

    Returns:
        SessionBackend implementation
    """
    factory = get_backend_factory()
    return await factory.create_session_backend()
