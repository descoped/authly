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

    async def create_rate_limit_backend(self) -> RateLimitBackend:
        """Create rate limiting backend.

        Returns:
            RateLimitBackend implementation (Redis or memory)
        """
        if self.config.redis_rate_limit_enabled and self.resource_manager.redis_available:
            try:
                from authly.core.backends import RedisRateLimitBackend

                redis_client = self.resource_manager.get_redis_client()
                logger.info("Using Redis rate limiting backend")
                return RedisRateLimitBackend(redis_client)
            except ImportError:
                logger.warning("Redis rate limiting requested but Redis not available, falling back to memory")
            except Exception as e:
                logger.error(f"Failed to create Redis rate limit backend: {e}, falling back to memory")

        logger.info("Using memory rate limiting backend")
        return MemoryRateLimitBackend()

    async def create_cache_backend(self) -> CacheBackend:
        """Create caching backend.

        Returns:
            CacheBackend implementation (Redis or memory)
        """
        if self.config.redis_cache_enabled and self.resource_manager.redis_available:
            try:
                from authly.core.backends import RedisCacheBackend

                redis_client = self.resource_manager.get_redis_client()
                logger.info("Using Redis caching backend")
                return RedisCacheBackend(redis_client)
            except ImportError:
                logger.warning("Redis caching requested but Redis not available, falling back to memory")
            except Exception as e:
                logger.error(f"Failed to create Redis cache backend: {e}, falling back to memory")

        logger.info("Using memory caching backend")
        return MemoryCacheBackend()

    async def create_session_backend(self) -> SessionBackend:
        """Create session storage backend.

        Returns:
            SessionBackend implementation (Redis or memory)
        """
        if self.config.redis_session_enabled and self.resource_manager.redis_available:
            try:
                from authly.core.backends import RedisSessionBackend

                redis_client = self.resource_manager.get_redis_client()
                logger.info("Using Redis session backend")
                return RedisSessionBackend(redis_client)
            except ImportError:
                logger.warning("Redis sessions requested but Redis not available, falling back to memory")
            except Exception as e:
                logger.error(f"Failed to create Redis session backend: {e}, falling back to memory")

        logger.info("Using memory session backend")
        return MemorySessionBackend()


# Global factory instance (will be initialized by dependency injection)
_backend_factory: BackendFactory = None


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
