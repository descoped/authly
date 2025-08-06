"""Rate limiter with configurable backend support.

This module provides rate limiting functionality with support for both
memory-based and Redis-based backends, allowing flexible deployment
configurations.
"""

import logging

from authly.core.backend_factory import get_rate_limit_backend
from authly.core.backends import RateLimitBackend

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter with configurable backend support."""

    def __init__(self, max_requests: int = 5, window_seconds: int = 60, backend: RateLimitBackend | None = None):
        """Initialize rate limiter with configurable backend.

        Args:
            max_requests: Maximum requests allowed per window (default 5)
            window_seconds: Time window in seconds (default 60)
            backend: Optional backend implementation (will be auto-created if None)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._backend = backend

    async def _get_backend(self) -> RateLimitBackend:
        """Get backend implementation, creating it if necessary."""
        if self._backend is None:
            self._backend = await get_rate_limit_backend()
        return self._backend

    async def check_rate_limit(self, key: str) -> bool:
        """Check if request is within rate limit.

        Args:
            key: Unique identifier for the rate limit (e.g., IP address, user ID)

        Returns:
            True if request is allowed

        Raises:
            HTTPException: When rate limit is exceeded
        """
        backend = await self._get_backend()
        return await backend.check_rate_limit(key, self.max_requests, self.window_seconds)

    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for a specific key.

        Args:
            key: Unique identifier for the rate limit

        Returns:
            True if reset was successful
        """
        backend = await self._get_backend()
        return await backend.reset_rate_limit(key)
