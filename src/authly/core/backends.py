"""Backend abstraction layer for optional Redis integration.

This module provides abstract interfaces and concrete implementations for
different backend services, allowing flexible deployment configurations
with automatic fallback to memory-based implementations.
"""

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


class RateLimitBackend(ABC):
    """Abstract interface for rate limiting backends."""

    @abstractmethod
    async def check_rate_limit(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """Check if request is within rate limit.

        Args:
            key: Unique identifier for the rate limit (e.g., IP address, user ID)
            max_requests: Maximum requests allowed in the window
            window_seconds: Time window in seconds

        Returns:
            True if request is allowed, raises HTTPException if rate limited

        Raises:
            HTTPException: When rate limit is exceeded
        """
        pass

    @abstractmethod
    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for a specific key.

        Args:
            key: Unique identifier for the rate limit

        Returns:
            True if reset was successful
        """
        pass


class CacheBackend(ABC):
    """Abstract interface for caching backends."""

    @abstractmethod
    async def get(self, key: str) -> str | None:
        """Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value as string or None if not found
        """
        pass

    @abstractmethod
    async def set(self, key: str, value: str, ttl: int | None = None) -> bool:
        """Set value in cache.

        Args:
            key: Cache key
            value: Value to cache (as string)
            ttl: Time to live in seconds (None for no expiration)

        Returns:
            True if set was successful
        """
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete value from cache.

        Args:
            key: Cache key

        Returns:
            True if delete was successful
        """
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        Args:
            key: Cache key

        Returns:
            True if key exists
        """
        pass


class SessionBackend(ABC):
    """Abstract interface for session storage backends."""

    @abstractmethod
    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get session data.

        Args:
            session_id: Session identifier

        Returns:
            Session data as dictionary or None if not found
        """
        pass

    @abstractmethod
    async def set_session(self, session_id: str, data: dict[str, Any], ttl: int | None = None) -> bool:
        """Set session data.

        Args:
            session_id: Session identifier
            data: Session data as dictionary
            ttl: Time to live in seconds (None for no expiration)

        Returns:
            True if set was successful
        """
        pass

    @abstractmethod
    async def delete_session(self, session_id: str) -> bool:
        """Delete session.

        Args:
            session_id: Session identifier

        Returns:
            True if delete was successful
        """
        pass


# Memory-based implementations (fallback)


class MemoryRateLimitBackend(RateLimitBackend):
    """In-memory rate limiting backend."""

    def __init__(self):
        self.requests: dict[str, list[datetime]] = {}

    async def check_rate_limit(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """Check rate limit using in-memory storage."""
        from fastapi import HTTPException
        from starlette import status

        now = datetime.now()
        window_start = now - timedelta(seconds=window_seconds)

        if key not in self.requests:
            self.requests[key] = []

        # Clean old requests
        self.requests[key] = [t for t in self.requests[key] if t > window_start]

        if len(self.requests[key]) >= max_requests:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

        self.requests[key].append(now)
        return True

    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for key."""
        if key in self.requests:
            del self.requests[key]
        return True


class MemoryCacheBackend(CacheBackend):
    """In-memory caching backend."""

    def __init__(self):
        self.cache: dict[str, dict[str, str | datetime]] = {}

    async def get(self, key: str) -> str | None:
        """Get value from memory cache."""
        if key not in self.cache:
            return None

        entry = self.cache[key]
        expires_at = entry.get("expires_at")

        # Check expiration
        if expires_at and isinstance(expires_at, datetime) and datetime.now() > expires_at:
            del self.cache[key]
            return None

        return entry["value"]

    async def set(self, key: str, value: str, ttl: int | None = None) -> bool:
        """Set value in memory cache."""
        expires_at = None
        if ttl:
            expires_at = datetime.now() + timedelta(seconds=ttl)

        self.cache[key] = {"value": value, "expires_at": expires_at}
        return True

    async def delete(self, key: str) -> bool:
        """Delete value from memory cache."""
        if key in self.cache:
            del self.cache[key]
            return True
        return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in memory cache."""
        if key not in self.cache:
            return False

        # Check expiration
        entry = self.cache[key]
        expires_at = entry.get("expires_at")

        if expires_at and isinstance(expires_at, datetime) and datetime.now() > expires_at:
            del self.cache[key]
            return False

        return True


class MemorySessionBackend(SessionBackend):
    """In-memory session storage backend."""

    def __init__(self):
        self.sessions: dict[str, dict[str, dict[str, Any] | datetime]] = {}

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get session from memory storage."""
        if session_id not in self.sessions:
            return None

        entry = self.sessions[session_id]
        expires_at = entry.get("expires_at")

        # Check expiration
        if expires_at and isinstance(expires_at, datetime) and datetime.now() > expires_at:
            del self.sessions[session_id]
            return None

        return entry["data"]

    async def set_session(self, session_id: str, data: dict[str, Any], ttl: int | None = None) -> bool:
        """Set session in memory storage."""
        expires_at = None
        if ttl:
            expires_at = datetime.now() + timedelta(seconds=ttl)

        self.sessions[session_id] = {"data": data, "expires_at": expires_at}
        return True

    async def delete_session(self, session_id: str) -> bool:
        """Delete session from memory storage."""
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False


# Redis-based implementations (optional)


class RedisRateLimitBackend(RateLimitBackend):
    """Redis-based rate limiting backend using sliding window."""

    def __init__(self, redis_client):
        self.redis = redis_client

    async def check_rate_limit(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """Check rate limit using Redis sliding window."""
        from fastapi import HTTPException
        from starlette import status

        try:
            now = datetime.now().timestamp()
            window_start = now - window_seconds

            # Use Redis pipeline for atomic operations
            pipe = self.redis.pipeline()

            # Remove expired entries
            pipe.zremrangebyscore(key, 0, window_start)

            # Count current requests in window
            pipe.zcard(key)

            # Execute pipeline
            results = await pipe.execute()
            current_requests = results[1]

            if current_requests >= max_requests:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

            # Add current request
            await self.redis.zadd(key, {str(now): now})

            # Set expiration for cleanup
            await self.redis.expire(key, window_seconds)

            return True

        except Exception as e:
            logger.error(f"Redis rate limit error: {e}")
            # Fall back to allowing the request on Redis error
            return True

    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for key in Redis."""
        try:
            await self.redis.delete(key)
            return True
        except Exception as e:
            logger.error(f"Redis rate limit reset error: {e}")
            return False


class RedisCacheBackend(CacheBackend):
    """Redis-based caching backend."""

    def __init__(self, redis_client):
        self.redis = redis_client

    async def get(self, key: str) -> str | None:
        """Get value from Redis cache."""
        try:
            value = await self.redis.get(key)
            return value.decode() if value else None
        except Exception as e:
            logger.error(f"Redis cache get error: {e}")
            return None

    async def set(self, key: str, value: str, ttl: int | None = None) -> bool:
        """Set value in Redis cache."""
        try:
            if ttl:
                await self.redis.setex(key, ttl, value)
            else:
                await self.redis.set(key, value)
            return True
        except Exception as e:
            logger.error(f"Redis cache set error: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete value from Redis cache."""
        try:
            result = await self.redis.delete(key)
            return result > 0
        except Exception as e:
            logger.error(f"Redis cache delete error: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in Redis cache."""
        try:
            result = await self.redis.exists(key)
            return result > 0
        except Exception as e:
            logger.error(f"Redis cache exists error: {e}")
            return False


class RedisSessionBackend(SessionBackend):
    """Redis-based session storage backend."""

    def __init__(self, redis_client, key_prefix: str = "session:"):
        self.redis = redis_client
        self.key_prefix = key_prefix

    def _session_key(self, session_id: str) -> str:
        """Generate Redis key for session."""
        return f"{self.key_prefix}{session_id}"

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get session from Redis storage."""
        try:
            key = self._session_key(session_id)
            data = await self.redis.get(key)
            if data:
                return json.loads(data.decode())
            return None
        except Exception as e:
            logger.error(f"Redis session get error: {e}")
            return None

    async def set_session(self, session_id: str, data: dict[str, Any], ttl: int | None = None) -> bool:
        """Set session in Redis storage."""
        try:
            key = self._session_key(session_id)
            serialized_data = json.dumps(data)

            if ttl:
                await self.redis.setex(key, ttl, serialized_data)
            else:
                await self.redis.set(key, serialized_data)
            return True
        except Exception as e:
            logger.error(f"Redis session set error: {e}")
            return False

    async def delete_session(self, session_id: str) -> bool:
        """Delete session from Redis storage."""
        try:
            key = self._session_key(session_id)
            result = await self.redis.delete(key)
            return result > 0
        except Exception as e:
            logger.error(f"Redis session delete error: {e}")
            return False
