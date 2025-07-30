from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import HTTPException
from starlette import status


class RateLimiter:
    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        """
        Initialize rate limiter with fixed limits.

        Args:
            max_requests: Maximum requests allowed per window (default 5)
            window_seconds: Time window in seconds (default 60)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list[datetime]] = {}

    async def check_rate_limit(self, key: str) -> bool:
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window_seconds)

        if key not in self.requests:
            self.requests[key] = []

        # Clean old requests
        self.requests[key] = [t for t in self.requests[key] if t > window_start]

        if len(self.requests[key]) >= self.max_requests:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

        self.requests[key].append(now)
        return True
