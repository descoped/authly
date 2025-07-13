from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import HTTPException
from starlette import status


class RateLimiter:
    def __init__(self, max_requests: Optional[int] = None, window_seconds: Optional[int] = None):
        # Use config values if not provided
        if max_requests is None or window_seconds is None:
            try:
                from authly import get_config

                config = get_config()
                self.max_requests = max_requests or config.rate_limit_max_requests
                self.window_seconds = window_seconds or config.rate_limit_window_seconds
            except RuntimeError:
                # Fallback for tests without full Authly initialization
                self.max_requests = max_requests or 5
                self.window_seconds = window_seconds or 60
        else:
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
