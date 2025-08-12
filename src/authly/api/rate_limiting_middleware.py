"""
Rate limiting middleware for OAuth 2.1 compliance.

Implements rate limiting at the middleware layer to protect token endpoints
and other sensitive operations from abuse.
"""

import logging
from collections.abc import Callable

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from authly.api.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that implements rate limiting for OAuth endpoints.

    Returns 429 Too Many Requests when rate limits are exceeded,
    as required by OAuth 2.1 compliance testing.
    """

    def __init__(
        self,
        app,
        max_requests: int = 10,
        window_seconds: int = 60,
        paths_to_limit: list[str] | None = None,
    ):
        """
        Initialize rate limiting middleware.

        Args:
            app: FastAPI application
            max_requests: Maximum requests allowed per window
            window_seconds: Time window in seconds
            paths_to_limit: Specific paths to apply rate limiting (None = all paths)
        """
        super().__init__(app)
        self.rate_limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)
        self.paths_to_limit = paths_to_limit or []

        # Default to limiting OAuth token endpoint if no paths specified
        if not self.paths_to_limit:
            self.paths_to_limit = [
                "/api/v1/oauth/token",
                "/api/v1/token",  # Alternative token endpoint
                "/oauth/token",  # Non-versioned endpoint
                "/token",  # Bare endpoint
            ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request with rate limiting."""

        # Check if this path should be rate limited
        should_limit = False
        if self.paths_to_limit:
            # Check if the current path matches any of the limited paths
            for limited_path in self.paths_to_limit:
                if request.url.path.startswith(limited_path):
                    should_limit = True
                    break

        if should_limit:
            # Extract client IP for rate limiting key
            client_ip = self._get_client_ip(request)
            rate_limit_key = f"ratelimit:{request.url.path}:{client_ip}"

            try:
                # Check rate limit
                is_allowed = await self.rate_limiter.check_rate_limit(rate_limit_key)

                if not is_allowed:
                    # Return 429 Too Many Requests as required by OAuth 2.1
                    logger.warning(
                        f"Rate limit exceeded for {client_ip} on {request.url.path}",
                        extra={
                            "client_ip": client_ip,
                            "path": request.url.path,
                            "method": request.method,
                        },
                    )

                    # OAuth 2.1 compliant error response
                    return JSONResponse(
                        content={
                            "error": "too_many_requests",
                            "error_description": "Rate limit exceeded. Please try again later.",
                        },
                        status_code=429,
                        headers={
                            "Retry-After": str(self.rate_limiter.window_seconds),
                            "X-RateLimit-Limit": str(self.rate_limiter.max_requests),
                            "X-RateLimit-Window": str(self.rate_limiter.window_seconds),
                        },
                    )

            except HTTPException as e:
                # If HTTPException is raised with 429, handle it properly
                if e.status_code == 429:
                    return JSONResponse(
                        content={
                            "error": "too_many_requests",
                            "error_description": e.detail or "Rate limit exceeded. Please try again later.",
                        },
                        status_code=429,
                        headers={
                            "Retry-After": str(self.rate_limiter.window_seconds),
                            "X-RateLimit-Limit": str(self.rate_limiter.max_requests),
                            "X-RateLimit-Window": str(self.rate_limiter.window_seconds),
                        },
                    )
                # Re-raise other HTTP exceptions
                raise
            except Exception as e:
                # Log unexpected errors but don't block the request
                logger.error(f"Rate limiting error for {request.url.path}: {e}", exc_info=True)
                # Continue processing even if rate limiting fails

        # Process the request normally
        response = await call_next(request)

        # Add rate limit headers to all responses for limited paths (not just successful ones)
        if should_limit:
            response.headers["X-RateLimit-Limit"] = str(self.rate_limiter.max_requests)
            response.headers["X-RateLimit-Window"] = str(self.rate_limiter.window_seconds)

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        # Check for forwarded headers (common in production behind load balancers)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # X-Forwarded-For can contain multiple IPs, take the first one
            return forwarded_for.split(",")[0].strip()

        forwarded = request.headers.get("x-forwarded")
        if forwarded:
            return forwarded.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

        # Fall back to direct client IP
        return request.client.host if request.client else "unknown"
