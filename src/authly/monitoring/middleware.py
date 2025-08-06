"""
Metrics integration utilities for middleware.

This module provides utilities to integrate Prometheus metrics collection
into existing middleware without creating additional middleware layers.
"""

import logging
import re
import time

from fastapi import Request, Response

from authly.monitoring.metrics import metrics

logger = logging.getLogger(__name__)

# Endpoint pattern mapping for better metrics grouping
ENDPOINT_PATTERNS = {
    # Auth endpoints
    r"^/api/v1/oauth/token$": "/api/v1/oauth/token",
    r"^/api/v1/oauth/refresh$": "/api/v1/oauth/refresh",
    r"^/api/v1/oauth/revoke$": "/api/v1/oauth/revoke",
    r"^/api/v1/auth/logout$": "/api/v1/auth/logout",
    # OAuth endpoints
    r"^/api/v1/oauth/authorize$": "/api/v1/oauth/authorize",
    # OIDC endpoints
    r"^/\.well-known/openid_configuration$": "/.well-known/openid_configuration",
    r"^/\.well-known/jwks\.json$": "/.well-known/jwks.json",
    r"^/oidc/userinfo$": "/oidc/userinfo",
    # OAuth discovery
    r"^/\.well-known/oauth-authorization-server$": "/.well-known/oauth-authorization-server",
    # Admin endpoints (grouped by operation)
    r"^/admin/clients(/.*)?$": "/admin/clients",
    r"^/admin/scopes(/.*)?$": "/admin/scopes",
    r"^/admin/users(/.*)?$": "/admin/users",
    r"^/admin/status$": "/admin/status",
    r"^/admin/auth/.*$": "/admin/auth",
    # User endpoints (with ID parameter grouped)
    r"^/api/v1/users/[^/]+$": "/api/v1/users/{id}",
    r"^/api/v1/users$": "/api/v1/users",
    # Health and metrics
    r"^/health(/.*)?$": "/health",
    r"^/metrics$": "/metrics",
    # Password change
    r"^/api/v1/password/change$": "/api/v1/password/change",
    # Static files (grouped)
    r"^/static/.*$": "/static/*",
    # Docs endpoints
    r"^/docs.*$": "/docs",
    r"^/redoc.*$": "/redoc",
    r"^/openapi\.json$": "/openapi.json",
}


def normalize_endpoint(path: str) -> str:
    """
    Normalize request path to a consistent endpoint pattern for metrics.

    This helps group similar requests together (e.g., /users/123 -> /users/{id})
    to prevent metric cardinality explosion.

    Args:
        path: The request path

    Returns:
        Normalized endpoint pattern
    """
    # Check against predefined patterns
    for pattern, normalized in ENDPOINT_PATTERNS.items():
        if re.match(pattern, path):
            return normalized

    # Fallback: group unknown paths as 'other'
    return "other"


class MetricsCollector:
    """
    Utility class for collecting HTTP metrics within existing middleware.

    This class provides methods to integrate metrics collection into the
    existing LoggingMiddleware without creating a separate middleware layer.
    """

    def __init__(self):
        """Initialize metrics collector."""
        self._active_requests: dict[str, float] = {}

    def start_request_tracking(self, request: Request, correlation_id: str) -> None:
        """
        Start tracking metrics for a request.

        Args:
            request: FastAPI request object
            correlation_id: Unique correlation ID for the request
        """
        try:
            endpoint = normalize_endpoint(request.url.path)
            method = request.method

            # Track request start
            metrics.track_http_request_start(method, endpoint)

            # Store start time for duration calculation
            self._active_requests[correlation_id] = time.time()

            logger.debug(f"Started metrics tracking for {method} {endpoint}")
        except Exception as e:
            logger.warning(f"Failed to start request metrics tracking: {e}")

    def end_request_tracking(
        self, request: Request, response: Response | None, correlation_id: str, error: Exception | None = None
    ) -> None:
        """
        End tracking metrics for a request.

        Args:
            request: FastAPI request object
            response: FastAPI response object (None if error occurred)
            correlation_id: Unique correlation ID for the request
            error: Exception if request failed
        """
        try:
            endpoint = normalize_endpoint(request.url.path)
            method = request.method

            # Calculate duration
            start_time = self._active_requests.pop(correlation_id, None)
            duration = time.time() - start_time if start_time else 0.0

            # Determine status code
            if error:
                status_code = getattr(error, "status_code", 500)
            elif response:
                status_code = response.status_code
            else:
                status_code = 500

            # Track request completion
            metrics.track_http_request(method, endpoint, status_code, duration)

            # Track request end (for in-progress gauge)
            metrics.track_http_request_end(method, endpoint)

            logger.debug(f"Completed metrics tracking for {method} {endpoint} - {status_code} ({duration:.3f}s)")

        except Exception as e:
            logger.warning(f"Failed to end request metrics tracking: {e}")

    def cleanup_stale_requests(self, max_age_seconds: int = 300) -> None:
        """
        Clean up stale request tracking entries.

        Args:
            max_age_seconds: Maximum age for tracking entries before cleanup
        """
        try:
            current_time = time.time()
            stale_keys = [
                key for key, start_time in self._active_requests.items() if current_time - start_time > max_age_seconds
            ]

            for key in stale_keys:
                self._active_requests.pop(key, None)

            if stale_keys:
                logger.debug(f"Cleaned up {len(stale_keys)} stale metrics tracking entries")

        except Exception as e:
            logger.warning(f"Failed to cleanup stale request metrics: {e}")


# Global metrics collector instance
metrics_collector = MetricsCollector()
