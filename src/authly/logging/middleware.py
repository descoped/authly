"""
Logging middleware for FastAPI.

Adds correlation ID tracking and request context to all HTTP requests
for better observability and request tracing.
"""

import logging
import time
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .context import LoggingContext, generate_correlation_id

logger = logging.getLogger(__name__)

# Import metrics collector for HTTP metrics integration
try:
    from authly.monitoring.middleware import metrics_collector

    METRICS_ENABLED = True
except ImportError:
    logger.debug("Metrics collection not available - continuing without metrics")
    METRICS_ENABLED = False
    metrics_collector = None


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds correlation ID tracking and request logging.

    For each request:
    1. Generates or extracts correlation ID from headers
    2. Sets up logging context with request information
    3. Logs request start and completion with timing
    4. Includes correlation ID in response headers
    """

    def __init__(
        self,
        app,
        correlation_header: str = "X-Correlation-ID",
        include_request_body: bool = False,
        include_response_body: bool = False,
    ):
        super().__init__(app)
        self.correlation_header = correlation_header
        self.include_request_body = include_request_body
        self.include_response_body = include_response_body

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request with logging context."""
        start_time = time.time()

        # Extract or generate correlation ID
        correlation_id = request.headers.get(self.correlation_header)
        if not correlation_id:
            correlation_id = generate_correlation_id()

        # Extract client information
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")

        # Set up logging context
        request_context = {
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "client_ip": client_ip,
            "user_agent": user_agent,
        }

        # Add query parameters if present
        if request.url.query:
            request_context["query_params"] = dict(request.query_params)

        # Add request body if configured (be careful with sensitive data)
        if self.include_request_body and request.method in ("POST", "PUT", "PATCH"):
            try:
                # Note: This consumes the request body, so we need to be careful
                # In production, you might want to limit this to specific endpoints
                request_context["request_size"] = request.headers.get("content-length")
            except Exception as e:
                logger.warning("Failed to capture request body", extra={"error": str(e)})

        with LoggingContext(correlation_id=correlation_id, **request_context):
            # Start metrics tracking if enabled
            if METRICS_ENABLED and metrics_collector:
                metrics_collector.start_request_tracking(request, correlation_id)

            # Log request start
            logger.info(
                "Request started",
                extra={
                    "event": "request_start",
                    "method": request.method,
                    "path": request.url.path,
                },
            )

            try:
                # Process the request
                response = await call_next(request)

                # Calculate request duration
                duration = time.time() - start_time

                # Add correlation ID to response headers
                response.headers[self.correlation_header] = correlation_id

                # End metrics tracking if enabled
                if METRICS_ENABLED and metrics_collector:
                    metrics_collector.end_request_tracking(request, response, correlation_id)

                # Log request completion
                logger.info(
                    "Request completed",
                    extra={
                        "event": "request_complete",
                        "status_code": response.status_code,
                        "duration_ms": round(duration * 1000, 2),
                    },
                )

                return response

            except Exception as e:
                # Calculate request duration even for errors
                duration = time.time() - start_time

                # End metrics tracking for failed requests if enabled
                if METRICS_ENABLED and metrics_collector:
                    metrics_collector.end_request_tracking(request, None, correlation_id, error=e)

                # Log request error
                logger.error(
                    "Request failed",
                    extra={
                        "event": "request_error",
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "duration_ms": round(duration * 1000, 2),
                    },
                    exc_info=True,
                )

                # Re-raise the exception
                raise

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
