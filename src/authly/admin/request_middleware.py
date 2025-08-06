"""
Request ID Middleware for Admin Operations.

This middleware adds unique request IDs to all admin requests for better
tracing and debugging. Request IDs are included in logs and error responses.
"""

import logging
import time
from collections.abc import Callable
from uuid import uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class AdminRequestIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add unique request IDs to admin API requests.

    This middleware:
    1. Generates or extracts a unique request ID for each request
    2. Adds the request ID to the request state for use by handlers
    3. Includes the request ID in response headers
    4. Logs request/response information with the request ID
    5. Measures request processing time
    """

    def __init__(self, app, admin_path_prefix: str = "/admin"):
        """
        Initialize the middleware.

        Args:
            app: FastAPI application
            admin_path_prefix: Path prefix for admin routes
        """
        super().__init__(app)
        self.admin_path_prefix = admin_path_prefix

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and add request ID tracking.

        Args:
            request: Incoming request
            call_next: Next middleware/handler in chain

        Returns:
            Response with request ID headers
        """
        # Only apply to admin routes
        if not request.url.path.startswith(self.admin_path_prefix):
            return await call_next(request)

        # Generate or extract request ID
        request_id = self._get_or_create_request_id(request)

        # Store request ID in request state
        request.state.request_id = request_id

        # Record start time
        start_time = time.time()

        # Log incoming request
        logger.info(
            f"Admin request started [request_id={request_id}]: {request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "method": request.method,
                "url": str(request.url),
                "client_ip": self._get_client_ip(request),
                "user_agent": request.headers.get("user-agent"),
            },
        )

        try:
            # Process the request
            response = await call_next(request)

            # Calculate processing time
            processing_time = time.time() - start_time

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Processing-Time"] = f"{processing_time:.3f}s"

            # Log successful response
            logger.info(
                f"Admin request completed [request_id={request_id}]: {response.status_code} in {processing_time:.3f}s",
                extra={
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "processing_time": processing_time,
                    "method": request.method,
                    "url": str(request.url),
                },
            )

            return response

        except Exception as exc:
            # Calculate processing time for errors too
            processing_time = time.time() - start_time

            # Log error
            logger.error(
                f"Admin request failed [request_id={request_id}]: {type(exc).__name__} in {processing_time:.3f}s",
                extra={
                    "request_id": request_id,
                    "exception_type": type(exc).__name__,
                    "processing_time": processing_time,
                    "method": request.method,
                    "url": str(request.url),
                },
                exc_info=True,
            )

            # Re-raise the exception to let error handlers deal with it
            raise

    def _get_or_create_request_id(self, request: Request) -> str:
        """
        Get request ID from headers or generate a new one.

        Args:
            request: Incoming request

        Returns:
            Request ID string
        """
        # Try to get request ID from headers (useful for tracing across services)
        request_id = request.headers.get("X-Request-ID")
        if request_id:
            return request_id

        # Try alternative header names
        request_id = request.headers.get("X-Trace-ID")
        if request_id:
            return request_id

        request_id = request.headers.get("X-Correlation-ID")
        if request_id:
            return request_id

        # Generate a new request ID
        return str(uuid4())

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP address from request.

        Args:
            request: Incoming request

        Returns:
            Client IP address
        """
        # Check for forwarded headers (common in load balancer setups)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # X-Forwarded-For can contain multiple IPs, take the first one
            return forwarded_for.split(",")[0].strip()

        # Check for real IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to client host
        client = getattr(request, "client", None)
        if client:
            return client.host

        return "unknown"


class AdminRequestContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add additional context to admin requests.

    This middleware adds useful context information to request state
    that can be used by handlers and logging.
    """

    def __init__(self, app, admin_path_prefix: str = "/admin"):
        """
        Initialize the middleware.

        Args:
            app: FastAPI application
            admin_path_prefix: Path prefix for admin routes
        """
        super().__init__(app)
        self.admin_path_prefix = admin_path_prefix

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Add context information to admin requests.

        Args:
            request: Incoming request
            call_next: Next middleware/handler in chain

        Returns:
            Response
        """
        # Only apply to admin routes
        if not request.url.path.startswith(self.admin_path_prefix):
            return await call_next(request)

        # Add context information to request state
        request.state.is_admin_request = True
        request.state.admin_path = request.url.path
        request.state.client_ip = self._get_client_ip(request)
        request.state.user_agent = request.headers.get("user-agent", "unknown")

        # Add authentication context if available
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            request.state.has_bearer_token = True
        else:
            request.state.has_bearer_token = False

        # Process the request
        return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        client = getattr(request, "client", None)
        if client:
            return client.host

        return "unknown"


def setup_admin_middleware(app, admin_path_prefix: str = "/admin") -> None:
    """
    Set up all admin middleware.

    Args:
        app: FastAPI application
        admin_path_prefix: Path prefix for admin routes
    """
    # Add request context middleware first
    app.add_middleware(AdminRequestContextMiddleware, admin_path_prefix=admin_path_prefix)

    # Add request ID middleware
    app.add_middleware(AdminRequestIDMiddleware, admin_path_prefix=admin_path_prefix)

    logger.info(f"Admin middleware configured for path prefix: {admin_path_prefix}")
