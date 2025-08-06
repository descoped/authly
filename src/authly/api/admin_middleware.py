"""
Admin API Middleware for Authly authentication service.

This middleware provides security controls for admin endpoints including:
- Localhost-only access enforcement
- Admin API enable/disable configuration
- Security logging for blocked access attempts
"""

import logging
import os
from collections.abc import Callable

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


# Helper functions to read configuration at runtime
def _is_admin_api_enabled() -> bool:
    """Check if admin API is enabled via environment variable."""
    return os.getenv("AUTHLY_ADMIN_API_ENABLED", "true").lower() == "true"


def _is_admin_api_localhost_only() -> bool:
    """Check if admin API is restricted to localhost via environment variable."""
    return os.getenv("AUTHLY_ADMIN_API_LOCALHOST_ONLY", "true").lower() == "true"


# Allowed localhost addresses
LOCALHOST_IPS = {"127.0.0.1", "::1", "localhost"}


class AdminSecurityMiddleware:
    """
    Middleware to enforce security controls for admin API endpoints.

    Features:
    - Localhost-only access enforcement
    - Admin API enable/disable toggle
    - Security event logging
    - Configurable via environment variables
    """

    def __init__(self, app: Callable):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        # Check if this is an admin API request
        if request.url.path.startswith("/admin"):
            # Check if admin API is enabled
            if not _is_admin_api_enabled():
                logger.warning(f"Admin API access denied - API disabled: {request.client.host}")
                response = JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"detail": "Admin API is currently disabled", "error_code": "ADMIN_API_DISABLED"},
                )
                await response(scope, receive, send)
                return

            # Check localhost-only access
            if _is_admin_api_localhost_only():
                client_host = request.client.host if request.client else None

                # Get real IP from headers (for proxy setups)
                forwarded_for = request.headers.get("X-Forwarded-For")
                real_ip = request.headers.get("X-Real-IP")

                # Determine actual client IP
                actual_ip = forwarded_for.split(",")[0].strip() if forwarded_for else real_ip or client_host

                if not self._is_localhost(actual_ip):
                    logger.warning(
                        f"Admin API access denied - non-localhost access: {actual_ip} "
                        f"requesting {request.method} {request.url.path}"
                    )
                    response = JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "detail": "Admin API access restricted to localhost only",
                            "error_code": "ADMIN_API_LOCALHOST_ONLY",
                        },
                    )
                    await response(scope, receive, send)
                    return

            # Log admin API access for audit purposes
            client_ip = request.client.host if request.client else "unknown"
            logger.info(f"Admin API access: {client_ip} - {request.method} {request.url.path}")

        # Continue to application
        await self.app(scope, receive, send)

    def _is_localhost(self, ip: str) -> bool:
        """
        Check if the given IP address is considered localhost.

        Args:
            ip: IP address to check

        Returns:
            True if IP is localhost, False otherwise
        """
        if not ip:
            return False

        # Direct localhost check
        if ip in LOCALHOST_IPS:
            return True

        # IPv4 localhost range (127.0.0.0/8)
        if ip.startswith("127."):
            return True

        # IPv6 localhost
        if ip == "::1" or ip.lower() == "localhost":
            return True

        # Docker internal IPs (when running in containers)
        docker_internal_ips = {
            "172.17.0.1",  # Default Docker bridge
            "172.18.0.1",  # Common Docker bridge
            "host.docker.internal",  # Docker Desktop
        }

        return ip in docker_internal_ips


def setup_admin_middleware(app):
    """
    Setup admin security middleware for the FastAPI application.

    Args:
        app: FastAPI application instance
    """
    # Add the admin security middleware
    app.add_middleware(AdminSecurityMiddleware)

    logger.info("Admin API middleware configured:")
    logger.info(f"  - Admin API enabled: {_is_admin_api_enabled()}")
    logger.info(f"  - Localhost only: {_is_admin_api_localhost_only()}")


# Dependency function for manual middleware checking (if needed)
async def check_admin_access(request: Request):
    """
    Manual admin access check that can be used as a FastAPI dependency.

    This provides the same checks as the middleware but can be used
    selectively on specific endpoints if needed.
    """
    if not _is_admin_api_enabled():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Admin API is currently disabled")

    if _is_admin_api_localhost_only():
        client_host = request.client.host if request.client else None

        # Get real IP from headers (for proxy setups)
        forwarded_for = request.headers.get("X-Forwarded-For")
        real_ip = request.headers.get("X-Real-IP")

        # Determine actual client IP
        actual_ip = forwarded_for.split(",")[0].strip() if forwarded_for else real_ip or client_host

        # Check if localhost
        middleware = AdminSecurityMiddleware(None)
        if not middleware._is_localhost(actual_ip):
            logger.warning(f"Admin API access denied - non-localhost: {actual_ip}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Admin API access restricted to localhost only"
            )

    return True
