"""
Security Headers Middleware for Authly authentication service.

This middleware provides comprehensive security headers including:
- HSTS (HTTP Strict Transport Security)
- CSP (Content Security Policy)
- X-Frame-Options (Clickjacking protection)
- X-Content-Type-Options (MIME sniffing protection)
- X-XSS-Protection (XSS protection)
- Referrer-Policy (Control referrer information)
- Permissions-Policy (Control browser features)
"""

import logging
import os
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds comprehensive security headers to all HTTP responses.

    Features:
    - HSTS for HTTPS enforcement
    - CSP for XSS and data injection protection
    - Clickjacking protection
    - MIME sniffing protection
    - XSS protection
    - Referrer policy control
    - Browser feature permissions
    - Environment-based configuration
    """

    def __init__(
        self,
        app,
        hsts_max_age: int = 31536000,  # 1 year
        hsts_include_subdomains: bool = True,
        hsts_preload: bool = True,
        csp_policy: str | None = None,
        frame_options: str = "DENY",
        referrer_policy: str = "strict-origin-when-cross-origin",
        permissions_policy: str | None = None,
        custom_headers: dict[str, str] | None = None,
    ):
        super().__init__(app)
        self.hsts_max_age = hsts_max_age
        self.hsts_include_subdomains = hsts_include_subdomains
        self.hsts_preload = hsts_preload
        self.csp_policy = csp_policy or self._get_default_csp()
        self.frame_options = frame_options
        self.referrer_policy = referrer_policy
        self.permissions_policy = permissions_policy or self._get_default_permissions_policy()
        self.custom_headers = custom_headers or {}

        # Environment-based configuration
        self.hsts_enabled = self._is_hsts_enabled()
        self.csp_enabled = self._is_csp_enabled()

        logger.info("Security headers middleware configured:")
        logger.info(f"  - HSTS enabled: {self.hsts_enabled}")
        logger.info(f"  - CSP enabled: {self.csp_enabled}")
        logger.info(f"  - Frame options: {self.frame_options}")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers to the response."""
        response = await call_next(request)

        # Add security headers
        self._add_security_headers(request, response)

        return response

    def _add_security_headers(self, request: Request, response: Response) -> None:
        """Add all security headers to the response."""

        # HSTS - Only add for HTTPS requests or in development
        if self.hsts_enabled and (request.url.scheme == "https" or self._is_development()):
            hsts_value = f"max-age={self.hsts_max_age}"
            if self.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            if self.hsts_preload:
                hsts_value += "; preload"
            response.headers["Strict-Transport-Security"] = hsts_value

        # Content Security Policy - with path-specific policies
        if self.csp_enabled:
            csp_policy = self._get_path_specific_csp(request.url.path)
            response.headers["Content-Security-Policy"] = csp_policy

        # X-Frame-Options - Clickjacking protection
        response.headers["X-Frame-Options"] = self.frame_options

        # X-Content-Type-Options - MIME sniffing protection
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-XSS-Protection - XSS protection (legacy but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer-Policy - Control referrer information
        response.headers["Referrer-Policy"] = self.referrer_policy

        # Permissions-Policy - Control browser features
        if self.permissions_policy:
            response.headers["Permissions-Policy"] = self.permissions_policy

        # Cross-Origin-Opener-Policy - Process isolation
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        # Cross-Origin-Embedder-Policy - Require explicit opt-in for cross-origin resources
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        # Cross-Origin-Resource-Policy - Control cross-origin embedding
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # Custom headers
        for header_name, header_value in self.custom_headers.items():
            response.headers[header_name] = header_value

    def _get_default_csp(self) -> str:
        """Get default Content Security Policy for Authly."""
        # OAuth UI and API-focused CSP policy
        # Allows inline styles for OAuth templates but restricts scripts
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "media-src 'none'; "
            "object-src 'none'; "
            "child-src 'none'; "
            "frame-src 'none'; "
            "worker-src 'none'; "
            "manifest-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "upgrade-insecure-requests"
        )

    def _get_path_specific_csp(self, path: str) -> str:
        """Get Content Security Policy based on the request path."""
        # Documentation endpoints need to load external CDN resources
        if path in ["/docs", "/redoc"]:
            return self._get_docs_csp()

        # Use default CSP for all other paths
        return self.csp_policy

    def _get_docs_csp(self) -> str:
        """Get CSP policy for documentation endpoints (/docs, /redoc)."""
        # Relaxed CSP for Swagger UI and ReDoc that need external CDN resources
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "img-src 'self' data: fastapi.tiangolo.com; "
            "font-src 'self' cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "media-src 'none'; "
            "object-src 'none'; "
            "child-src 'none'; "
            "frame-src 'none'; "
            "worker-src 'none'; "
            "manifest-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "upgrade-insecure-requests"
        )

    def _get_default_permissions_policy(self) -> str:
        """Get default Permissions Policy for Authly."""
        # Restrictive permissions policy for OAuth server
        # Disables most browser features that aren't needed
        return (
            "accelerometer=(), "
            "autoplay=(), "
            "camera=(), "
            "cross-origin-isolated=(), "
            "display-capture=(), "
            "encrypted-media=(), "
            "fullscreen=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "midi=(), "
            "payment=(), "
            "picture-in-picture=(), "
            "publickey-credentials-get=(), "
            "screen-wake-lock=(), "
            "sync-xhr=(), "
            "usb=(), "
            "web-share=(), "
            "xr-spatial-tracking=()"
        )

    def _is_hsts_enabled(self) -> bool:
        """Check if HSTS is enabled via environment variable."""
        return os.getenv("AUTHLY_SECURITY_HSTS_ENABLED", "true").lower() == "true"

    def _is_csp_enabled(self) -> bool:
        """Check if CSP is enabled via environment variable."""
        return os.getenv("AUTHLY_SECURITY_CSP_ENABLED", "true").lower() == "true"

    def _is_development(self) -> bool:
        """Check if running in development mode."""
        return os.getenv("AUTHLY_ENVIRONMENT", "production").lower() in ("development", "dev", "local")


def setup_security_middleware(app, **kwargs):
    """
    Setup security headers middleware for the FastAPI application.

    Args:
        app: FastAPI application instance
        **kwargs: Additional configuration options for SecurityHeadersMiddleware
    """
    # Add the security headers middleware
    app.add_middleware(SecurityHeadersMiddleware, **kwargs)

    logger.info("Security headers middleware configured")


# Environment variable configuration helpers
def get_security_config() -> dict[str, str]:
    """
    Get security configuration from environment variables.

    Returns:
        Dictionary of security configuration values
    """
    return {
        "hsts_enabled": os.getenv("AUTHLY_SECURITY_HSTS_ENABLED", "true"),
        "csp_enabled": os.getenv("AUTHLY_SECURITY_CSP_ENABLED", "true"),
        "hsts_max_age": os.getenv("AUTHLY_SECURITY_HSTS_MAX_AGE", "31536000"),
        "frame_options": os.getenv("AUTHLY_SECURITY_FRAME_OPTIONS", "DENY"),
        "referrer_policy": os.getenv("AUTHLY_SECURITY_REFERRER_POLICY", "strict-origin-when-cross-origin"),
        "environment": os.getenv("AUTHLY_ENVIRONMENT", "production"),
    }
