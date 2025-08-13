"""
FastAPI application factory for Authly.

This module provides a centralized way to create and configure FastAPI applications
for different deployment scenarios (production, development, embedded).
"""

import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles

from authly._version import __version__
from authly.api import auth_router, health_router, metrics_router, oauth_router, oidc_router, users_router
from authly.api.admin_middleware import setup_admin_middleware
from authly.api.admin_router import admin_router
from authly.api.oauth_discovery_router import oauth_discovery_router
from authly.api.password_change import router as password_change_router
from authly.api.rate_limiting_middleware import RateLimitingMiddleware
from authly.api.security_middleware import setup_security_middleware
from authly.authentication import auth_router as authentication_router
from authly.config import AuthlyConfig
from authly.logging.middleware import LoggingMiddleware


def create_app(
    config: AuthlyConfig | None = None,
    title: str = "Authly Authentication Service",
    version: str = __version__,
    description: str = "Production-ready authentication and authorization service with OAuth 2.1 support",
    lifespan: Callable[[FastAPI], AbstractAsyncContextManager[Any]] | None = None,
    static_path: str | None = None,
    api_prefix: str | None = None,
) -> FastAPI:
    """
    Create and configure a FastAPI application for Authly.

    Args:
        config: AuthlyConfig instance (optional, will use defaults if not provided)
        title: Application title
        version: Application version
        description: Application description
        lifespan: Lifespan context manager (optional)
        static_path: Path to static files directory (optional)
        api_prefix: API prefix for versioned routes (optional)

    Returns:
        Configured FastAPI application instance
    """
    # Create FastAPI app
    app = FastAPI(title=title, version=version, description=description, lifespan=lifespan)

    # Add logging middleware first (to capture all requests)
    app.add_middleware(LoggingMiddleware)

    # Add rate limiting middleware for OAuth 2.1 compliance
    # This must be early in the middleware stack to protect endpoints
    app.add_middleware(
        RateLimitingMiddleware,
        max_requests=10,  # Allow 10 requests
        window_seconds=60,  # Per minute
        paths_to_limit=[
            "/api/v1/oauth/token",
            "/api/v1/token",
            "/oauth/token",
            "/token",
        ],
    )

    # Add CORS middleware for browser compatibility
    # This should be after logging but before other middleware
    # Load CORS configuration from AuthlyConfig or use defaults
    if config:
        # Use config if provided
        from authly.config import AuthlyConfig

        if isinstance(config, AuthlyConfig):
            allowed_origins = config.cors_allowed_origins
            allow_credentials = config.cors_allow_credentials
            allow_methods = config.cors_allow_methods
            allow_headers = config.cors_allow_headers
            expose_headers = config.cors_expose_headers
            max_age = config.cors_max_age
        else:
            # Fallback to environment variables if config is not AuthlyConfig
            cors_origins = os.getenv("AUTHLY_CORS_ORIGINS", "")
            if cors_origins == "*":
                allowed_origins = ["*"]
            elif cors_origins:
                allowed_origins = cors_origins.split(",")
            else:
                # Default development origins
                allowed_origins = [
                    "http://localhost:8080",
                    "http://localhost:3000",
                    "http://localhost:8000",
                    "http://127.0.0.1:8080",
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:8000",
                ]
            allow_credentials = True
            allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
            allow_headers = ["*"]
            expose_headers = ["*"]
            max_age = 600
    else:
        # No config provided, use environment or defaults
        cors_origins = os.getenv("AUTHLY_CORS_ORIGINS", "")
        if cors_origins == "*":
            allowed_origins = ["*"]
        elif cors_origins:
            allowed_origins = cors_origins.split(",")
        else:
            # Default development origins
            allowed_origins = [
                "http://localhost:8080",
                "http://localhost:3000",
                "http://localhost:8000",
                "http://127.0.0.1:8080",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:8000",
            ]
        allow_credentials = True
        allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        allow_headers = ["*"]
        expose_headers = ["*"]
        max_age = 600

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=allow_credentials,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
        expose_headers=expose_headers,
        max_age=max_age,
    )

    # Setup security headers middleware (after CORS)
    setup_security_middleware(app)

    # Setup admin security middleware
    setup_admin_middleware(app)

    # Mount static files for OAuth templates
    if static_path is None:
        static_path = os.path.join(os.path.dirname(__file__), "static")

    if os.path.exists(static_path):
        app.mount("/static", StaticFiles(directory=static_path), name="static")

    # Include authentication router for browser-based login (no prefix - uses /auth)
    app.include_router(authentication_router)

    # Patch OAuth authorization endpoints to support session-based authentication
    from authly.authentication.oauth_integration import patch_oauth_authorization_endpoints

    patch_oauth_authorization_endpoints()

    # Include health router (no prefix)
    app.include_router(health_router)

    # Include metrics router (no prefix - standard /metrics path)
    app.include_router(metrics_router)

    # Get API prefix from config, parameter, or environment
    if api_prefix is None:
        api_prefix = config.fastapi_api_version_prefix if config else os.getenv("AUTHLY_API_PREFIX", "/api/v1")

    # Include versioned API routers
    app.include_router(auth_router, prefix=api_prefix)
    app.include_router(password_change_router, prefix=api_prefix)
    app.include_router(users_router, prefix=api_prefix)
    app.include_router(oauth_router, prefix=api_prefix)

    # Include OIDC router (no prefix - uses well-known paths)
    app.include_router(oidc_router)

    # Include OAuth discovery router (no prefix - RFC 8414 compliance)
    app.include_router(oauth_discovery_router)

    # Include admin router (no prefix - has its own /admin prefix)
    app.include_router(admin_router)

    # Configure OpenAPI schema
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        openapi_schema = get_openapi(
            title=title,
            version=version,
            description=description,
            routes=app.routes,
        )

        # Add security schemes
        openapi_schema["components"]["securitySchemes"] = {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi

    return app


def create_production_app(lifespan: Callable[[FastAPI], AbstractAsyncContextManager[Any]]) -> FastAPI:
    """
    Create a production-ready FastAPI application.

    Args:
        lifespan: Lifespan context manager for resource management

    Returns:
        Configured FastAPI application for production use
    """
    return create_app(
        title="Authly Authentication Service",
        version=__version__,
        description="Production-ready authentication and authorization service with OAuth 2.1 support",
        lifespan=lifespan,
    )


def create_embedded_app(config: AuthlyConfig, database_url: str, seed: bool = False) -> FastAPI:
    """
    Create a FastAPI application for embedded development mode.

    Args:
        config: AuthlyConfig instance
        database_url: Database connection URL
        seed: Whether to seed test data

    Returns:
        Configured FastAPI application for embedded development
    """
    app = create_app(
        config=config,
        title="Authly Auth API (Embedded)",
        version=__version__,
        description="Authly Authentication and Authorization Service - Embedded Development Mode",
        api_prefix=config.fastapi_api_version_prefix,
    )

    # Configuration will be available through resource manager dependency injection
    # No direct app.state storage needed - use get_resource_manager() dependency

    return app
