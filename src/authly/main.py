"""
Production entry point for Authly authentication service.

This module provides the main FastAPI application factory and server
entry point for production deployments.
"""

import asyncio
import logging
import os
import signal
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress

import uvicorn
from fastapi import FastAPI

# Legacy Authly import removed - using AuthlyResourceManager
from authly.app import create_production_app
from authly.bootstrap import bootstrap_admin_system
from authly.config import AuthlyConfig, EnvDatabaseProvider, EnvSecretProvider
from authly.core.database import get_database
from authly.core.deployment_modes import DeploymentMode
from authly.core.mode_factory import AuthlyModeFactory

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    FastAPI lifespan context manager with psycopg-toolkit Database integration.

    Uses the new AuthlyResourceManager with full psycopg-toolkit Database lifecycle
    management while maintaining backward compatibility with existing code.
    """
    logger.info("Starting Authly application with psycopg-toolkit Database integration...")

    try:
        # Create resource manager with mode auto-detection
        # Force production mode for main.py entry point
        os.environ.setdefault("AUTHLY_MODE", "production")
        resource_manager = AuthlyModeFactory.create_resource_manager()

        # Validate that we're in production mode
        if resource_manager.mode != DeploymentMode.PRODUCTION:
            raise RuntimeError(
                f"Production entry point detected {resource_manager.mode.value} mode - use appropriate entry point"
            )

        logger.info(f"AuthlyResourceManager created for {resource_manager.mode.value} mode")

        # Initialize with managed Database lifecycle
        async with get_database(resource_manager.get_config()) as database:
            # Initialize resource manager with Database
            await resource_manager.initialize_with_external_database(database)

            # Initialize Redis if configured
            redis_initialized = await resource_manager.initialize_redis()
            if redis_initialized:
                logger.info("Redis integration enabled")
            else:
                logger.info("Redis integration disabled - using memory backends")

            # Initialize backend factory
            from authly.core.backend_factory import initialize_backend_factory

            initialize_backend_factory(resource_manager)

            # Set up dependency injection without app.state
            from authly.core.dependencies import create_resource_manager_provider, get_resource_manager

            # Create the provider and override the default dependency
            provider = create_resource_manager_provider(resource_manager)
            app.dependency_overrides[get_resource_manager] = provider
            logger.info("Resource manager dependency injection configured")

            # Bootstrap admin system if enabled by mode configuration
            if resource_manager.should_bootstrap_admin():
                bootstrap_enabled = os.getenv("AUTHLY_BOOTSTRAP_ENABLED", "true").lower() == "true"
                if bootstrap_enabled:
                    try:
                        async with resource_manager.get_pool().connection() as conn:
                            bootstrap_results = await bootstrap_admin_system(conn)
                            logger.info(f"Admin bootstrap completed: {bootstrap_results}")
                    except Exception as e:
                        logger.error(f"Admin bootstrap failed: {e}")
                        # Continue startup even if bootstrap fails

            logger.info(
                f"Authly application ready - {resource_manager.mode.value} mode with psycopg-toolkit Database integration"
            )
            yield  # Application ready for requests

    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise RuntimeError("Failed to initialize application: See logs for details") from None
    finally:
        logger.info("Shutting down Authly application...")
        # Cleanup Redis connections if initialized
        if "resource_manager" in locals():
            await resource_manager.cleanup_redis()
        # Cleanup handled by context managers and resource manager
        logger.info("Application shutdown completed")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance
    """
    return create_production_app(lifespan=lifespan)


def setup_logging():
    """Configure logging for production deployment"""
    from authly.logging.setup import get_service_version, setup_structured_logging

    # Determine if we should use JSON logging
    json_logging = os.getenv("LOG_JSON", "true").lower() in ("true", "1", "yes")

    # Setup structured logging
    setup_structured_logging(
        service_name="authly",
        service_version=get_service_version(),
        json_format=json_logging,
        include_location=os.getenv("LOG_INCLUDE_LOCATION", "false").lower() in ("true", "1", "yes"),
    )


async def main():
    """
    Main entry point for running the server directly.

    This is useful for development or when not using a WSGI server.
    """
    setup_logging()

    app = create_app()

    # Load configuration to get defaults

    authly_config = AuthlyConfig.load(EnvSecretProvider(), EnvDatabaseProvider())

    # Configuration from environment with config defaults
    host = os.getenv("HOST", authly_config.default_host)
    port = int(os.getenv("PORT", str(authly_config.default_port)))
    workers = int(os.getenv("WORKERS", "1"))

    # Create uvicorn configuration
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        workers=workers if workers > 1 else None,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
        access_log=os.getenv("ACCESS_LOG", "true").lower() == "true",
    )

    server = uvicorn.Server(config)

    # Setup signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    signals = (signal.SIGTERM, signal.SIGINT)

    def signal_handler():
        logger.info("Received shutdown signal")
        server.should_exit = True

    for sig in signals:
        loop.add_signal_handler(sig, signal_handler)

    try:
        logger.info(f"Starting Authly server on {host}:{port}")
        await server.serve()
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise RuntimeError("An error occurred") from None
    finally:
        # Remove signal handlers
        for sig in signals:
            with suppress(ValueError):
                loop.remove_signal_handler(sig)


# FastAPI app instance for WSGI servers (gunicorn, etc.)
app = create_app()

if __name__ == "__main__":
    asyncio.run(main())
