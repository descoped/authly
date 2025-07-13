"""
Production entry point for Authly authentication service.

This module provides the main FastAPI application factory and server
entry point for production deployments.
"""

import asyncio
import logging
import os
import signal
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI

from authly import Authly
from authly.app import create_production_app
from authly.bootstrap import bootstrap_admin_system
from authly.config import AuthlyConfig, EnvDatabaseProvider, EnvSecretProvider

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    FastAPI lifespan context manager for proper resource management.

    Handles startup and shutdown of database connections and other resources.
    """
    logger.info("Starting Authly application...")

    try:
        # Load configuration from environment
        secret_provider = EnvSecretProvider()
        database_provider = EnvDatabaseProvider()
        config = AuthlyConfig.load(secret_provider, database_provider)

        # Create database connection pool using psycopg-toolkit Database class
        from urllib.parse import urlparse

        from psycopg_toolkit import Database, DatabaseSettings

        database_url = database_provider.get_database_config().database_url

        # Parse database URL into settings
        url = urlparse(database_url)

        # Get default port from config
        try:
            default_port = config.postgres_port
        except (AttributeError, RuntimeError):
            # Fallback for tests without full initialization
            default_port = 5432

        settings = DatabaseSettings(
            host=url.hostname,
            port=url.port or default_port,
            dbname=url.path.lstrip("/"),
            user=url.username,
            password=url.password,
        )

        # Create database with proper lifecycle management
        db = Database(settings)
        await db.create_pool()
        await db.init_db()
        pool = await db.get_pool()

        # Initialize Authly singleton with pool and configuration
        authly = Authly.initialize(pool=pool, configuration=config)
        logger.info("Authly initialized successfully")

        # Bootstrap admin system if enabled
        bootstrap_enabled = os.getenv("AUTHLY_BOOTSTRAP_ENABLED", "true").lower() == "true"
        if bootstrap_enabled:
            try:
                # Get pool from the initialized Authly instance
                bootstrap_pool = authly.get_pool()
                async with bootstrap_pool.connection() as conn:
                    bootstrap_results = await bootstrap_admin_system(conn)
                    logger.info(f"Admin bootstrap completed: {bootstrap_results}")
            except Exception as e:
                logger.error(f"Admin bootstrap failed: {e}")
                # Continue startup even if bootstrap fails (for existing deployments)

        # Note: Database instance is managed through Authly singleton and dependency injection
        # Do not store state on app.state.db - use FastAPI dependency injection instead

        # Application is ready
        yield

    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise
    finally:
        # Cleanup resources during shutdown
        logger.info("Shutting down Authly application...")
        try:
            # Clean up database properly
            if hasattr(app.state, "db"):
                await app.state.db.cleanup()
                logger.info("Database cleanup completed")
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance
    """
    return create_production_app(lifespan=lifespan)


def setup_logging():
    """Configure logging for production deployment"""
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_format = os.getenv("LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    logging.basicConfig(level=getattr(logging, log_level), format=log_format)

    # Set specific logger levels
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("authly").setLevel(log_level)


async def main():
    """
    Main entry point for running the server directly.

    This is useful for development or when not using a WSGI server.
    """
    setup_logging()

    app = create_app()

    # Configuration from environment
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
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
        raise
    finally:
        # Remove signal handlers
        for sig in signals:
            try:
                loop.remove_signal_handler(sig)
            except ValueError:
                pass


# FastAPI app instance for WSGI servers (gunicorn, etc.)
app = create_app()

if __name__ == "__main__":
    asyncio.run(main())
