"""Database lifecycle management for FastAPI lifespan.

This module provides database resource management using FastAPI's lifespan
context manager with full psycopg-toolkit integration, replacing the singleton
pattern with proper dependency injection.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from psycopg_pool import AsyncConnectionPool
from psycopg_toolkit import Database, DatabaseSettings

from authly.config import AuthlyConfig

logger = logging.getLogger(__name__)


@asynccontextmanager
async def get_database(config: AuthlyConfig) -> AsyncGenerator[Database, None]:
    """Create and manage psycopg-toolkit Database lifecycle.

    This is the modern approach using full psycopg-toolkit Database integration
    for FastAPI lifespan management with proper resource cleanup.

    Args:
        config: Application configuration containing database settings

    Yields:
        Database: Managed psycopg-toolkit Database instance

    Raises:
        Exception: If database initialization fails
    """
    logger.info("Initializing psycopg-toolkit Database with dependency injection pattern")

    # Parse database URL from config
    database_url = config.database_url
    url = urlparse(database_url)

    # Get default port from config with fallback
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

    # Create and initialize Database
    database = Database(settings)
    try:
        await database.create_pool()
        await database.init_db()

        logger.info(
            f"psycopg-toolkit Database initialized successfully - host: {url.hostname}, db: {url.path.lstrip('/')}"
        )
        yield database

    except Exception as e:
        logger.error(f"Failed to initialize psycopg-toolkit Database: {e}")
        raise RuntimeError("Failed to initialize psycopg-toolkit Database: See logs for details") from None
    finally:
        # Cleanup on shutdown
        logger.info("Shutting down psycopg-toolkit Database")
        try:
            await database.cleanup()
            logger.info("psycopg-toolkit Database cleanup completed")
        except Exception as e:
            logger.error(f"Error during psycopg-toolkit Database cleanup: {e}")


@asynccontextmanager
async def get_database_pool(config: AuthlyConfig) -> AsyncGenerator[AsyncConnectionPool, None]:
    """Legacy method: Create and manage database connection pool lifecycle.

    This method is provided for backward compatibility. New code should use
    get_database() to access the full psycopg-toolkit Database functionality.

    Args:
        config: Application configuration containing database settings

    Yields:
        AsyncConnectionPool: Shared database connection pool

    Raises:
        Exception: If database initialization fails
    """
    logger.warning(
        "Using legacy get_database_pool - consider migrating to get_database for full psycopg-toolkit integration"
    )

    async with get_database(config) as database:
        pool = await database.get_pool()
        yield pool


@asynccontextmanager
async def get_configuration() -> AsyncGenerator[AuthlyConfig, None]:
    """Load and provide configuration instance.

    Yields:
        AuthlyConfig: Application configuration

    Raises:
        Exception: If configuration loading fails
    """
    logger.info("Loading application configuration")

    try:
        from authly.config import EnvDatabaseProvider, EnvSecretProvider

        secret_provider = EnvSecretProvider()
        database_provider = EnvDatabaseProvider()
        config = AuthlyConfig.load(secret_provider, database_provider)

        logger.info("Configuration loaded successfully")
        yield config

    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise RuntimeError("Failed to load configuration: See logs for details") from None
    finally:
        # No cleanup needed for config
        logger.debug("Configuration context cleanup completed")
