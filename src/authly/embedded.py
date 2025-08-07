"""
Embedded development server for Authly.

This module provides functionality to run Authly with embedded PostgreSQL
container for development and testing purposes.
"""

import asyncio
import contextlib
import logging
import os
import signal
from datetime import UTC, datetime
from uuid import uuid4

import uvicorn
from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool
from psycopg_toolkit import Database, DatabaseSettings
from testcontainers.postgres import PostgresContainer

from authly.app import create_embedded_app
from authly.auth import get_password_hash
from authly.bootstrap import bootstrap_admin_system
from authly.config import AuthlyConfig, StaticDatabaseProvider, StaticSecretProvider, find_root_folder
from authly.core.deployment_modes import DeploymentMode
from authly.core.mode_factory import AuthlyModeFactory
from authly.users import UserModel, UserRepository

logger = logging.getLogger("authly.embedded")


async def _post_initialize_db(pool: AsyncConnectionPool, seed: bool = False) -> None:
    """Execute initialization after Docker Postgres container has run init-db-and-user.sql"""
    # Log tables to verify setup
    async with pool.connection() as connection, connection.cursor() as cursor:
        await cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
        tables = await cursor.fetchall()
        logger.info("Tables: %s", ", ".join(table[0] for table in tables))

    # Create test users including admin user for testing
    if seed:
        async with pool.connection() as connection:
            user_repo = UserRepository(connection)
            test_users = [
                {
                    "username": "admin",
                    "email": "admin@example.com",
                    "password": "Test123!",
                    "is_admin": True,
                },
                {
                    "username": "user1",
                    "email": "user1@example.com",
                    "password": "Test123!",
                    "is_admin": False,
                },
            ]

            for user_data in test_users:
                if not await user_repo.get_by_email(user_data["email"]):
                    user = UserModel(
                        id=uuid4(),
                        username=user_data["username"],
                        email=user_data["email"],
                        password_hash=get_password_hash(user_data["password"]),
                        created_at=datetime.now(UTC),
                        updated_at=datetime.now(UTC),
                        is_active=True,
                        is_verified=True,
                        is_admin=bool(user_data["is_admin"]),
                    )
                    await user_repo.create(user)
                    logger.info("Created user: %s (admin: %s)", user.username, user.is_admin)

    # Bootstrap admin system with proper scopes
    async with pool.connection() as connection:
        try:
            bootstrap_results = await bootstrap_admin_system(connection)
            logger.info(f"Admin bootstrap completed: {bootstrap_results}")
        except Exception as e:
            logger.error(f"Admin bootstrap failed: {e}")
            # Continue setup even if bootstrap fails


def create_embedded_app_with_config(database_url: str, seed: bool = False) -> FastAPI:
    """Create FastAPI application for embedded mode with configuration."""
    # Configure Authly with static providers
    secret_provider = StaticSecretProvider("my-secret", "refresh-secret")
    database_provider = StaticDatabaseProvider(database_url)
    config = AuthlyConfig.load(secret_provider, database_provider)

    # Use shared app factory
    return create_embedded_app(config, database_url, seed)


async def run_embedded_server(host: str = "0.0.0.0", port: int = 8000, seed: bool = False) -> None:
    """Run Authly with embedded PostgreSQL container.

    This function automatically sets AUTHLY_MODE=embedded for proper resource manager initialization.
    """
    # Set deployment mode for embedded operation
    os.environ.setdefault("AUTHLY_MODE", "embedded")
    logger.info("Starting Authly embedded development server...")

    # Create PostgreSQL container with proper configuration
    postgres = PostgresContainer(
        image="pgvector/pgvector:pg17", username="authly", password="authly", dbname="authly"
    ).with_env("POSTGRES_HOST_AUTH_METHOD", "trust")

    # Add volume mapping for SQL initialization scripts
    postgres.with_volume_mapping(
        str(find_root_folder() / "docker-postgres"),
        "/docker-entrypoint-initdb.d",
    )

    # Start the container
    postgres.start()

    try:
        # Get dynamic port assignment from container
        # Use standard PostgreSQL port for embedded containers
        postgres_port = 5432

        container_host = postgres.get_container_host_ip()
        container_port = postgres.get_exposed_port(postgres_port)

        # Build connection settings using dynamic port
        settings = DatabaseSettings(
            host=container_host,
            port=container_port,
            dbname=postgres.dbname,
            user=postgres.username,
            password=postgres.password,
        )

        logger.info(f"PostgreSQL container started on {container_host}:{container_port}")

        # Build connection string for CLI testing
        database_url = (
            f"postgresql://{settings.user}:{settings.password}@{settings.host}:{settings.port}/{settings.dbname}"
        )
        print("\n🔧 To test CLI with this database, run:")
        print(
            f"JWT_SECRET_KEY='test-secret-key' JWT_REFRESH_SECRET_KEY='test-refresh-key' DATABASE_URL='{database_url}' python -m authly admin status\n"
        )

        # Create database pool and initialize
        db = Database(settings)
        await db.create_pool()
        await db.register_init_callback(lambda pool: _post_initialize_db(pool, seed))
        await db.init_db()

        await db.get_pool()

        # Initialize resource manager for embedded mode
        secret_provider = StaticSecretProvider("my-secret", "refresh-secret")
        database_provider = StaticDatabaseProvider(database_url)
        config = AuthlyConfig.load(secret_provider, database_provider)

        # Create resource manager using mode factory (will detect embedded mode)
        resource_manager = AuthlyModeFactory.create_resource_manager(config, DeploymentMode.EMBEDDED)
        await resource_manager.initialize_with_external_database(db)

        # Initialize Redis if configured
        redis_initialized = await resource_manager.initialize_redis()
        if redis_initialized:
            logger.info("Redis integration enabled for embedded mode")
        else:
            logger.info("Redis integration disabled - using memory backends")

        # Initialize backend factory
        from authly.core.backend_factory import initialize_backend_factory

        initialize_backend_factory(resource_manager)

        # Create FastAPI application with resource manager
        app = create_embedded_app(config, database_url, seed)

        # Set up dependency injection without app.state
        from authly.core.dependencies import create_resource_manager_provider, get_resource_manager

        provider = create_resource_manager_provider(resource_manager)
        app.dependency_overrides[get_resource_manager] = provider

        # Create uvicorn server
        config = uvicorn.Config(app, host=host, port=port)
        server = uvicorn.Server(config)

        # Setup signal handlers for graceful shutdown
        async def shutdown_handler():
            logger.info("Initiating graceful shutdown...")
            server.should_exit = True

            # Close resource manager and database connections
            logger.info("Cleaning up resource manager and database connections...")
            try:
                # Cleanup resource manager first
                if resource_manager:
                    await resource_manager.cleanup_redis()
                    await resource_manager.cleanup()

                # Clean up database with timeout from config
                cleanup_timeout = config.db_cleanup_timeout_seconds
                await asyncio.wait_for(db.cleanup(), timeout=cleanup_timeout)
            except TimeoutError:
                logger.warning("Database cleanup timed out")
            except Exception as e:
                logger.error(f"Error during database cleanup: {e}")

            # Stop PostgreSQL container
            logger.info("Stopping PostgreSQL container...")
            try:
                postgres.stop()
            except Exception as e:
                logger.error(f"Error stopping container: {e}")

            logger.info("Shutdown complete")

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        signals = (signal.SIGTERM, signal.SIGINT)

        for sig in signals:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown_handler()))

        # Start server
        logger.info(f"Starting Authly embedded server on http://{host}:{port}")
        await server.serve()

    except Exception as e:
        logger.error(f"Embedded server error: {e}")
        postgres.stop()
        raise RuntimeError("An error occurred") from e
    finally:
        # Cleanup signal handlers
        loop = asyncio.get_event_loop()
        for sig in signals:
            with contextlib.suppress(ValueError):
                loop.remove_signal_handler(sig)
