import asyncio
import logging
import os
import signal
from datetime import datetime, timezone
from uuid import uuid4

import uvicorn
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from psycopg_pool import AsyncConnectionPool
from psycopg_toolkit import Database, DatabaseSettings
from setup_logging import setup_logging
from testcontainers.postgres import PostgresContainer

from authly import Authly
from authly.api import auth_router, health_router, oauth_router, users_router
from authly.api.admin_middleware import setup_admin_middleware
from authly.api.admin_router import admin_router
from authly.auth import get_password_hash
from authly.bootstrap import bootstrap_admin_system
from authly.config import AuthlyConfig, StaticDatabaseProvider, StaticSecretProvider, find_root_folder
from authly.users import UserModel, UserRepository

logger = logging.getLogger("authly-embedded")

"""
Fixed embedded server for Authly development and testing.

Run:
    poetry install
    source .venv/bin/activate 
    python examples/authly-embedded.py
    
    cd examples
    
    # Test all endpoints
    ./api-test.sh
    
    # Test rate limiting and invalid payload
    ./api-test.sh test_rate_limiting test_invalid_payload
     
    # Parallel test rate limiting 
    ./api-test.sh --parallel test_rate_limiting
"""


async def _post_initialize_db(pool: AsyncConnectionPool) -> None:
    """Execute initialization after Docker Postgres container has run init-db-and-user.sql

    This callback is triggered after the Postgres database container has completed
    its initial setup and executed the init-db-and-user.sql script.

    Args:
        pool: The async connection pool

    Returns:
        None
    """
    # Log tables to verify setup
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
            tables = await cursor.fetchall()
            logger.info("Tables: %s", ", ".join(table[0] for table in tables))

    # Create test users including admin user for testing
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
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                    is_active=True,
                    is_verified=True,
                    is_admin=bool(user_data["is_admin"]),
                )
                await user_repo.create(user)
                logger.info("Created user: %s (admin: %s)", user.username, user.is_admin)
        
        # Bootstrap admin system with proper scopes
        try:
            bootstrap_results = await bootstrap_admin_system(connection)
            logger.info(f"Admin bootstrap completed: {bootstrap_results}")
        except Exception as e:
            logger.error(f"Admin bootstrap failed: {e}")
            # Continue setup even if bootstrap fails


async def init_app():
    """Initialize the application with PostgreSQL container and FastAPI app"""
    
    # Create PostgreSQL container with proper configuration
    postgres = PostgresContainer(
        image="pgvector/pgvector:pg17",  # Use same image as tests
        username="authly",
        password="authly", 
        dbname="authly"
    ).with_env("POSTGRES_HOST_AUTH_METHOD", "trust")
    
    # Add volume mapping for SQL initialization scripts
    postgres.with_volume_mapping(
        str(find_root_folder() / "docker"),
        "/docker-entrypoint-initdb.d",
    )
    
    # Start the container without problematic port binding
    postgres.start()

    # Get dynamic port assignment from container
    host = postgres.get_container_host_ip()
    port = postgres.get_exposed_port(5432)
    
    # Build connection settings using dynamic port
    settings = DatabaseSettings(
        host=host,
        port=port,
        dbname=postgres.dbname,
        user=postgres.username,
        password=postgres.password,
    )

    logger.info(f"PostgreSQL container started on {host}:{port}")
    
    # Build connection string for CLI testing
    database_url = f"postgresql://{settings.user}:{settings.password}@{settings.host}:{settings.port}/{settings.dbname}"
    print(f"\n🔧 To test CLI with this database, run:")
    print(f"JWT_SECRET_KEY='test-secret-key' JWT_REFRESH_SECRET_KEY='test-refresh-key' DATABASE_URL='{database_url}' poetry run python -m authly.admin.cli status\n")

    # Create database pool and initialize
    db = Database(settings)
    try:
        await db.create_pool()
        await db.register_init_callback(_post_initialize_db)
        await db.init_db()
    except Exception as e:
        await db.cleanup()
        postgres.stop()
        raise e

    db_pool = await db.get_pool()

    # Configure Authly with static providers
    secret_provider = StaticSecretProvider("my-secret", "refresh-secret")
    database_provider = StaticDatabaseProvider(database_url)
    config = AuthlyConfig.load(secret_provider, database_provider)
    
    # Initialize Authly singleton
    _ = Authly.initialize(pool=db_pool, configuration=config)

    # Create FastAPI application
    app = FastAPI(
        title="Authly Auth API",
        version="0.1.0",
        description="Authly Authentication and Authorization Service"
    )
    
    # Setup admin security middleware
    setup_admin_middleware(app)
    
    # Mount static files for OAuth templates
    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src", "authly", "static")
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    # Include all routers
    app.include_router(health_router)
    app.include_router(auth_router, prefix=config.fastapi_api_version_prefix)
    app.include_router(users_router, prefix=config.fastapi_api_version_prefix)
    app.include_router(oauth_router, prefix=config.fastapi_api_version_prefix)
    
    # Include admin router
    app.include_router(admin_router)

    # Custom OpenAPI schema
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        openapi_schema = get_openapi(
            title="Authly Auth API",
            version="0.1.0",
            description="Authly Authentication and Authorization Service",
            routes=app.routes,
        )
        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi

    return app, db, postgres


async def shutdown(server: uvicorn.Server, db, postgres):
    """Graceful shutdown handler for all resources"""
    logger.info("Initiating graceful shutdown...")

    # Stop uvicorn server
    logger.info("Stopping uvicorn server...")
    server.should_exit = True

    # Close database connections with timeout
    logger.info("Closing database connections...")
    try:
        await asyncio.wait_for(db.cleanup(), timeout=10.0)
    except asyncio.TimeoutError:
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


async def main():
    """Main entry point for embedded Authly server"""
    setup_logging(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")

    # Set specific logger levels
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("testcontainers").setLevel(logging.INFO)

    app, db, postgres = await init_app()

    # Create uvicorn server
    config = uvicorn.Config(app, host="0.0.0.0", port=8000)
    server = uvicorn.Server(config)

    # Setup signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    signals = (signal.SIGTERM, signal.SIGINT)

    for sig in signals:
        loop.add_signal_handler(
            sig, 
            lambda s=sig: asyncio.create_task(shutdown(server, db, postgres))
        )

    # Start server
    try:
        logger.info("Starting Authly embedded server on http://0.0.0.0:8000")
        await server.serve()
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        # Remove signal handlers
        for sig in signals:
            try:
                loop.remove_signal_handler(sig)
            except ValueError:
                pass  # Signal handler already removed


if __name__ == "__main__":
    asyncio.run(main())