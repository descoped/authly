import asyncio
import logging
import signal
from datetime import datetime, timezone
from uuid import uuid4

import uvicorn
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from psycopg_pool import AsyncConnectionPool
from psycopg_toolkit import Database, DatabaseSettings
from testcontainers.postgres import PostgresContainer

from authly import AuthlyConfig, Authly
from authly.api import auth_router, users_router, health_router
from authly.auth import get_password_hash
from authly.config import StaticSecretProvider, find_root_folder
from authly.users import UserModel, UserRepository
from setup_logging import setup_logging

logger = logging.getLogger(__name__)

"""
Run:
    poetry install
    source .venv/bin/activate 
    python examples/embeded.py
    
    cd examples
    
    # Test all endpoints
    ./api-test.sh
    
    # Test rate limiting and invalid payload
    ./api-test.sh test_invalid_payload
     
    # Parallel test rate limiting 
    ./api-test.sh --parallel test_rate_limiting
"""

async def _post_initialize_db(pool: AsyncConnectionPool) -> None:
    """Execute initialization after Docker Postgres container has run ini-db-and-user.sql

    This callback is triggered after the Postgres database container has completed
    its initial setup and executed the ini-db-and-user.sql script.

    Args:
        pool: The async connection pool

    Returns:
        None
    """
    # TODO: Remove after database schema is finalized - currently used to verify table creation
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            # noinspection SqlDialectInspection,SqlNoDataSourceInspection
            await cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
            tables = await cursor.fetchall()
            logger.info("Tables: %s", ", ".join(table[0] for table in tables))

    async with pool.connection() as connection:
        user_repo = UserRepository(connection)
        test_users = [
            {
                "username": "admin",
                "email": "admin@example.com",
                "password": "Test123!",
                "full_name": "Admin User",
                "is_admin": True,
            },
            {
                "username": "user1",
                "email": "user1@example.com",
                "password": "Test123!",
                "full_name": "Usee One",
                "is_admin": False,
            }
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
                logger.info("Created new user: %s", user.id)


async def run_init_script(conn, script_path: str):
    """
    Read and execute the initialization SQL script on the given connection.
    This connection is not wrapped in an explicit transaction, so commands like
    CREATE DATABASE can run in autocommit mode.
    """
    with open(script_path, "r") as f:
        sql = f.read()
    await conn.execute(sql)
    print("Initialization SQL script executed.")


async def init_app():
    # Create the container with a command override to ensure it stays alive.
    postgres = (
        PostgresContainer(
            image="pgvector/pgvector:pg17",
            username="test",
            password="test",
            dbname="authly_test"
        )
        .with_command("postgres")
    )

    postgres.with_volume_mapping(
        str(find_root_folder() / "docker"),
        "/docker-entrypoint-initdb.d",  # all sql scripts put in this directory, will be executed on startup
    )

    # Start the container.
    postgres.start()

    # Build the connection settings.
    settings = DatabaseSettings(
        host=postgres.get_container_host_ip(),
        port=postgres.get_exposed_port(5432),
        dbname=postgres.dbname,
        user=postgres.username,
        password=postgres.password
    )

    # Create the database pool.
    db = Database(settings)
    try:
        await db.create_pool()
        await db.register_init_callback(_post_initialize_db)
        await db.init_db()
    except Exception as e:
        await db.cleanup()
        raise e

    db_pool = await db.get_pool()

    # Load the Authly configuration
    secret_provider = StaticSecretProvider("my-secret", "refresh-secret")
    config = AuthlyConfig.load(secret_provider)  # secrets_path = None meaning it will use the default path
    _ = Authly.initialize(
        pool=db_pool,
        configuration=config
    )

    # Create the FastAPI app
    app = FastAPI()
    app.include_router(health_router)
    app.include_router(auth_router, prefix=config.fastapi_api_version_prefix)
    app.include_router(users_router, prefix=config.fastapi_api_version_prefix)

    # OpenAPI schema
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        openapi_schema = get_openapi(
            title="Authly Auth API",
            version="0.1.0",
            description="Authly Auth API",
            routes=app.routes,
        )
        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi

    # Return the app, database pool, and Postgres container
    return app, db, postgres


async def shutdown(server: uvicorn.Server, db, postgres):
    """Graceful shutdown handler"""
    logger.info("Initiating graceful shutdown...")

    # Signal the uvicorn server to stop
    logger.info("Stopping uvicorn server...")
    server.should_exit = True

    # Close database connections with a reasonable timeout
    logger.info("Closing database connections...")
    try:
        await asyncio.wait_for(db.cleanup(), timeout=10.0)
    except asyncio.TimeoutError:
        logger.warning("Database cleanup timed out")
    except Exception as e:
        logger.error(f"Error during database cleanup: {e}")

    # Stop the postgres container
    logger.info("Stopping postgres container...")
    postgres.stop()

    logger.info("Shutdown complete")


async def main():
    setup_logging()

    # Set specific logger levels
    logging.getLogger('uvicorn').setLevel(logging.INFO)
    logging.getLogger('testcontainers').setLevel(logging.INFO)

    app, db, postgres = await init_app()

    # Create the uvicorn server
    config = uvicorn.Config(app, host="0.0.0.0", port=8000)
    server = uvicorn.Server(config)

    # Setup signal handlers
    loop = asyncio.get_event_loop()
    signals = (signal.SIGTERM, signal.SIGINT)

    for sig in signals:
        loop.add_signal_handler(
            sig,
            lambda s=sig: asyncio.create_task(
                shutdown(server, db, postgres)
            )
        )

    # We're good to go
    try:
        await server.serve()
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        # Remove signal handlers
        for sig in signals:
            loop.remove_signal_handler(sig)


if __name__ == "__main__":
    asyncio.run(main())
