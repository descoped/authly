import logging
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator

import psycopg
import pytest
from psycopg import AsyncConnection, AsyncTransaction
from psycopg_pool import AsyncConnectionPool
from psycopg_toolkit import Database, DatabaseSettings, TransactionManager
from testcontainers.postgres import PostgresContainer

from authly.config import find_root_folder

logger = logging.getLogger(__name__)

# Global registry for callbacks
DBCallback = Callable[[AsyncConnectionPool], Awaitable[None]]
_db_callbacks: list[DBCallback] = []


# Register callbacks
def register_db_init_callback(callback: DBCallback):
    """Register a callback to be run when database pool is initialized"""
    _db_callbacks.append(callback)


# Private reference to Database
_db: Database | None = None


@pytest.fixture(scope="session")
def postgres_container() -> Generator[PostgresContainer, None, None]:
    """Provides a PostgreSQL container for the test session"""
    postgres = PostgresContainer(
        image="pgvector/pgvector:pg17",
        username="test",
        password="test",
        dbname="authly_test",
    )

    postgres.with_volume_mapping(
        str(find_root_folder() / "docker-postgres"),
        "/docker-entrypoint-initdb.d",  # all sql scripts put in this directory, will be executed on startup
    )

    with postgres as container:
        yield container


@pytest.fixture(scope="session")
def _db_settings(postgres_container: PostgresContainer) -> DatabaseSettings:
    return DatabaseSettings(
        host=postgres_container.get_container_host_ip(),
        port=postgres_container.get_exposed_port(5432),
        dbname=postgres_container.dbname,
        user=postgres_container.username,
        password=postgres_container.password,
        # Increase pool size for tests to handle concurrent connections
        min_pool_size=10,
        max_pool_size=50,
    )


@pytest.fixture(scope="function")
async def _database_instance(_db_settings: DatabaseSettings) -> AsyncGenerator[Database, None]:
    """Create a Database instance that persists for the entire test session."""
    global _db
    if _db is None:
        logger.info("Creating new Database instance (first test)")
        _db = Database(settings=_db_settings)
        try:
            await _db.create_pool()
            # Register all collected callbacks
            for callback in _db_callbacks:
                await _db.register_init_callback(callback)

            await _db.init_db()
            logger.info("Database pool initialized successfully")
        except Exception as e:
            await _db.cleanup()
            raise e from e
    else:
        logger.debug("Reusing existing Database instance")

    yield _db

    # Clean up after each test to prevent pool exhaustion
    if _db is not None:
        pool = await _db.get_pool()
        stats = pool.get_stats()
        logger.debug(f"Pool stats before cleanup: {stats}")
        await _db.cleanup()
        _db = None


@pytest.fixture(scope="function")
async def db_pool(_database_instance: Database) -> AsyncGenerator[AsyncConnectionPool, None]:
    """Get the connection pool from the database instance."""
    yield await _database_instance.get_pool()


@pytest.fixture(scope="function")
async def db_connection(_database_instance: Database) -> AsyncGenerator[AsyncConnection, None]:
    pool = await _database_instance.get_pool()
    async with pool.connection() as conn, conn.cursor() as _:
        yield conn


@pytest.fixture(scope="function")
async def db_connection_rollback_transaction(_database_instance: Database) -> AsyncGenerator[AsyncConnection, None]:
    pool = await _database_instance.get_pool()
    async with pool.connection() as conn:
        assert conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
        async with conn.cursor() as cursor:
            await cursor.execute("BEGIN")
            assert conn.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS
            try:
                yield conn
            finally:
                assert conn.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS
                await cursor.execute("ROLLBACK")
                assert conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE


@pytest.fixture(scope="function")
async def transaction_manager(_database_instance: Database) -> AsyncGenerator[TransactionManager, None]:
    yield await _database_instance.get_transaction_manager()


@pytest.fixture(scope="function")
async def transaction(transaction_manager: TransactionManager) -> AsyncGenerator[AsyncTransaction, None]:
    """Get a transaction for each test function."""
    async with transaction_manager.transaction() as conn, conn.transaction() as tx:
        yield tx
