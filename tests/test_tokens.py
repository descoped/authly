import pytest
from psycopg import AsyncConnection
from psycopg import AsyncTransaction
from psycopg_pool import AsyncConnectionPool
from psycopg_toolkit import TransactionManager
from testcontainers.postgres import PostgresContainer


def test_postgres(postgres_container: PostgresContainer):
    print(f"\nPostgres URL: {postgres_container.get_connection_url()}")


@pytest.mark.asyncio
async def test_db_pool(db_pool: AsyncConnectionPool):
    async with db_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1")
            print("SELECT 1: success")


@pytest.mark.asyncio
async def test_database(db_connection: AsyncConnection):
    async with db_connection.cursor() as cur:
        await cur.execute("SELECT 1")
        print("\nSELECT 1: success")


@pytest.mark.asyncio
async def test_transaction(transaction: AsyncTransaction):
    async with transaction.connection.cursor() as cur:
        await cur.execute("SELECT 1")
        print("\nSELECT 1: success")


@pytest.mark.asyncio
async def test_with_transaction(transaction_manager: TransactionManager):
    async with transaction_manager.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1")
            print("\nSELECT 1: success")
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1")
            print("\nSELECT 1: 2nd success")
