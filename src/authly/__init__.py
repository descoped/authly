import logging
from typing import AsyncGenerator

from psycopg import AsyncConnection, AsyncTransaction

from authly.authly import Authly
from authly.config.config import AuthlyConfig

__all__ = [
    "Authly",
    "authly_db_connection",
    "authly_db_transaction",
    "get_config",
]

logger = logging.getLogger(__name__)


def get_config() -> AuthlyConfig:
    """Get current configuration."""
    return Authly.get_instance().get_config()  # to omit reading a private variable on instance


async def authly_db_connection() -> AsyncGenerator[AsyncConnection, None]:
    """Get a database connection as an async generator.

    Yields:
        AsyncConnection: Database connection from the pool in autocommit mode
    """
    pool = Authly.get_instance().get_pool()
    async with pool.connection() as conn:
        # Set autocommit mode for OAuth flows - data needs to be immediately visible
        await conn.set_autocommit(True)
        yield conn


async def authly_db_transaction() -> AsyncGenerator[AsyncTransaction, None]:
    """Get a database transaction as an async generator.

    Yields:
        AsyncTransaction: Transaction that is automatically committed or rolled back
    """
    async for conn in authly_db_connection():
        async with conn.transaction() as transaction:
            yield transaction
