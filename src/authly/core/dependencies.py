"""FastAPI dependency injection for shared resources.

This module provides FastAPI dependencies using proper dependency injection
patterns without relying on app.state.
"""

import logging
from collections.abc import AsyncGenerator, Callable

from fastapi import Depends
from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool
from psycopg_toolkit import Database, TransactionManager

from authly.config import AuthlyConfig
from authly.core.resource_manager import AuthlyResourceManager

logger = logging.getLogger(__name__)

# Global resource manager instance - will be set by create_resource_manager_provider
_resource_manager_instance: AuthlyResourceManager | None = None


def create_resource_manager_provider(resource_manager: AuthlyResourceManager) -> Callable[[], AuthlyResourceManager]:
    """Create a dependency provider for the resource manager.

    This function creates a closure that captures the resource manager instance
    and returns it when called. This is the proper FastAPI pattern for injecting
    shared resources without using app.state.

    Args:
        resource_manager: The initialized resource manager instance

    Returns:
        A callable that returns the resource manager when invoked
    """

    def get_resource_manager() -> AuthlyResourceManager:
        """Get the resource manager instance.

        Returns:
            AuthlyResourceManager: The shared resource manager instance

        Raises:
            RuntimeError: If resource manager not initialized
        """
        if resource_manager is None:
            raise RuntimeError(
                "AuthlyResourceManager not initialized. "
                "Ensure create_resource_manager_provider was called during app startup."
            )
        return resource_manager

    # Store globally for other providers that need direct access
    global _resource_manager_instance
    _resource_manager_instance = resource_manager

    return get_resource_manager


# Default provider that will be overridden during app initialization
def get_resource_manager() -> AuthlyResourceManager:
    """Default resource manager provider.

    This will be overridden by the actual provider during app initialization.

    Raises:
        RuntimeError: Always, as this should be overridden
    """
    if _resource_manager_instance is None:
        raise RuntimeError(
            "Resource manager provider not initialized. This dependency must be overridden during app initialization."
        )
    return _resource_manager_instance


def get_database(resource_manager: AuthlyResourceManager = Depends(get_resource_manager)) -> Database:
    """FastAPI dependency to get psycopg-toolkit Database instance.

    Args:
        resource_manager: Injected resource manager

    Returns:
        Database: psycopg-toolkit Database instance
    """
    return resource_manager.get_database()


def get_transaction_manager(
    resource_manager: AuthlyResourceManager = Depends(get_resource_manager),
) -> TransactionManager:
    """FastAPI dependency to get psycopg-toolkit TransactionManager.

    Args:
        resource_manager: Injected resource manager

    Returns:
        TransactionManager: TransactionManager for advanced transaction control
    """
    return resource_manager.get_transaction_manager()


def get_config(resource_manager: AuthlyResourceManager = Depends(get_resource_manager)) -> AuthlyConfig:
    """FastAPI dependency to get shared configuration.

    Args:
        resource_manager: Injected resource manager

    Returns:
        AuthlyConfig: Application configuration
    """
    return resource_manager.get_config()


def get_database_pool(resource_manager: AuthlyResourceManager = Depends(get_resource_manager)) -> AsyncConnectionPool:
    """FastAPI dependency to get shared database pool.

    Args:
        resource_manager: Injected resource manager

    Returns:
        AsyncConnectionPool: Shared database connection pool
    """
    return resource_manager.get_pool()


async def get_database_connection(
    resource_manager: AuthlyResourceManager = Depends(get_resource_manager),
) -> AsyncGenerator[AsyncConnection, None]:
    """FastAPI dependency to get database connection from shared pool.

    Args:
        resource_manager: Injected resource manager

    Yields:
        AsyncConnection: Database connection from shared pool
    """
    pool = resource_manager.get_pool()

    async with pool.connection() as conn:
        logger.debug("Database connection acquired from resource manager pool")
        # Set autocommit mode for OAuth flows - data needs to be immediately visible
        await conn.set_autocommit(True)
        yield conn
        logger.debug("Database connection returned to resource manager pool")
