"""Mode-adaptive resource manager for Authly.

This module provides the core AuthlyResourceManager that replaces the singleton
pattern with a unified approach supporting all deployment modes.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from psycopg_pool import AsyncConnectionPool
from psycopg_toolkit import Database, DatabaseSettings, TransactionManager

from authly.config import AuthlyConfig
from authly.core.deployment_modes import DeploymentMode, ModeConfiguration

logger = logging.getLogger(__name__)


class AuthlyResourceManager:
    """Mode-adaptive resource manager supporting all deployment patterns.

    This class replaces the singleton pattern and dependency injection
    redundancy with a unified approach that adapts to different deployment modes.

    Key features:
    - Mode-aware initialization and lifecycle management
    - Unified resource access across all deployment scenarios
    - Optimized settings per deployment mode
    - Clean separation of resource management from business logic
    """

    def __init__(self, mode: DeploymentMode, config: AuthlyConfig):
        """Initialize resource manager for specific deployment mode.

        Args:
            mode: The deployment mode to configure for
            config: Application configuration instance
        """
        self.mode = mode
        self.config = config
        self._database: Database | None = None
        self._pool: AsyncConnectionPool | None = None
        self._transaction_manager: TransactionManager | None = None
        self._redis_client = None
        self._redis_pool = None
        self._self_managed = False

        logger.info(f"Initializing AuthlyResourceManager for {mode.value} mode")

    @property
    def is_initialized(self) -> bool:
        """Check if resource manager is properly initialized.

        Returns:
            True if the database and pool are available, False otherwise
        """
        return self._database is not None and self._pool is not None

    # Factory Methods for Different Modes

    @classmethod
    def for_production(cls, config: AuthlyConfig) -> "AuthlyResourceManager":
        """Create resource manager for production deployment.

        Production mode expects external pool management via FastAPI lifespan.
        The pool lifecycle is managed by the application container.

        Args:
            config: Application configuration

        Returns:
            Configured resource manager for production mode
        """
        logger.debug("Creating resource manager for production mode")
        return cls(DeploymentMode.PRODUCTION, config)

    @classmethod
    def for_embedded(cls, config: AuthlyConfig) -> "AuthlyResourceManager":
        """Create resource manager for embedded development mode.

        Embedded mode creates and manages its own PostgreSQL testcontainer
        with automatic seeding and cleanup.

        Args:
            config: Application configuration

        Returns:
            Configured resource manager for embedded mode
        """
        logger.debug("Creating resource manager for embedded mode")
        return cls(DeploymentMode.EMBEDDED, config)

    @classmethod
    def for_cli(cls, config: AuthlyConfig) -> "AuthlyResourceManager":
        """Create resource manager for CLI/admin operations.

        CLI mode connects to existing database with minimal resource usage
        optimized for short-lived administrative operations.

        Args:
            config: Application configuration

        Returns:
            Configured resource manager for CLI mode
        """
        logger.debug("Creating resource manager for CLI mode")
        return cls(DeploymentMode.CLI, config)

    @classmethod
    def for_testing(cls, config: AuthlyConfig) -> "AuthlyResourceManager":
        """Create resource manager for testing scenarios.

        Testing mode integrates with pytest fixtures and testcontainers
        with optimized settings for test execution and isolation.

        Args:
            config: Application configuration

        Returns:
            Configured resource manager for testing mode
        """
        logger.debug("Creating resource manager for testing mode")
        return cls(DeploymentMode.TESTING, config)

    # Resource Management Methods

    async def initialize_with_external_database(self, database: Database) -> None:
        """Initialize with externally managed psycopg-toolkit Database (production mode).

        Used when Database lifecycle is managed by FastAPI lifespan or similar
        external container. The resource manager does not own the Database lifecycle.

        Args:
            database: Externally managed psycopg-toolkit Database instance
        """
        if self._database is not None:
            logger.warning("Resource manager already initialized, replacing database")

        self._database = database
        self._pool = await database.get_pool()
        self._transaction_manager = await database.get_transaction_manager()
        self._self_managed = False
        logger.info(f"Resource manager initialized with external Database - mode: {self.mode.value}")

    async def initialize_with_external_pool(self, pool: AsyncConnectionPool) -> None:
        """Legacy method for backward compatibility.

        This method is provided for transition compatibility but creates a minimal
        Database wrapper around the pool. New code should use initialize_with_external_database.

        Args:
            pool: Externally managed database connection pool
        """
        logger.warning(
            "Using legacy initialize_with_external_pool - consider migrating to initialize_with_external_database"
        )

        # Create minimal Database settings from config
        database_url = self.config.database_url
        url = urlparse(database_url)

        # Get default port from config with fallback
        try:
            default_port = self.config.postgres_port
        except (AttributeError, RuntimeError):
            default_port = 5432

        settings = DatabaseSettings(
            host=url.hostname,
            port=url.port or default_port,
            dbname=url.path.lstrip("/"),
            user=url.username,
            password=url.password,
        )

        # Create Database instance but don't manage its lifecycle
        database = Database(settings)
        database._pool = pool  # Inject the external pool

        await self.initialize_with_external_database(database)

    @asynccontextmanager
    async def managed_database(self) -> AsyncGenerator[Database, None]:
        """Create and manage Database lifecycle using psycopg-toolkit (embedded/CLI modes).

        Use this for modes that need self-contained resource management.
        The Database instance is created, initialized, and cleaned up automatically.

        Yields:
            Database: Self-managed psycopg-toolkit Database instance

        Raises:
            RuntimeError: If used in production mode (should use external Database)
        """
        if self.mode == DeploymentMode.PRODUCTION:
            raise RuntimeError("Production mode should use initialize_with_external_database")

        logger.info(f"Creating managed Database for {self.mode.value} mode")

        # Parse database URL from config
        database_url = self.config.database_url
        url = urlparse(database_url)

        # Get default port from config with fallback
        try:
            default_port = self.config.postgres_port
        except (AttributeError, RuntimeError):
            default_port = 5432

        # Apply mode-specific pool settings
        pool_settings = ModeConfiguration.get_pool_settings(self.mode)
        logger.debug(f"Using pool settings for {self.mode.value}: {pool_settings}")

        settings = DatabaseSettings(
            host=url.hostname,
            port=url.port or default_port,
            dbname=url.path.lstrip("/"),
            user=url.username,
            password=url.password,
            **pool_settings,  # Apply mode-specific settings
        )

        database = Database(settings)
        try:
            await database.create_pool()
            await database.init_db()

            await self.initialize_with_external_database(database)
            self._self_managed = True

            logger.info(
                f"Managed Database ready for {self.mode.value} mode - host: {url.hostname}, db: {url.path.lstrip('/')}"
            )
            yield database

        except Exception as e:
            logger.error(f"Failed to initialize managed Database for {self.mode.value} mode: {e}")
            raise RuntimeError(
                "Failed to initialize managed Database for {self.mode.value} mode: See logs for details"
            ) from None
        finally:
            self._database = None
            self._pool = None
            self._transaction_manager = None
            self._self_managed = False

            logger.info(f"Shutting down managed Database for {self.mode.value} mode")
            try:
                await database.close()
                logger.info(f"Database cleanup completed for {self.mode.value} mode")
            except Exception as e:
                logger.error(f"Error during Database cleanup for {self.mode.value} mode: {e}")

    @asynccontextmanager
    async def managed_pool(self) -> AsyncGenerator[AsyncConnectionPool, None]:
        """Legacy method providing pool access via Database (backward compatibility).

        This method is provided for transition compatibility. New code should use
        managed_database() to get full psycopg-toolkit Database functionality.

        Yields:
            AsyncConnectionPool: Pool from managed Database instance
        """
        logger.warning("Using legacy managed_pool - consider migrating to managed_database")

        async with self.managed_database() as database:
            pool = await database.get_pool()
            yield pool

    def get_database(self) -> Database:
        """Get psycopg-toolkit Database instance regardless of deployment mode.

        Returns:
            Database: The active psycopg-toolkit Database instance

        Raises:
            RuntimeError: If resource manager not properly initialized
        """
        if not self.is_initialized:
            raise RuntimeError(
                f"Resource manager not initialized for {self.mode.value} mode. "
                f"Use initialize_with_external_database() or managed_database() context manager."
            )
        return self._database

    def get_pool(self) -> AsyncConnectionPool:
        """Get database pool regardless of deployment mode.

        Returns:
            AsyncConnectionPool: The active database connection pool

        Raises:
            RuntimeError: If resource manager not properly initialized
        """
        if not self.is_initialized:
            raise RuntimeError(
                f"Resource manager not initialized for {self.mode.value} mode. "
                f"Use initialize_with_external_database() or managed_database() context manager."
            )
        return self._pool

    def get_transaction_manager(self) -> TransactionManager:
        """Get psycopg-toolkit TransactionManager for test isolation and advanced transaction control.

        Returns:
            TransactionManager: The active TransactionManager instance

        Raises:
            RuntimeError: If resource manager not properly initialized
        """
        if not self.is_initialized:
            raise RuntimeError(
                f"Resource manager not initialized for {self.mode.value} mode. "
                f"Use initialize_with_external_database() or managed_database() context manager."
            )
        return self._transaction_manager

    def get_config(self) -> AuthlyConfig:
        """Get application configuration.

        Returns:
            AuthlyConfig: The application configuration instance
        """
        return self.config

    # Redis Connection Management (Optional)

    async def initialize_redis(self) -> bool:
        """Initialize Redis connection if configured.

        Returns:
            True if Redis was successfully initialized, False if disabled or failed
        """
        if not self.config.redis_enabled:
            logger.debug("Redis disabled via configuration")
            return False

        if not self.config.redis_url:
            logger.debug("Redis URL not configured")
            return False

        try:
            # Import Redis only when needed
            import redis.asyncio as redis

            # Create Redis connection pool
            self._redis_pool = redis.ConnectionPool.from_url(
                self.config.redis_url,
                max_connections=self.config.redis_connection_pool_size,
                socket_connect_timeout=self.config.redis_connection_timeout,
                socket_keepalive=self.config.redis_socket_keepalive,
                decode_responses=True,
            )

            # Create Redis client
            self._redis_client = redis.Redis(connection_pool=self._redis_pool)

            # Test connection
            await self._redis_client.ping()

            logger.info("Redis connection initialized successfully")
            return True

        except ImportError:
            logger.warning("Redis dependency not available. Install with: uv add --group redis authly")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize Redis connection: {e}")
            self._redis_client = None
            self._redis_pool = None
            return False

    async def cleanup_redis(self) -> None:
        """Cleanup Redis connections."""
        if self._redis_client:
            try:
                await self._redis_client.aclose()
            except Exception as e:
                logger.error(f"Error closing Redis client: {e}")
            finally:
                self._redis_client = None

        if self._redis_pool:
            try:
                await self._redis_pool.aclose()
            except Exception as e:
                logger.error(f"Error closing Redis pool: {e}")
            finally:
                self._redis_pool = None

    def get_redis_client(self):
        """Get Redis client if available.

        Returns:
            Redis client instance or None if not configured/available
        """
        return self._redis_client

    @property
    def redis_available(self) -> bool:
        """Check if Redis is available and connected.

        Returns:
            True if Redis client is available and connected
        """
        return self._redis_client is not None

    async def test_redis_connection(self) -> bool:
        """Test Redis connection health.

        Returns:
            True if Redis is accessible, False otherwise
        """
        if not self._redis_client:
            return False

        try:
            await self._redis_client.ping()
            return True
        except Exception as e:
            logger.error(f"Redis connection test failed: {e}")
            return False

    # Mode-Specific Behavior

    def get_pool_settings(self) -> dict:
        """Get pool configuration optimized for current deployment mode.

        Returns:
            Dictionary containing mode-optimized pool settings
        """
        return ModeConfiguration.get_pool_settings(self.mode)

    def should_bootstrap_admin(self) -> bool:
        """Determine if admin bootstrap should run in current mode.

        Returns:
            True if admin system should be bootstrapped, False otherwise
        """
        result = ModeConfiguration.should_bootstrap_admin(self.mode)
        logger.debug(f"Admin bootstrap for {self.mode.value} mode: {result}")
        return result

    def get_lifecycle_strategy(self) -> str:
        """Get resource lifecycle management strategy for current mode.

        Returns:
            String identifier for the lifecycle strategy
        """
        return ModeConfiguration.get_lifecycle_strategy(self.mode)

    # Utility Methods

    def get_mode_info(self) -> dict:
        """Get comprehensive information about current mode configuration.

        Returns:
            Dictionary containing mode, settings, and status information
        """
        return {
            "mode": self.mode.value,
            "initialized": self.is_initialized,
            "self_managed": self._self_managed,
            "has_database": self._database is not None,
            "has_pool": self._pool is not None,
            "has_transaction_manager": self._transaction_manager is not None,
            "pool_settings": self.get_pool_settings(),
            "lifecycle_strategy": self.get_lifecycle_strategy(),
            "bootstrap_admin": self.should_bootstrap_admin(),
        }

    def __repr__(self) -> str:
        """String representation of resource manager.

        Returns:
            Human-readable string describing the resource manager state
        """
        status = "initialized" if self.is_initialized else "uninitialized"
        return f"AuthlyResourceManager(mode={self.mode.value}, status={status})"
