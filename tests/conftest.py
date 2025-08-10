import tempfile
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest

# Legacy Authly import removed - using AuthlyResourceManager
from authly.config import AuthlyConfig, StaticDatabaseProvider, StaticSecretProvider, find_root_folder
from authly.core.resource_manager import AuthlyResourceManager

pytest_plugins = [
    "fixtures.testing",
]

# Import helper fixtures for committed test data

_test_config: AuthlyConfig | None = None


@pytest.fixture(scope="session")
def test_config() -> AuthlyConfig:
    global _test_config
    if _test_config is None:
        secret_provider = StaticSecretProvider(secret_key="test-secret-key", refresh_secret_key="test-refresh-key")
        database_provider = StaticDatabaseProvider(database_url="postgresql://authly:authly@localhost:5432/authly")
        output_dir = find_root_folder() / "output"
        output_dir.mkdir(exist_ok=True)
        secrets_path = Path(tempfile.mkdtemp(dir=output_dir))
        _test_config = AuthlyConfig.load(secret_provider, database_provider, secrets_path)
    return _test_config


@pytest.fixture(scope="function")
async def test_resource_manager(
    test_config: AuthlyConfig, _database_instance
) -> AsyncGenerator[AuthlyResourceManager, None]:
    """Create AuthlyResourceManager for testing with external Database instance.

    This fixture integrates the new resource manager pattern with the existing
    test architecture, providing full psycopg-toolkit Database integration.
    """
    # Create resource manager for testing mode
    resource_manager = AuthlyResourceManager.for_testing(test_config)

    # Initialize with the test Database instance
    await resource_manager.initialize_with_external_database(_database_instance)

    # Initialize Redis (will be disabled in test config by default)
    await resource_manager.initialize_redis()

    # Initialize backend factory for tests
    from authly.core.backend_factory import initialize_backend_factory

    initialize_backend_factory(resource_manager)

    # Set up the global resource manager for dependencies
    from authly.core.dependencies import create_resource_manager_provider

    create_resource_manager_provider(resource_manager)

    yield resource_manager

    # No cleanup needed - Database lifecycle is managed by _database_instance fixture


@pytest.fixture(scope="function")
async def initialize_authly(
    test_config: AuthlyConfig, _database_instance
) -> AsyncGenerator[AuthlyResourceManager, None]:
    """Updated fixture - provides AuthlyResourceManager instead of legacy Authly singleton.

    This fixture replaces the legacy Authly singleton with the modern resource manager
    architecture for proper dependency injection patterns.
    """
    resource_manager = AuthlyResourceManager.for_testing(test_config)
    await resource_manager.initialize_with_external_database(_database_instance)

    # Initialize Redis (will be disabled in test config by default)
    await resource_manager.initialize_redis()

    # Initialize backend factory for tests
    from authly.core.backend_factory import initialize_backend_factory

    initialize_backend_factory(resource_manager)

    # Set up the global resource manager for dependencies
    from authly.core.dependencies import create_resource_manager_provider

    create_resource_manager_provider(resource_manager)

    yield resource_manager

    # No cleanup needed - Database lifecycle is managed by _database_instance fixture


@pytest.fixture(scope="function")
async def initialize_authly_with_resource_manager(
    test_resource_manager: AuthlyResourceManager,
) -> AsyncGenerator[AuthlyResourceManager, None]:
    """Updated fixture - provides AuthlyResourceManager directly.

    This fixture eliminates the hybrid approach and provides clean
    resource manager access for modern dependency injection patterns.
    """
    yield test_resource_manager


@pytest.fixture(scope="function")
async def authly_service_factory_rm(test_resource_manager: AuthlyResourceManager, transaction_manager):
    """Modern service factory using resource manager and TransactionManager.

    This factory creates services with proper resource manager integration
    and transaction isolation for testing.
    """

    def _create_service(service_class, **kwargs):
        """Create service instance with resource manager and transaction support.

        Args:
            service_class: The service class to instantiate
            **kwargs: Additional arguments to pass to service constructor

        Returns:
            Service instance configured for testing
        """
        # Service constructors will be updated to accept resource_manager
        # For now, provide both resource manager and legacy parameters
        service_kwargs = {
            "resource_manager": test_resource_manager,
            "transaction_manager": transaction_manager,
            **kwargs,
        }

        return service_class(**service_kwargs)

    return _create_service


@pytest.fixture(scope="function")
async def authly_repository_factory_rm(test_resource_manager: AuthlyResourceManager, transaction_manager):
    """Modern repository factory using resource manager and TransactionManager.

    This factory creates repositories with proper transaction isolation
    and psycopg-toolkit BaseRepository patterns.
    """

    async def _create_repository(repository_class, **kwargs):
        """Create repository instance with transaction-isolated connection.

        Args:
            repository_class: The repository class to instantiate
            **kwargs: Additional arguments to pass to repository constructor

        Returns:
            Repository instance with transaction-isolated connection
        """
        # Create repository inside transaction context
        async with transaction_manager.transaction() as conn:
            repository_kwargs = {"db_connection": conn, **kwargs}

            repository = repository_class(**repository_kwargs)
            yield repository

    return _create_repository
