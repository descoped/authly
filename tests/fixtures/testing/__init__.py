from .lifespan import (
    custom_test_server,
    hybrid_test_server,
    resource_manager_server,
    resource_manager_test_server,
    test_server,
)
from .postgres import (
    _database_instance,
    _db_callbacks,
    _db_settings,
    db_connection,
    db_connection_rollback_transaction,
    db_pool,
    postgres_container,
    register_db_init_callback,
    transaction,
    transaction_manager,
)

__all__ = [
    "_database_instance",
    "_db_callbacks",
    "_db_settings",
    # FastAPI test server fixtures (legacy)
    "custom_test_server",
    "db_connection",
    "db_connection_rollback_transaction",
    "db_pool",
    "hybrid_test_server",
    # PostgreSQL fixtures
    "postgres_container",
    "register_db_init_callback",
    "resource_manager_server",
    # FastAPI test server fixtures (resource manager)
    "resource_manager_test_server",
    "test_server",
    "transaction",
    "transaction_manager",
]


# noinspection SpellCheckingInspection
def pytest_addoption(parser):
    """Add database-related command line options"""
    group = parser.getgroup("database")
    group.addoption(
        "--db-init-callback", action="store", default=None, help="Path to database initialization callback function"
    )
