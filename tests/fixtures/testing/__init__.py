from fixtures.testing.lifespan import custom_test_server, test_server
from fixtures.testing.postgres import (
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
    "postgres_container",
    "db_pool",
    "db_connection",
    "db_connection_rollback_transaction",
    "transaction_manager",
    "transaction",
    "_database_instance",
    "_db_settings",
    "register_db_init_callback",
    "_db_callbacks",
    "custom_test_server",
    "test_server",
]


# noinspection SpellCheckingInspection
def pytest_addoption(parser):
    """Add database-related command line options"""
    group = parser.getgroup("database")
    group.addoption(
        "--db-init-callback", action="store", default=None, help="Path to database initialization callback function"
    )
