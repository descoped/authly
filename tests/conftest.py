import tempfile
from pathlib import Path
from typing import AsyncGenerator, Optional

import pytest
from psycopg_pool import AsyncConnectionPool

from authly import Authly
from authly.config import AuthlyConfig, StaticSecretProvider, StaticDatabaseProvider, find_root_folder

pytest_plugins = [
    "fixtures.testing",
]

_test_config: Optional[AuthlyConfig] = None


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
async def initialize_authly(test_config: AuthlyConfig, db_pool: AsyncConnectionPool) -> AsyncGenerator[Authly, None]:
    authly = Authly.initialize(pool=db_pool, configuration=test_config)

    yield authly

    # Reset the Authly singleton for the next test ensures that:
    #
    # 1. Each test gets a fresh Authly instance
    # 2. Each test works with its own database pool
    # 3. There's no state leakage between tests
    # 4. The "pool closed" error is avoided since we're not trying to reuse a closed pool
    #
    Authly._instance = None  # This is important!
