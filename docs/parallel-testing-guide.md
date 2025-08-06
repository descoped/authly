# Parallel Testing Guide for Authly

This guide explains how to implement and optimize parallel test execution for the Authly test suite.

## Current State

- **706 tests** total
- **PostgreSQL testcontainer** with connection pooling
- **Transaction isolation** for each test
- **Function-scoped fixtures** due to asyncio constraints

## Prerequisites

### 1. Install pytest-xdist

```bash
uv add pytest-xdist --dev
```

This plugin enables parallel test execution with pytest.

## Implementation Strategy

### Option 1: Process-Based Parallelism (Recommended)

Each test process gets its own:
- PostgreSQL container
- Connection pool
- Isolated database

**Pros:**
- Complete isolation between test processes
- No connection pool contention
- No shared state issues

**Cons:**
- Higher resource usage (multiple containers)
- Longer startup time

### Option 2: Shared Database with Schema Isolation

Single PostgreSQL container with:
- Multiple schemas (one per worker)
- Separate connection pools
- Schema-based isolation

**Pros:**
- Lower resource usage
- Faster startup
- Single container to manage

**Cons:**
- More complex setup
- Potential for cross-schema issues

## Implementation Steps

### Step 1: Update Test Fixtures for Parallel Execution

Create a new file `tests/fixtures/testing/parallel.py`:

```python
import os
import pytest
from testcontainers.postgres import PostgresContainer
from psycopg_toolkit import Database, DatabaseSettings
from typing import Generator, Optional
import logging

logger = logging.getLogger(__name__)

# Worker-specific containers
_worker_containers: dict[str, PostgresContainer] = {}
_worker_databases: dict[str, Database] = {}


def get_worker_id() -> str:
    """Get the pytest-xdist worker ID or 'master' for non-parallel execution."""
    return os.environ.get('PYTEST_XDIST_WORKER', 'master')


@pytest.fixture(scope="session")
def postgres_container_parallel() -> Generator[PostgresContainer, None, None]:
    """Provides a PostgreSQL container per worker for parallel execution."""
    worker_id = get_worker_id()
    
    if worker_id not in _worker_containers:
        logger.info(f"Creating PostgreSQL container for worker: {worker_id}")
        
        postgres = PostgresContainer(
            image="pgvector/pgvector:pg17",
            username="test",
            password="test",
            dbname=f"authly_test_{worker_id}",
        )
        
        postgres.with_volume_mapping(
            str(find_root_folder() / "docker-postgres"),
            "/docker-entrypoint-initdb.d",
        )
        
        postgres.start()
        _worker_containers[worker_id] = postgres
    
    yield _worker_containers[worker_id]


@pytest.fixture(scope="session")
def _db_settings_parallel(postgres_container_parallel: PostgresContainer) -> DatabaseSettings:
    """Database settings for parallel execution."""
    worker_id = get_worker_id()
    
    return DatabaseSettings(
        host=postgres_container_parallel.get_container_host_ip(),
        port=postgres_container_parallel.get_exposed_port(5432),
        dbname=f"authly_test_{worker_id}",
        user=postgres_container_parallel.username,
        password=postgres_container_parallel.password,
        # Larger pool for parallel execution
        min_pool_size=20,
        max_pool_size=100,
    )


@pytest.fixture(scope="function")
async def _database_instance_parallel(_db_settings_parallel: DatabaseSettings) -> AsyncGenerator[Database, None]:
    """Database instance for parallel execution."""
    worker_id = get_worker_id()
    
    if worker_id not in _worker_databases:
        logger.info(f"Creating Database instance for worker: {worker_id}")
        db = Database(settings=_db_settings_parallel)
        await db.create_pool()
        await db.init_db()
        _worker_databases[worker_id] = db
    
    yield _worker_databases[worker_id]
    
    # No cleanup - let worker keep its database instance


def pytest_sessionfinish(session, exitstatus):
    """Clean up worker-specific resources."""
    worker_id = get_worker_id()
    
    # Clean up database
    if worker_id in _worker_databases:
        import asyncio
        loop = asyncio.get_event_loop()
        if not loop.is_closed():
            loop.run_until_complete(_worker_databases[worker_id].cleanup())
        del _worker_databases[worker_id]
    
    # Clean up container
    if worker_id in _worker_containers:
        _worker_containers[worker_id].stop()
        del _worker_containers[worker_id]
```

### Step 2: Update conftest.py to Support Parallel Mode

Add to `tests/conftest.py`:

```python
# Check if we're running in parallel mode
PARALLEL_MODE = os.environ.get('PYTEST_XDIST_WORKER') is not None

if PARALLEL_MODE:
    # Use parallel fixtures
    from fixtures.testing.parallel import (
        postgres_container_parallel as postgres_container,
        _db_settings_parallel as _db_settings,
        _database_instance_parallel as _database_instance,
    )
else:
    # Use regular fixtures
    from fixtures.testing.postgres import (
        postgres_container,
        _db_settings,
        _database_instance,
    )
```

### Step 3: Configure pytest for Parallel Execution

Update `pyproject.toml`:

```toml
[tool.pytest.ini_options]
# ... existing config ...
# Add parallel execution options
addopts = "-m 'not integration' --strict-markers"

# Define test groups for better parallelization
markers = [
    "asyncio: mark test as async",
    "integration: mark test as integration test",
    "slow: mark test as slow",
    "unit: mark test as unit test",
    "parallel_safe: mark test as safe for parallel execution",
]

[tool.pytest.parallel]
# Custom parallel execution settings
groups = [
    # Group tests by module to reduce fixture setup overhead
    "tests/test_admin_*.py",
    "tests/test_oauth_*.py", 
    "tests/test_oidc_*.py",
    "tests/test_users_*.py",
    "tests/test_auth_*.py",
]
```

## Running Tests in Parallel

### Basic Parallel Execution

```bash
# Run with 4 parallel workers
uv run pytest -n 4

# Run with auto-detected CPU count
uv run pytest -n auto

# Run with load balancing (distributes tests dynamically)
uv run pytest -n auto --dist loadscope

# Run specific test group in parallel
uv run pytest tests/test_admin_*.py -n 4
```

### Advanced Parallel Strategies

```bash
# Group by test file (reduces fixture overhead)
uv run pytest -n auto --dist loadfile

# Group by test class
uv run pytest -n auto --dist loadscope

# Distribute each test individually (maximum parallelism)
uv run pytest -n auto --dist load

# Run only parallel-safe tests
uv run pytest -m parallel_safe -n auto
```

## Optimizing for Parallel Execution

### 1. Mark Parallel-Safe Tests

```python
@pytest.mark.parallel_safe
async def test_user_creation(db_connection):
    """This test is safe for parallel execution."""
    # Test implementation
```

### 2. Use Worker-Specific Resources

```python
@pytest.fixture
async def worker_specific_cache():
    """Create a cache instance specific to this worker."""
    worker_id = get_worker_id()
    cache_key_prefix = f"test_cache_{worker_id}_"
    return CacheService(key_prefix=cache_key_prefix)
```

### 3. Avoid Shared State

```python
# Bad: Shared global state
_test_counter = 0

# Good: Worker-specific state
_worker_counters = {}

def get_test_counter():
    worker_id = get_worker_id()
    if worker_id not in _worker_counters:
        _worker_counters[worker_id] = 0
    return _worker_counters[worker_id]
```

## Performance Considerations

### Expected Performance Gains

With proper parallel execution:
- **2 workers**: ~1.8x speedup
- **4 workers**: ~3.5x speedup
- **8 workers**: ~6x speedup (diminishing returns)

### Resource Requirements

Per worker:
- **PostgreSQL container**: ~100MB RAM
- **Connection pool**: 50-100 connections
- **Python process**: ~50-100MB RAM

### Recommended Settings

For a development machine with 8 cores and 16GB RAM:
```bash
# Optimal for most cases
uv run pytest -n 4 --dist loadscope

# For CI/CD with more resources
uv run pytest -n 8 --dist loadfile
```

## Troubleshooting

### Common Issues

1. **Port Conflicts**
   - Each worker needs a unique PostgreSQL port
   - Testcontainers handles this automatically

2. **Connection Pool Exhaustion**
   - Increase pool size for parallel execution
   - Monitor pool statistics

3. **Test Failures in Parallel Only**
   - Usually indicates shared state issues
   - Check for global variables or fixtures

### Debugging Parallel Tests

```bash
# Run with verbose output
uv run pytest -n 4 -v

# Run with worker output
uv run pytest -n 4 --capture=no

# Run specific failing test serially
uv run pytest tests/test_specific.py::test_function
```

## Monitoring Parallel Execution

Add to test output:
```python
@pytest.fixture(autouse=True)
def log_worker_info(request):
    """Log which worker is running each test."""
    worker_id = get_worker_id()
    logger.info(f"Test {request.node.nodeid} running on worker {worker_id}")
```

## Best Practices

1. **Start Small**: Begin with 2 workers and increase gradually
2. **Group Related Tests**: Use `--dist loadscope` to keep related tests together
3. **Monitor Resources**: Watch CPU, memory, and database connections
4. **Profile First**: Identify slow tests before parallelizing
5. **Clean Isolation**: Ensure each test is truly independent

## Example GitHub Actions Configuration

```yaml
name: Parallel Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.11, 3.12]
        
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        pip install uv
        uv sync --all-groups
    
    - name: Run parallel tests
      run: |
        # Use number of CPUs available in GitHub Actions
        uv run pytest -n auto --dist loadscope
```

## Conclusion

Parallel testing can significantly reduce test execution time, but requires careful consideration of:
- Resource isolation
- Database connections
- Shared state
- Test dependencies

Start with the process-based approach and optimize based on your specific needs and constraints.