# Technical Plan: Replacing Authly Singleton with Dependency Injection

## 1. Problem Statement

The current `Authly` class is implemented as a singleton, managing global state such as the PostgreSQL database connection pool and core configuration. While this simplifies access in a single-process environment, it introduces critical limitations for horizontal scaling and distributed deployments:

*   **Resource Duplication**: When deployed with multiple Uvicorn worker processes (e.g., via Gunicorn), each worker process initializes its own independent `Authly` singleton instance. This leads to each worker creating its own separate database connection pool, resulting in `(number of workers) x (configured pool size)` database connections. This can quickly exhaust database connection limits and lead to inefficient resource utilization.
*   **Inconsistent State**: For any in-memory components managed directly by the singleton (e.g., a non-distributed rate limiter or cache), their state is isolated to each worker process, leading to inconsistent behavior across the application.
*   **Single Point of Failure (Conceptual)**: While not a literal single point of failure in terms of process crash, the architectural pattern itself limits the ability to distribute load and achieve high availability through simple horizontal scaling.

## 2. Goal

To refactor the `Authly` class and its associated resource management to leverage FastAPI's Dependency Injection (DI) system and `lifespan` events. This will ensure that shared, expensive resources (like the database connection pool) are initialized once per application instance (before worker processes are forked) and are then shared efficiently across all worker processes, enabling true horizontal scalability.

## 3. Proposed Solution Overview

The solution involves:
1.  Transforming `Authly` from a singleton into a regular class whose instances are managed by the application's lifecycle.
2.  Utilizing FastAPI's `lifespan` context manager to initialize and clean up shared resources (e.g., database pool, configuration) once, before worker processes are spawned.
3.  Storing these initialized resources on the FastAPI `app.state` object.
4.  Creating FastAPI `Depends` functions to inject these shared resources into API endpoints and other service layers.

## 4. Detailed Implementation Plan

### Step 1: Identify All Shared Resources

Review the `Authly` singleton's current responsibilities and identify all resources that need to be initialized once and shared across all worker processes.
*   **Primary**: PostgreSQL database connection pool (`psycopg-pool`).
*   **Secondary**: Configuration objects, potentially other managers or clients that are currently instantiated within the singleton.

### Step 2: Refactor Resource Initialization and Cleanup

Create dedicated functions or classes responsible for initializing and cleaning up each shared resource. These will be designed to be used within the `lifespan` context.

**Example: Database Pool Management**

```python
# src/authly/core/database.py (New or modified file)

from contextlib import asynccontextmanager
from psycopg_pool import AsyncConnectionPool
from authly.config import AuthlyConfig # Assuming config is now passed in

@asynccontextmanager
async def get_db_pool(config: AuthlyConfig):
    """Provides an asynchronous database connection pool."""
    pool = None
    try:
        # Use config to get DB connection details
        pool = AsyncConnectionPool(
            conninfo=config.database_url,
            min_size=config.db_pool_min_size,
            max_size=config.db_pool_max_size,
            open=False # Don't open immediately, lifespan will handle
        )
        await pool.open()
        yield pool
    finally:
        if pool:
            await pool.close()

# Similar functions for other shared resources (e.g., config, external clients)
```

### Step 3: Transform `Authly` from Singleton to Regular Class

Modify the `Authly` class to remove its singleton pattern (e.g., `_instance`, `__new__`, `get_instance` methods). Its constructor should now accept the necessary shared resources as arguments.

```python
# src/authly/core/authly.py (Modified file)

# Remove singleton boilerplate (e.g., _instance, __new__, get_instance)

class Authly:
    def __init__(self, db_pool: AsyncConnectionPool, config: AuthlyConfig, ...):
        self.db_pool = db_pool
        self.config = config
        # Initialize other managers/services that depend on these shared resources
        # e.g., self.user_service = UserService(db_pool, config)
        # self.token_manager = TokenManager(db_pool, config)
        # ...

    # Keep existing methods that operate on these resources
    # e.g., async def get_user_repository(self) -> UserRepository: ...
```

### Step 4: Integrate with FastAPI `lifespan`

Modify the main FastAPI application file (e.g., `src/authly/main.py` or `src/authly/app.py`) to use the `lifespan` context manager. This is where shared resources will be initialized and stored on `app.state`.

```python
# src/authly/main.py (Modified file)

from fastapi import FastAPI
from contextlib import asynccontextmanager
from authly.core.database import get_db_pool
from authly.core.authly import Authly
from authly.config import AuthlyConfig # Assuming config loading is separate

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Load Configuration (if not already loaded globally)
    config = AuthlyConfig.load_from_env() # Example: load config from env
    app.state.config = config

    # 2. Initialize Database Pool
    async with get_db_pool(config) as db_pool:
        app.state.db_pool = db_pool

        # 3. Initialize Authly instance with shared resources
        app.state.authly_instance = Authly(db_pool=db_pool, config=config)
        # Initialize other top-level services that depend on Authly or shared resources
        # e.g., app.state.oauth_service = OAuthService(app.state.authly_instance)

        yield # Application is ready to receive requests

    # Cleanup happens after 'yield' when the application shuts down
    # (e.g., db_pool.close() is handled by get_db_pool context manager)

app = FastAPI(lifespan=lifespan, ...)

# Include API routers here
# app.include_router(auth_router)
# app.include_router(user_router)
# ...
```

### Step 5: Update FastAPI Dependencies

Modify existing FastAPI `Depends` functions and create new ones to retrieve the shared resources (or the `Authly` instance) from `app.state`.

```python
# src/authly/dependencies.py (Modified or new file)

from fastapi import Request
from authly.core.authly import Authly
from psycopg_pool import AsyncConnectionPool
from authly.config import AuthlyConfig

def get_authly_instance(request: Request) -> Authly:
    """Dependency to get the shared Authly instance."""
    return request.app.state.authly_instance

def get_db_pool_dependency(request: Request) -> AsyncConnectionPool:
    """Dependency to get the shared database connection pool."""
    return request.app.state.db_pool

def get_config_dependency(request: Request) -> AuthlyConfig:
    """Dependency to get the shared configuration."""
    return request.app.state.config

# Example usage in an API router:
# @router.get("/users/me")
# async def read_current_user(authly: Authly = Depends(get_authly_instance)):
#     user = await authly.user_service.get_current_user(...)
#     return user
```

### Step 6: Adapt Testing Strategy

Update `pytest` fixtures to initialize resources and the `Authly` instance in a way that mimics the `lifespan` behavior, ensuring proper cleanup for each test. Test containers for PostgreSQL should still be used.

```python
# tests/conftest.py (Modified file)

import pytest
from httpx import AsyncClient
from authly.main import app as fastapi_app # Import your main FastAPI app
from authly.core.database import get_db_pool
from authly.core.authly import Authly
from authly.config import AuthlyConfig

@pytest.fixture(scope="session")
async def test_db_pool(test_config: AuthlyConfig): # Assuming test_config fixture exists
    """Session-scoped database pool for tests."""
    async with get_db_pool(test_config) as pool:
        yield pool

@pytest.fixture(scope="session")
async def test_authly_instance(test_db_pool: AsyncConnectionPool, test_config: AuthlyConfig):
    """Session-scoped Authly instance for tests."""
    return Authly(db_pool=test_db_pool, config=test_config)

@pytest.fixture(scope="session")
async def client(test_authly_instance: Authly, test_db_pool: AsyncConnectionPool, test_config: AuthlyConfig):
    """Async HTTP client for testing FastAPI endpoints."""
    # Manually set app.state for testing
    fastapi_app.state.authly_instance = test_authly_instance
    fastapi_app.state.db_pool = test_db_pool
    fastapi_app.state.config = test_config

    async with AsyncClient(app=fastapi_app, base_url="http://test") as ac:
        yield ac

# Ensure individual tests clean up their data using transactions or similar
# (Existing psycopg-toolkit transaction fixtures should still be applicable)
```

### Step 7: Deployment Considerations

*   **ASGI Server Compatibility**: Ensure the ASGI server (e.g., Uvicorn, Gunicorn with Uvicorn worker) is configured to correctly handle FastAPI's `lifespan` events. Modern versions do this automatically.
*   **Gunicorn Configuration**: When using Gunicorn, the `lifespan` events are executed in the main Gunicorn process *before* worker processes are forked. This is precisely what enables shared resources.

## 5. Expected Outcomes

*   **True Horizontal Scalability**: The application will be able to scale horizontally by adding more Uvicorn worker processes or more Docker containers, with all workers sharing a single, efficiently managed database connection pool.
*   **Consistent State**: Any shared resources will maintain consistent state across all worker processes.
*   **Improved Resource Utilization**: Reduced overall database connections and more efficient use of system resources.
*   **Cleaner Architecture**: Decoupling resource management from the core `Authly` logic, leading to a more maintainable and testable codebase.
*   **Adherence to Best Practices**: Aligning with modern Python and FastAPI application design patterns for production-ready services.
