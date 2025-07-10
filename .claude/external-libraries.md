# External Descoped Libraries

This document contains learnings and usage patterns for external libraries developed by the Descoped team that are used in this project.

**Local Repository References:**
- **psycopg-toolkit**: `../psycopg-toolkit/` (local development repository)
- **fastapi-testing**: `../fastapi-testing/` (local development repository)

## psycopg-toolkit

The `psycopg-toolkit` library provides enhanced PostgreSQL operations with modern async patterns, connection pooling, and transaction management.

### Key Components

#### Database
- **Purpose**: PostgreSQL database manager with connection pooling and lifecycle management
- **Features**: Connection retry logic, health checks, initialization callbacks, transaction management
- **Usage**: Central database management class that provides connection pools and transaction managers

```python
from psycopg_toolkit import Database, DatabaseSettings

# Create database settings
settings = DatabaseSettings(
    host="localhost",
    port=5432,
    dbname="authly",
    user="authly",
    password="password"
)

# Initialize database
database = Database(settings)
await database.create_pool()
await database.init_db()

# Get connection pool
pool = await database.get_pool()

# Get transaction manager
transaction_manager = await database.get_transaction_manager()
```

**Key Methods:**
- `create_pool()`: Initialize connection pool with retry logic
- `init_db()`: Run initialization callbacks and health checks
- `get_pool()`: Access underlying AsyncConnectionPool
- `get_transaction_manager()`: Get TransactionManager instance (lazy initialization)
- `close()`: Clean shutdown of pool and resources

#### TransactionManager
- **Purpose**: Comprehensive transaction management with savepoints, schema, and test data support
- **Usage**: Always use within `async with` context managers
- **Pattern**: Each test should use its own transaction for isolation

```python
# Basic transaction
async with transaction_manager.transaction() as conn:
    repo = SomeRepository(conn)
    result = await repo.create(data)

# With savepoint
async with transaction_manager.transaction(savepoint="user_creation") as conn:
    # Operations can rollback to savepoint
    pass

# With schema and test data management
async with transaction_manager.managed_transaction(
    schema_manager=UserSchemaManager(),
    data_manager=TestUserData()
) as conn:
    # Schema created, test data inserted, transaction active
    pass
```

**Advanced Features:**
- **Savepoint Support**: `transaction(savepoint="name")` for nested rollback points
- **Schema Management**: `with_schema(schema_manager)` for automatic schema setup/cleanup
- **Test Data Management**: `with_test_data(data_manager)` for automatic test data lifecycle
- **Combined Operations**: `managed_transaction()` orchestrates schema, data, and transaction

#### BaseRepository
- **Purpose**: Abstract base class for database repositories with CRUD operations
- **Inheritance**: All repositories should extend `BaseRepository[ModelType, KeyType]`
- **Features**: Built-in create, read, update, delete operations with proper error handling

#### PsycopgHelper Utility Methods

##### build_insert_query()
```python
# Correct API signature
PsycopgHelper.build_insert_query(
    table_name: str,
    data: Dict[str, Any],  # Use actual data, not placeholders
    batch_size: int = 1
) -> SQL
```

**Key Points**:
- Does NOT have a `returning` parameter
- Use actual data dictionary, not placeholder strings
- To get inserted records back, manually append RETURNING clause:

```python
from psycopg.sql import SQL

insert_query = PsycopgHelper.build_insert_query("table_name", data)
await cur.execute(insert_query + SQL(" RETURNING *"), list(data.values()))
```

##### build_update_query()
```python
# Correct API signature  
PsycopgHelper.build_update_query(
    table_name: str,
    data: Dict[str, Any],
    where_clause: Dict[str, Any]
) -> SQL
```

**Key Points**:
- Does NOT have a `returning` parameter
- Same pattern as insert - manually append RETURNING clause for updated records
- Use actual data and where clause values, not placeholders

##### build_select_query()
```python
# Used for WHERE clause queries
query = PsycopgHelper.build_select_query(
    table_name="table_name", 
    where_clause={"column": value}
)
```

### Common Patterns

#### Repository Implementation
```python
class MyRepository(BaseRepository[MyModel, UUID]):
    def __init__(self, db_connection: AsyncConnection):
        super().__init__(
            db_connection=db_connection,
            table_name="my_table",
            model_class=MyModel,
            primary_key="id"
        )
    
    async def custom_method(self) -> List[MyModel]:
        query = PsycopgHelper.build_select_query(
            table_name=self.table_name,
            where_clause={"is_active": True}
        )
        async with self.db_connection.cursor(row_factory=dict_row) as cur:
            await cur.execute(query, [True])
            results = await cur.fetchall()
            return [MyModel(**result) for result in results]
```

#### Database Array Handling
PostgreSQL arrays require special handling:

```python
# For PostgreSQL array fields
if "redirect_uris" in data:
    data["redirect_uris"] = list(data["redirect_uris"])  # Ensure it's a list
if "grant_types" in data:
    data["grant_types"] = [
        gt.value if hasattr(gt, "value") else str(gt) 
        for gt in data["grant_types"]
    ]  # Convert enums to strings
```

#### Error Handling
- Always catch and re-raise as `OperationError` or `RecordNotFoundError`
- Use descriptive error messages
- Log errors before re-raising

## fastapi-testing

The `fastapi-testing` library provides async-first testing utilities for FastAPI applications with real server lifecycle management and comprehensive HTTP/WebSocket testing support.

### Key Components

#### Config
- **Purpose**: Global configuration for testing framework behavior
- **Features**: WebSocket settings, HTTP connection limits, port management, retry configuration
- **Usage**: Customize testing environment behavior

```python
from fastapi_testing import Config, global_config

# Custom configuration
config = Config(
    ws_max_message_size=2**21,        # 2MB WebSocket messages
    http_max_connections=200,         # HTTP connection pool size
    port_range_start=8001,            # Port allocation range
    port_range_end=9000,
    ws_retry_attempts=3,              # WebSocket retry logic
    ws_retry_delay=1.0
)

# Environment-based configuration
config = Config.from_env(prefix="FASTAPI_TESTING_")
```

#### AsyncTestServer
- **Purpose**: Real FastAPI server instance for integration testing  
- **Features**: Automatic port management, proper startup/shutdown lifecycle, real Uvicorn server
- **Usage**: Use within `async with` context managers or direct instantiation

```python
from fastapi_testing import AsyncTestServer

# Context manager usage
async with AsyncTestServer() as server:
    @server.app.get("/test")
    async def test_endpoint():
        return {"message": "success"}
    
    response = await server.client.get("/test")
    await response.expect_status(200)

# Direct usage
server = AsyncTestServer()
await server.start()
try:
    # Test operations
    pass
finally:
    await server.stop()
```

#### AsyncTestClient
- **Purpose**: HTTP client for making requests to test server
- **Features**: Full HTTP method support, JSON handling, WebSocket support
- **Methods**: `get()`, `post()`, `put()`, `delete()`, `patch()`, `websocket()`

#### AsyncTestResponse
- **Purpose**: Enhanced response wrapper with assertion helpers
- **Methods**: 
  - `await response.json()` - Parse JSON response
  - `await response.text()` - Get text response
  - `await response.expect_status(code)` - Assert status code
  - `response.status_code` - Get status code

### Testing Patterns

#### Router Integration Testing
```python
async def test_endpoint(test_server: AsyncTestServer):
    # Register router with prefix
    test_server.app.include_router(my_router, prefix="/api/v1")
    
    # Make request
    response = await test_server.client.post("/api/v1/endpoint", json=data)
    
    # Assert response
    await response.expect_status(201)
    result = await response.json()
    assert result["field"] == expected_value
```

#### Authentication Testing
```python
async def test_protected_endpoint(test_server: AsyncTestServer, test_user_token: str):
    test_server.app.include_router(protected_router, prefix="/api/v1")
    
    headers = {"Authorization": f"Bearer {test_user_token}"}
    response = await test_server.client.get("/api/v1/protected", headers=headers)
    await response.expect_status(200)
```

#### Database Integration Testing
```python
async def test_with_database(test_server: AsyncTestServer, transaction_manager: TransactionManager):
    async with transaction_manager.transaction() as conn:
        # Set up test data in database
        repo = MyRepository(conn)
        test_data = await repo.create(sample_data)
        
        # Test the API
        test_server.app.include_router(api_router)
        response = await test_server.client.get(f"/api/items/{test_data.id}")
        await response.expect_status(200)
        
        # Verify response matches database
        result = await response.json()
        assert result["id"] == str(test_data.id)
```

### Configuration and WebSocket Support

#### Config Class
```python
from fastapi_testing import Config

# Custom configuration
config = Config(
    ws_max_message_size=2**21,
    http_max_connections=200,
    port_range_start=8001,
    port_range_end=9000
)
```

#### WebSocket Testing
```python
async def test_websocket(test_server: AsyncTestServer):
    @test_server.app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_json({"message": "hello"})
    
    ws_response = await test_server.client.websocket("/ws")
    message = await test_server.client.ws.receive_json(ws_response)
    assert message["message"] == "hello"
```

## Testing Philosophy

### Real-World Integration Testing
Both libraries support the project's philosophy of **real-world integration testing** over mocking:

1. **Real Database**: Use actual PostgreSQL with testcontainers
2. **Real HTTP Server**: Use actual FastAPI server instances
3. **Real Connections**: Use actual async database connections
4. **Transaction Isolation**: Each test gets its own database transaction
5. **No Mocking**: Avoid monkey patching or mocking critical components

### Test Structure Pattern
```python
@pytest.mark.asyncio
async def test_feature(initialize_authly: Authly, transaction_manager: TransactionManager):
    """Test description"""
    async with transaction_manager.transaction() as conn:
        # 1. Set up repositories/services
        repo = FeatureRepository(conn)
        service = FeatureService(repo)
        
        # 2. Create test data
        test_data = await repo.create(sample_data)
        
        # 3. Execute business logic
        result = await service.perform_operation(test_data.id)
        
        # 4. Assert results
        assert result.status == "success"
        
        # 5. Verify database state
        updated_data = await repo.get_by_id(test_data.id)
        assert updated_data.field == expected_value
```

## Best Practices

### Database Operations
1. Always use `async with transaction_manager.transaction()` for test isolation
2. Create repositories inside transaction context, not as fixtures
3. Use proper error handling with `OperationError` and `RecordNotFoundError`
4. Handle PostgreSQL arrays correctly when dealing with list fields
5. Use `dict_row` factory for easier result processing

### API Testing
1. Register routers with proper prefixes in each test
2. Use `await response.expect_status()` for clear assertions
3. Test both success and error scenarios
4. Include authentication headers when testing protected endpoints
5. Use real user fixtures instead of mocking authentication

### Code Quality
1. Import `SQL` from `psycopg.sql` when building custom queries
2. Don't use placeholder strings with PsycopgHelper methods
3. Always append RETURNING clauses manually when needed
4. Use proper type hints for repository generic types
5. Follow the established patterns from existing tests

This approach ensures robust, maintainable tests that catch real integration issues and provide confidence in production deployments.