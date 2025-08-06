# External Descoped Libraries

This document contains learnings and usage patterns for external libraries developed by the Descoped team that are used in this project.

**Local Repository References:**
- **psycopg-toolkit**: `../psycopg-toolkit/` (local development repository) - **v0.2.1 with JSONB support**
- **fastapi-testing**: `../fastapi-testing/` (local development repository)

## psycopg-toolkit (v0.2.2)

The `psycopg-toolkit` library provides enhanced PostgreSQL operations with modern async patterns, connection pooling, transaction management, and comprehensive JSONB support with array field preservation and date field conversion.

**Latest Update (v0.2.2)**: Enhanced `date_fields` parameter to handle both DATE and TIMESTAMP types, fully resolving date/timestamp conversion issues for Pydantic models.

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

#### Common Pitfalls

##### 1. Forgetting to Include All Date/Timestamp Fields
```python
# ❌ Incomplete - missing timestamp fields
date_fields={"birthdate"}  # Missing created_at, updated_at, etc.

# ✅ Complete - all date/timestamp fields included
date_fields={"birthdate", "created_at", "updated_at", "last_login"}
```

##### 2. Mixing Array and JSONB List Fields
```python
# ❌ All lists become JSONB
auto_detect_json=True  # redirect_uris becomes JSONB!

# ✅ Preserve PostgreSQL arrays
auto_detect_json=True,
array_fields={"redirect_uris", "grant_types", "scopes"}
```

#### Testing JSONB Features

```python
# Test JSONB field updates
async def test_jsonb_update():
    user = await user_repo.create(UserModel(
        username="test",
        address={"city": "Boston", "state": "MA"}
    ))
    
    # Update nested JSONB
    updated = await user_repo.update(user.id, {
        "address": {**user.address, "postal_code": "02101"}
    })
    assert updated.address["postal_code"] == "02101"

# Test array preservation
async def test_array_fields():
    client = await client_repo.create(OAuthClientModel(
        client_id="test",
        redirect_uris=["http://localhost:3000", "http://localhost:3001"]
    ))
    
    # Arrays stored as PostgreSQL TEXT[]
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT redirect_uris[1] FROM oauth_clients WHERE id = %s",
            [client.id]
        )
        first_uri = await cur.fetchone()
        assert first_uri[0] == "http://localhost:3000"
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

### JSONB Support (v0.2.2)

**See `../psycopg-toolkit/docs/jsonb_support.md` for comprehensive documentation**

**Key Features in v0.2.2**:
- `array_fields` parameter preserves PostgreSQL array types (TEXT[], INTEGER[])
- `date_fields` parameter handles both DATE and TIMESTAMP/TIMESTAMPTZ types
- Full control over JSONB processing with `auto_detect_json`
- Clear field precedence: array_fields > json_fields > auto_detect

#### Overview
psycopg-toolkit v0.2.1 provides comprehensive JSONB support with:
- Automatic JSON field detection from Pydantic type hints
- Array field preservation for PostgreSQL array types (NEW)
- Date field conversion between PostgreSQL and Pydantic (NEW)
- Seamless serialization/deserialization between Python objects and PostgreSQL JSONB
- Multiple configuration approaches for different use cases
- psycopg JSON adapter integration for optimal performance

#### Key Features (v0.2.2)

##### 1. Automatic JSON Field Detection
The toolkit automatically detects these types as JSON fields when `auto_detect_json=True`:
- `Dict[K, V]` - Any dictionary type → JSONB
- `List[T]` - Any list type → JSONB (unless in `array_fields`)
- `Optional[Dict[K, V]]` / `Optional[List[T]]` - Optional JSON types → JSONB
- `Union` types containing dictionaries or lists → JSONB
- Complex nested structures (e.g., `List[Dict[str, Any]]`) → JSONB

**Note**: When `auto_detect_json=False` with psycopg JSON adapters enabled, you may see "Failed to deserialize JSON field" warnings. These are expected and can be safely ignored.

##### 2. Array Field Preservation (NEW in v0.2.1)
Preserve PostgreSQL native array types (TEXT[], INTEGER[]) instead of converting to JSONB:
```python
class ClientRepository(BaseRepository[OAuthClientModel, UUID]):
    def __init__(self, db_connection):
        super().__init__(
            db_connection=db_connection,
            table_name="oauth_clients",
            model_class=OAuthClientModel,
            primary_key="id",
            auto_detect_json=True,  # Detects Dict fields as JSON
            array_fields={"redirect_uris", "grant_types", "response_types"}  # Keep as PostgreSQL arrays
        )
```

**Use Cases for Array Fields**:
- Simple list values that benefit from PostgreSQL array operators
- Fields that need array-specific indexing (GIN, GiST)
- Legacy database schemas using array columns
- Performance-critical queries using array containment operators

##### 3. Date Field Conversion (Enhanced in v0.2.2)
Automatic conversion between PostgreSQL DATE/TIMESTAMP and Pydantic string fields:
```python
class UserRepository(BaseRepository[UserModel, UUID]):
    def __init__(self, db_connection):
        super().__init__(
            db_connection=db_connection,
            table_name="users",
            model_class=UserModel,
            primary_key="id",
            auto_detect_json=True,
            # Include ALL date/timestamp fields
            date_fields={"birthdate", "created_at", "updated_at", "last_login"}
        )
```

**Important**: Include ALL date and timestamp fields in `date_fields`, not just DATE columns:
- DATE columns (e.g., `birthdate`)
- TIMESTAMP columns (e.g., `created_at`, `updated_at`)
- TIMESTAMPTZ columns (timezone-aware timestamps)
- Nullable date/timestamp fields (e.g., `last_login`)

**Conversion Behavior**:
- PostgreSQL DATE → ISO date string ("2024-01-15")
- PostgreSQL TIMESTAMP → ISO datetime string ("2024-01-15T10:30:00")
- PostgreSQL TIMESTAMPTZ → ISO datetime string with timezone
- Python string → PostgreSQL DATE/TIMESTAMP (automatic)
- Handles None/NULL values gracefully

#### Configuration for Authly (v0.2.1)

With the new features, Authly can completely remove manual JSON handling:

```python
# UserRepository - handles JSONB address and date conversion
class UserRepository(BaseRepository[UserModel, UUID]):
    def __init__(self, db_connection: AsyncConnection):
        super().__init__(
            db_connection=db_connection,
            table_name="users",
            model_class=UserModel,
            primary_key="id",
            auto_detect_json=True,  # Detects address as JSONB
            date_fields={"birthdate"}  # Converts date to ISO string
        )
# Remove ALL custom methods - no more manual JSON or date handling!

# ClientRepository - preserves arrays, handles JSONB
class ClientRepository(BaseRepository[OAuthClientModel, UUID]):
    def __init__(self, db_connection: AsyncConnection):
        super().__init__(
            db_connection=db_connection,
            table_name="oauth_clients",
            model_class=OAuthClientModel,
            primary_key="id",
            auto_detect_json=True,  # Detects metadata as JSONB
            array_fields={"redirect_uris", "grant_types", "response_types", "request_uris", "contacts"}
        )
# Remove custom create() method - arrays handled automatically!
```

#### Field Precedence (v0.2.2)
The order of precedence for field handling:
1. `array_fields` (highest priority - overrides JSON detection)
2. `json_fields` (explicit JSON fields)
3. `auto_detect_json` (lowest priority - automatic detection)

**Example**: If a field is both auto-detected as JSON and listed in `array_fields`, it will be treated as a PostgreSQL array, not JSONB.

**Processing Modes**:
- `auto_detect_json=True`: Always uses custom JSON processing
- `auto_detect_json=False` with no `json_fields`: Uses psycopg adapters
- Explicit `json_fields`: Always uses custom processing

#### Configuration Approaches

##### 1. Repository-Level Configuration (Recommended for Authly)
```python
# Fine-grained control per repository
class UserRepository(BaseRepository[UserModel, UUID]):
    def __init__(self, db_connection):
        super().__init__(
            db_connection=db_connection,
            table_name="users",
            model_class=UserModel,
            primary_key="id",
            auto_detect_json=True,  # Enable for this repository
            date_fields={"birthdate"}  # Repository-specific date handling
        )

class ClientRepository(BaseRepository[OAuthClientModel, UUID]):
    def __init__(self, db_connection):
        super().__init__(
            db_connection=db_connection,
            table_name="oauth_clients",
            model_class=OAuthClientModel,
            primary_key="id",
            auto_detect_json=True,
            array_fields={"redirect_uris", "grant_types", "response_types", "contacts"}
        )
```

##### 2. psycopg JSON Adapters (Alternative Approach)
```python
# Enable at database level
settings = DatabaseSettings(
    host="localhost",
    port=5432,
    dbname="mydb",
    user="user",
    password="password",
    enable_json_adapters=True  # Enable psycopg JSON adapters
)

# Let psycopg handle JSON
class UserRepository(BaseRepository[UserProfile, int]):
    def __init__(self, db_connection):
        super().__init__(
            db_connection=db_connection,
            table_name="users",
            model_class=UserProfile,
            primary_key="id",
            auto_detect_json=False  # Let psycopg handle JSON
        )
```

##### 3. Mixed Configuration Example
```python
# Complex repository with all features
class OrderRepository(BaseRepository[Order, UUID]):
    def __init__(self, db_connection):
        super().__init__(
            db_connection=db_connection,
            table_name="orders",
            model_class=Order,
            primary_key="id",
            auto_detect_json=True,  # Auto-detect Dict/List fields
            array_fields={"tags", "categories"},  # Keep as arrays
            date_fields={"created_at", "shipped_at", "delivered_at"},  # Convert dates
            strict_json_processing=True  # Raise errors on JSON issues
        )
```

##### 4. Disable All JSONB Features
When you need full control over JSON/JSONB processing:
```python
class LegacyRepository(BaseRepository[LegacyModel, int]):
    def __init__(self, db_connection):
        super().__init__(
            db_connection=db_connection,
            table_name="legacy_table",
            model_class=LegacyModel,
            primary_key="id",
            json_fields=set(),      # Empty set = no JSON fields
            auto_detect_json=False  # No auto-detection
        )
        # Handle JSON manually in custom methods if needed
```

#### JSONB Query Operators
PostgreSQL JSONB operators for queries:
- `->` - Get JSON object field (returns JSON)
- `->>` - Get JSON object field as text
- `#>` - Get JSON object at path (returns JSON)
- `#>>` - Get JSON object at path as text
- `?` - Does JSON contain key?
- `?|` - Does JSON contain any of these keys?
- `?&` - Does JSON contain all of these keys?
- `@>` - Does JSON contain sub-JSON?
- `<@` - Is JSON contained within?
- `||` - Concatenate JSON objects
- `jsonb_set()` - Update specific paths
- `jsonb_array_length()` - Get array length
- `jsonb_array_elements()` - Expand JSON array
- `jsonb_path_query()` - SQL/JSON path queries (PostgreSQL 12+)

Example queries:
```python
# Find users by address city
await cur.execute("""
    SELECT username FROM users
    WHERE address->>'city' = 'Boston'
""")

# Update nested JSON data
await cur.execute("""
    UPDATE users 
    SET address = jsonb_set(
        address,
        '{street}',
        %s::jsonb
    )
    WHERE id = %s
""", ['"123 New Street"', user_id])
```

#### Error Handling
JSON-specific exceptions:
- `JSONProcessingError` - Base JSON error
- `JSONSerializationError` - Serialization failures
- `JSONDeserializationError` - Deserialization failures

```python
from psycopg_toolkit import JSONSerializationError, JSONDeserializationError

try:
    user = await repo.create(user_data)
except JSONSerializationError as e:
    print(f"Failed to serialize field {e.field_name}: {e}")
except JSONDeserializationError as e:
    print(f"Failed to deserialize field {e.field_name}: {e}")
```

#### Migration Path for Authly (v0.2.2)

1. **UserRepository Migration**:
   ```python
   # Before: Manual JSON handling
   if "address" in data and isinstance(data["address"], dict):
       data["address"] = json.dumps(data["address"])
   
   # After: Automatic with v0.2.2
   super().__init__(
       auto_detect_json=True,
       date_fields={"birthdate", "created_at", "updated_at", "last_login"}
   )
   ```

2. **ClientRepository Migration**:
   ```python
   # Before: Manual array handling
   if "redirect_uris" in data:
       data["redirect_uris"] = list(data["redirect_uris"])
   
   # After: Automatic with v0.2.1
   super().__init__(
       auto_detect_json=True,
       array_fields={"redirect_uris", "grant_types", "response_types", "contacts"}
   )
   ```

3. **Benefits Achieved**:
   - ✅ ~150 lines of manual code removed
   - ✅ Automatic JSONB serialization/deserialization
   - ✅ Complete date/timestamp field handling (v0.2.2)
   - ✅ PostgreSQL array preservation
   - ✅ Better performance with psycopg optimizations
   - ✅ Cleaner, more maintainable architecture

#### Performance Optimization
For best performance with JSONB:
```sql
-- Create GIN indexes for JSONB columns
CREATE INDEX idx_users_address ON users USING GIN (address);

-- Create functional indexes for specific queries
CREATE INDEX idx_users_city ON users USING BTREE ((address->>'city'));

-- For array columns, use GIN with array operators
CREATE INDEX idx_clients_uris ON oauth_clients USING GIN (redirect_uris);
```

#### Common Patterns and Best Practices

##### Pattern 1: OIDC User Profile with Address
```python
class UserModel(BaseModel):
    # Standard fields
    username: str
    email: str
    
    # JSONB field for OIDC address claim
    address: Dict[str, Any] | None = None  # {formatted, street_address, locality, ...}
    
    # Date field needing conversion
    birthdate: str | None = None  # ISO date string

# Repository automatically handles both
UserRepository(..., auto_detect_json=True, date_fields={"birthdate"})
```

##### Pattern 2: OAuth Client with Arrays
```python
class OAuthClientModel(BaseModel):
    # PostgreSQL arrays (not JSONB)
    redirect_uris: List[str]  # TEXT[]
    grant_types: List[str]    # TEXT[]
    
    # JSONB field
    metadata: Dict[str, Any] | None = None

# Repository preserves arrays, detects JSONB
ClientRepository(..., auto_detect_json=True, array_fields={"redirect_uris", "grant_types"})
```

##### Pattern 3: Complex Nested Structures
```python
class OrderModel(BaseModel):
    # Complex JSONB with nested objects
    items: List[Dict[str, Any]]  # [{product_id, quantity, price, ...}]
    shipping_address: Dict[str, Any]  # {street, city, state, ...}
    
    # Simple PostgreSQL array
    tags: List[str]  # TEXT[]

# Mixed configuration
OrderRepository(..., auto_detect_json=True, array_fields={"tags"})
```

#### Key Examples
- **Array & Date Fields**: `../psycopg-toolkit/examples/array_and_date_fields.py` - v0.2.2 features
- **Simple Usage**: `../psycopg-toolkit/examples/jsonb_usage_simple.py` - Basic JSONB operations
- **Complex Operations**: `../psycopg-toolkit/examples/complex_json_operations.py` - Advanced patterns
- **Full Documentation**: `../psycopg-toolkit/docs/jsonb_support.md` - Complete reference

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