# External Libraries Integration Guide

This document provides comprehensive guidance for using external libraries developed by the Descoped team that power Authly's database operations and testing infrastructure. These libraries enable the high-quality, production-ready implementation with 171/171 tests passing.

## Overview

Authly leverages two specialized external libraries for robust database operations and comprehensive testing:

- **psycopg-toolkit**: Enhanced PostgreSQL operations with async patterns and transaction management
- **fastapi-testing**: Async-first testing utilities for FastAPI applications with real server lifecycle management

These libraries support Authly's philosophy of **real-world integration testing** over mocking, ensuring production-grade reliability.

## psycopg-toolkit

The `psycopg-toolkit` library provides enterprise-grade PostgreSQL operations with modern async patterns, connection pooling, and sophisticated transaction management.

### Core Components

#### TransactionManager

**Purpose**: Manages database transactions with automatic rollback capabilities and connection pooling.

**Key Features**:
- Automatic transaction rollback on exceptions
- Connection pool management 
- Async context manager support
- Transaction isolation for testing

**Usage Pattern**:
```python
from psycopg_toolkit import TransactionManager

async def database_operation():
    """Standard transaction pattern for database operations."""
    async with transaction_manager.transaction() as conn:
        repository = SomeRepository(conn)
        result = await repository.create(data)
        return result
    # Transaction automatically committed or rolled back
```

**Testing Pattern**:
```python
@pytest.mark.asyncio
async def test_database_operation(transaction_manager: TransactionManager):
    """Each test gets isolated transaction that's automatically rolled back."""
    async with transaction_manager.transaction() as conn:
        repo = UserRepository(conn)
        
        # Create test data
        user = await repo.create(test_user_data)
        
        # Test operations
        result = await repo.get_by_id(user.id)
        assert result.username == test_user_data["username"]
        
        # Transaction rolls back at end of test - no cleanup needed
```

#### BaseRepository

**Purpose**: Abstract base class providing standardized CRUD operations for all database entities.

**Generic Type Support**:
```python
from psycopg_toolkit import BaseRepository
from typing import UUID

class UserRepository(BaseRepository[UserModel, UUID]):
    def __init__(self, db_connection: AsyncConnection):
        super().__init__(
            db_connection=db_connection,
            table_name="users",
            model_class=UserModel,
            primary_key="id"
        )
```

**Built-in Operations**:
- `create(data: Dict[str, Any]) -> ModelType`
- `get_by_id(id: KeyType) -> Optional[ModelType]`
- `update(id: KeyType, data: Dict[str, Any]) -> Optional[ModelType]`
- `delete(id: KeyType) -> bool`
- `list_all() -> List[ModelType]`

**Custom Repository Methods**:
```python
class ClientRepository(BaseRepository[OAuthClient, UUID]):
    async def get_by_client_id(self, client_id: str) -> Optional[OAuthClient]:
        """Custom method for OAuth client lookup."""
        query = PsycopgHelper.build_select_query(
            table_name=self.table_name,
            where_clause={"client_id": client_id}
        )
        
        async with self.db_connection.cursor(row_factory=dict_row) as cur:
            await cur.execute(query, [client_id])
            result = await cur.fetchone()
            
            if result:
                return self.model_class(**result)
            return None
    
    async def get_active_clients(self) -> List[OAuthClient]:
        """Get all active OAuth clients with their scopes."""
        query = SQL("""
            SELECT c.*, array_agg(s.scope_name) as scopes
            FROM clients c
            LEFT JOIN client_scopes cs ON c.id = cs.client_id
            LEFT JOIN scopes s ON cs.scope_id = s.id
            WHERE c.is_active = true
            GROUP BY c.id
            ORDER BY c.created_at DESC
        """)
        
        async with self.db_connection.cursor(row_factory=dict_row) as cur:
            await cur.execute(query)
            results = await cur.fetchall()
            return [self.model_class(**result) for result in results]
```

#### PsycopgHelper Utility Methods

**Critical API Notes**: The PsycopgHelper methods have specific signatures that differ from typical ORM patterns.

##### build_insert_query()

```python
# Correct API signature
PsycopgHelper.build_insert_query(
    table_name: str,
    data: Dict[str, Any],  # Actual data values, not placeholders
    batch_size: int = 1
) -> SQL
```

**Important Limitations**:
- **No `returning` parameter** - must be added manually
- **Use actual data** - not placeholder strings
- **Returns SQL object** - combine with parameter values separately

**Correct Usage**:
```python
from psycopg.sql import SQL
from psycopg_toolkit import PsycopgHelper

async def create_client(client_data: Dict[str, Any]) -> OAuthClient:
    """Create OAuth client with proper insert query building."""
    
    # Build insert query with actual data
    insert_query = PsycopgHelper.build_insert_query("clients", client_data)
    
    # Manually append RETURNING clause
    full_query = insert_query + SQL(" RETURNING *")
    
    async with self.db_connection.cursor(row_factory=dict_row) as cur:
        # Execute with data values
        await cur.execute(full_query, list(client_data.values()))
        result = await cur.fetchone()
        return OAuthClient(**result)
```

**Common Mistake**:
```python
# WRONG - This will not work
insert_query = PsycopgHelper.build_insert_query(
    "clients", 
    {"name": "%s", "type": "%s"},  # Don't use placeholders
    returning="*"  # Parameter doesn't exist
)
```

##### build_update_query()

```python
# Correct API signature
PsycopgHelper.build_update_query(
    table_name: str,
    data: Dict[str, Any],          # Fields to update
    where_clause: Dict[str, Any]   # WHERE conditions
) -> SQL
```

**Usage Pattern**:
```python
async def update_client(client_id: UUID, updates: Dict[str, Any]) -> Optional[OAuthClient]:
    """Update OAuth client with proper query building."""
    
    # Build update query
    update_query = PsycopgHelper.build_update_query(
        table_name="clients",
        data=updates,
        where_clause={"id": client_id}
    )
    
    # Add RETURNING clause manually
    full_query = update_query + SQL(" RETURNING *")
    
    # Combine all parameters: update values + where values
    params = list(updates.values()) + [client_id]
    
    async with self.db_connection.cursor(row_factory=dict_row) as cur:
        await cur.execute(full_query, params)
        result = await cur.fetchone()
        
        if result:
            return OAuthClient(**result)
        return None
```

##### build_select_query()

```python
async def find_clients_by_type(self, client_type: str) -> List[OAuthClient]:
    """Find clients by type using select query builder."""
    
    query = PsycopgHelper.build_select_query(
        table_name="clients",
        where_clause={"client_type": client_type, "is_active": True}
    )
    
    async with self.db_connection.cursor(row_factory=dict_row) as cur:
        await cur.execute(query, [client_type, True])
        results = await cur.fetchall()
        return [OAuthClient(**result) for result in results]
```

### Advanced Patterns

#### PostgreSQL Array Handling

OAuth 2.1 implementation frequently uses PostgreSQL arrays for redirect URIs, scopes, and grant types:

```python
async def handle_postgresql_arrays(data: Dict[str, Any]) -> Dict[str, Any]:
    """Properly handle PostgreSQL array fields."""
    
    # Ensure redirect_uris is a proper list
    if "redirect_uris" in data:
        if isinstance(data["redirect_uris"], str):
            data["redirect_uris"] = [data["redirect_uris"]]
        else:
            data["redirect_uris"] = list(data["redirect_uris"])
    
    # Convert enums to strings for array storage
    if "grant_types" in data:
        data["grant_types"] = [
            gt.value if hasattr(gt, "value") else str(gt)
            for gt in data["grant_types"]
        ]
    
    # Handle scope arrays
    if "scopes" in data:
        if isinstance(data["scopes"], str):
            data["scopes"] = data["scopes"].split()
        data["scopes"] = [str(scope) for scope in data["scopes"]]
    
    return data
```

#### Complex Queries with Joins

```python
async def get_client_with_scopes(self, client_id: str) -> Optional[OAuthClientWithScopes]:
    """Get client with associated scopes using complex join."""
    
    query = SQL("""
        SELECT 
            c.*,
            COALESCE(array_agg(s.scope_name) FILTER (WHERE s.scope_name IS NOT NULL), '{}') as scopes,
            COALESCE(array_agg(s.description) FILTER (WHERE s.description IS NOT NULL), '{}') as scope_descriptions
        FROM clients c
        LEFT JOIN client_scopes cs ON c.id = cs.client_id
        LEFT JOIN scopes s ON cs.scope_id = s.id AND s.is_active = true
        WHERE c.client_id = %s AND c.is_active = true
        GROUP BY c.id
    """)
    
    async with self.db_connection.cursor(row_factory=dict_row) as cur:
        await cur.execute(query, [client_id])
        result = await cur.fetchone()
        
        if result:
            return OAuthClientWithScopes(**result)
        return None
```

#### Error Handling and Logging

```python
from psycopg_toolkit.exceptions import OperationError, RecordNotFoundError
import logging

logger = logging.getLogger(__name__)

async def safe_database_operation(self, data: Dict[str, Any]) -> OAuthClient:
    """Database operation with proper error handling."""
    try:
        result = await self._perform_database_operation(data)
        logger.info(f"Successfully created OAuth client: {result.client_id}")
        return result
        
    except psycopg.IntegrityError as e:
        logger.error(f"Database integrity error: {e}")
        if "duplicate key" in str(e):
            raise OperationError("Client ID already exists") from e
        raise OperationError(f"Database constraint violation: {e}") from e
        
    except psycopg.Error as e:
        logger.error(f"Database operation failed: {e}")
        raise OperationError(f"Database operation failed: {e}") from e
        
    except Exception as e:
        logger.error(f"Unexpected error in database operation: {e}")
        raise OperationError(f"Unexpected database error: {e}") from e
```

## fastapi-testing

The `fastapi-testing` library provides comprehensive testing utilities for FastAPI applications with real server lifecycle management and async-first design.

### Core Components

#### AsyncTestServer

**Purpose**: Creates real FastAPI server instances for integration testing with proper startup/shutdown lifecycle.

**Key Features**:
- Automatic port management
- Real HTTP server (not mocked)
- Proper application lifecycle
- Support for dependency injection
- WebSocket testing capabilities

**Basic Usage**:
```python
from fastapi_testing import create_test_server

@pytest.mark.asyncio
async def test_oauth_endpoint():
    """Test OAuth endpoint with real server."""
    async with create_test_server() as server:
        # Register OAuth router
        server.app.include_router(oauth_router, prefix="/oauth")
        
        # Test authorization endpoint
        response = await server.client.get("/oauth/authorize", params={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "https://test.com/callback",
            "scope": "read write",
            "state": "random-state"
        })
        
        await response.expect_status(200)
        content = await response.text()
        assert "Authorization Request" in content
```

#### AsyncTestClient

**Purpose**: HTTP client for making requests to test server with comprehensive method support.

**Available Methods**:
- `get(url, params=None, headers=None, **kwargs)`
- `post(url, json=None, data=None, headers=None, **kwargs)`
- `put(url, json=None, data=None, headers=None, **kwargs)`
- `delete(url, headers=None, **kwargs)`
- `patch(url, json=None, data=None, headers=None, **kwargs)`
- `websocket(url, **kwargs)`

**Authentication Testing**:
```python
@pytest.mark.asyncio
async def test_protected_endpoint(test_server: AsyncTestServer):
    """Test protected endpoint with OAuth token."""
    
    # Include protected router
    test_server.app.include_router(protected_router, prefix="/api/v1")
    
    # First, get an OAuth token
    token_response = await test_server.client.post("/oauth/token", json={
        "grant_type": "authorization_code",
        "code": "valid-auth-code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code_verifier": "test-verifier"
    })
    
    await token_response.expect_status(200)
    token_data = await token_response.json()
    access_token = token_data["access_token"]
    
    # Use token to access protected resource
    headers = {"Authorization": f"Bearer {access_token}"}
    protected_response = await test_server.client.get("/api/v1/protected", headers=headers)
    
    await protected_response.expect_status(200)
    result = await protected_response.json()
    assert "data" in result
```

#### AsyncTestResponse

**Purpose**: Enhanced response wrapper with assertion helpers and async content access.

**Key Methods**:
```python
# Status assertion
await response.expect_status(200)
await response.expect_status(201)

# Content access
json_data = await response.json()
text_content = await response.text()
raw_bytes = await response.content()

# Direct property access
status_code = response.status_code
headers = response.headers
```

### OAuth 2.1 Testing Patterns

#### Complete Authorization Flow Testing

```python
@pytest.mark.asyncio
async def test_complete_oauth_flow(
    test_server: AsyncTestServer,
    transaction_manager: TransactionManager
):
    """Test complete OAuth 2.1 authorization code flow with PKCE."""
    
    async with transaction_manager.transaction() as conn:
        # Set up test data
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        
        # Create test client and scopes
        test_client = await client_repo.create({
            "client_id": "test-web-app",
            "client_name": "Test Web App",
            "client_type": "confidential",
            "client_secret_hash": bcrypt.hashpw(b"test-secret", bcrypt.gensalt()).decode(),
            "redirect_uris": ["https://test.com/callback"],
            "is_active": True
        })
        
        await scope_repo.create({"scope_name": "read", "description": "Read access", "is_active": True})
        await scope_repo.create({"scope_name": "write", "description": "Write access", "is_active": True})
        
        # Include OAuth router
        test_server.app.include_router(oauth_router, prefix="/oauth")
        
        # Step 1: Authorization request
        auth_params = {
            "response_type": "code",
            "client_id": "test-web-app",
            "redirect_uri": "https://test.com/callback",
            "scope": "read write",
            "state": "random-state-123",
            "code_challenge": "test-challenge",
            "code_challenge_method": "S256"
        }
        
        auth_response = await test_server.client.get("/oauth/authorize", params=auth_params)
        await auth_response.expect_status(200)
        
        # Verify authorization form is shown
        auth_content = await auth_response.text()
        assert "Test Web App is requesting access" in auth_content
        assert "Read access" in auth_content
        assert "Write access" in auth_content
        
        # Step 2: User consent (simulate form submission)
        consent_data = {
            **auth_params,
            "username": "test@example.com",
            "password": "testpassword",
            "approve": "true"
        }
        
        consent_response = await test_server.client.post("/oauth/authorize", data=consent_data)
        await consent_response.expect_status(302)  # Redirect to callback
        
        # Extract authorization code from redirect
        location = consent_response.headers["location"]
        assert location.startswith("https://test.com/callback")
        auth_code = extract_code_from_url(location)
        
        # Step 3: Token exchange
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "client_id": "test-web-app",
            "client_secret": "test-secret",
            "code_verifier": "test-verifier",
            "redirect_uri": "https://test.com/callback"
        }
        
        token_response = await test_server.client.post("/oauth/token", json=token_data)
        await token_response.expect_status(200)
        
        token_result = await token_response.json()
        assert "access_token" in token_result
        assert "refresh_token" in token_result
        assert token_result["token_type"] == "Bearer"
        assert token_result["scope"] == "read write"
        
        # Step 4: Use access token
        headers = {"Authorization": f"Bearer {token_result['access_token']}"}
        api_response = await test_server.client.get("/api/v1/protected", headers=headers)
        await api_response.expect_status(200)
```

#### Error Scenario Testing

```python
@pytest.mark.asyncio
async def test_oauth_error_scenarios(test_server: AsyncTestServer):
    """Test OAuth error scenarios and proper error responses."""
    
    test_server.app.include_router(oauth_router, prefix="/oauth")
    
    # Test invalid client_id
    invalid_client_response = await test_server.client.get("/oauth/authorize", params={
        "response_type": "code",
        "client_id": "invalid-client",
        "redirect_uri": "https://test.com/callback"
    })
    await invalid_client_response.expect_status(400)
    error_data = await invalid_client_response.json()
    assert error_data["error"] == "invalid_client"
    
    # Test PKCE requirement
    no_pkce_response = await test_server.client.get("/oauth/authorize", params={
        "response_type": "code",
        "client_id": "test-client",
        "redirect_uri": "https://test.com/callback"
        # Missing code_challenge
    })
    await no_pkce_response.expect_status(400)
    error_data = await no_pkce_response.json()
    assert error_data["error"] == "invalid_request"
    assert "code_challenge" in error_data["error_description"]
```

#### Token Revocation Testing

```python
@pytest.mark.asyncio
async def test_token_revocation(
    test_server: AsyncTestServer,
    transaction_manager: TransactionManager
):
    """Test RFC 7009 compliant token revocation."""
    
    async with transaction_manager.transaction() as conn:
        # Set up test client
        client_repo = ClientRepository(conn)
        test_client = await client_repo.create(confidential_client_data)
        
        test_server.app.include_router(oauth_router, prefix="/oauth")
        
        # Get access token
        token_response = await test_server.client.post("/oauth/token", json={
            "grant_type": "authorization_code",
            "code": "valid-code",
            "client_id": test_client.client_id,
            "client_secret": "test-secret",
            "code_verifier": "test-verifier"
        })
        
        token_data = await token_response.json()
        access_token = token_data["access_token"]
        
        # Revoke token
        revoke_response = await test_server.client.post("/oauth/revoke", json={
            "token": access_token,
            "token_type_hint": "access_token"
        }, auth=(test_client.client_id, "test-secret"))
        
        # RFC 7009: Always return 200
        await revoke_response.expect_status(200)
        
        # Verify token is invalid
        api_response = await test_server.client.get("/api/protected", 
                                                  headers={"Authorization": f"Bearer {access_token}"})
        await api_response.expect_status(401)
```

### Database Integration Testing

#### Fixture Integration

```python
@pytest.fixture
async def test_server_with_database():
    """Test server with database integration."""
    async with create_test_server() as server:
        # Configure database dependencies
        from authly import Authly
        from authly.config import AuthlyConfig
        
        config = AuthlyConfig.load()
        pool = AsyncConnectionPool(config.database_url)
        authly = await Authly.initialize(pool, config)
        
        # Override dependencies
        server.app.dependency_overrides[get_authly] = lambda: authly
        
        yield server
        
        await pool.close()
```

#### Repository Testing with Real Database

```python
@pytest.mark.asyncio
async def test_repository_integration(
    test_server_with_database: AsyncTestServer,
    transaction_manager: TransactionManager
):
    """Test repository operations through API endpoints."""
    
    async with transaction_manager.transaction() as conn:
        # Direct repository testing
        client_repo = ClientRepository(conn)
        
        # Create test client via repository
        client_data = {
            "client_id": "repo-test-client",
            "client_name": "Repository Test Client",
            "client_type": "public",
            "redirect_uris": ["https://repo.test/callback"],
            "is_active": True
        }
        
        created_client = await client_repo.create(client_data)
        assert created_client.client_id == "repo-test-client"
        
        # Test API endpoint uses same data
        test_server_with_database.app.include_router(oauth_router)
        
        api_response = await test_server_with_database.client.get(
            f"/oauth/clients/{created_client.client_id}"
        )
        await api_response.expect_status(200)
        
        api_data = await api_response.json()
        assert api_data["client_name"] == client_data["client_name"]
        assert api_data["client_type"] == client_data["client_type"]
```

### WebSocket Testing

```python
@pytest.mark.asyncio
async def test_oauth_websocket_authentication(test_server: AsyncTestServer):
    """Test WebSocket authentication with OAuth tokens."""
    
    @test_server.app.websocket("/ws/oauth")
    async def oauth_websocket(websocket: WebSocket):
        # Authenticate WebSocket connection with OAuth token
        token = websocket.query_params.get("access_token")
        if not await validate_oauth_token(token):
            await websocket.close(code=1008)  # Policy violation
            return
            
        await websocket.accept()
        await websocket.send_json({"message": "authenticated", "user_id": "test-user"})
    
    # Get OAuth token first
    token_response = await test_server.client.post("/oauth/token", json=oauth_token_request)
    token_data = await token_response.json()
    access_token = token_data["access_token"]
    
    # Connect WebSocket with token
    ws_response = await test_server.client.websocket(f"/ws/oauth?access_token={access_token}")
    message = await test_server.client.ws.receive_json(ws_response)
    
    assert message["message"] == "authenticated"
    assert message["user_id"] == "test-user"
```

## Testing Philosophy and Best Practices

### Real-World Integration Testing

Both psycopg-toolkit and fastapi-testing support Authly's philosophy of comprehensive real-world integration testing:

**Core Principles**:
1. **Real Database**: Use actual PostgreSQL with testcontainers, not SQLite or mocks
2. **Real HTTP Server**: Use actual FastAPI server instances, not test clients that bypass middleware
3. **Real Connections**: Use actual async database connections with proper pooling
4. **Transaction Isolation**: Each test gets its own database transaction that rolls back
5. **No Critical Mocking**: Avoid mocking authentication, database operations, or HTTP requests

### Test Structure Pattern

```python
@pytest.mark.asyncio
async def test_oauth_feature(
    initialize_authly: Authly,
    transaction_manager: TransactionManager,
    test_server: AsyncTestServer
):
    """Comprehensive test following established patterns."""
    
    async with transaction_manager.transaction() as conn:
        # 1. Set up repositories and services (inside transaction)
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        client_service = ClientService(client_repo, scope_repo)
        
        # 2. Create test data using repositories
        test_client = await client_repo.create(oauth_client_data)
        test_scopes = await scope_repo.create_multiple(scope_data_list)
        
        # 3. Test business logic through services
        association_result = await client_service.associate_scopes(
            test_client.client_id, [scope.scope_name for scope in test_scopes]
        )
        assert association_result is True
        
        # 4. Test API endpoints with real HTTP server
        test_server.app.include_router(oauth_router, prefix="/oauth")
        
        api_response = await test_server.client.get(f"/oauth/clients/{test_client.client_id}")
        await api_response.expect_status(200)
        
        # 5. Verify API response matches database state
        api_data = await api_response.json()
        db_client = await client_repo.get_by_id(test_client.id)
        
        assert api_data["client_name"] == db_client.client_name
        assert len(api_data["scopes"]) == len(test_scopes)
        
        # 6. Test error scenarios
        invalid_response = await test_server.client.get("/oauth/clients/invalid-id")
        await invalid_response.expect_status(404)
        
        # Transaction automatically rolls back - no cleanup needed
```

### Performance and Reliability

#### Connection Pool Management

```python
# Proper connection pool configuration
from psycopg_pool import AsyncConnectionPool

pool = AsyncConnectionPool(
    conninfo=config.database_url,
    min_size=5,      # Minimum connections for responsive startup
    max_size=20,     # Maximum connections for high load
    timeout=30.0,    # Connection timeout in seconds
    max_idle=300,    # Maximum idle time before connection recycling
    max_lifetime=3600  # Maximum connection lifetime
)

# Use with transaction manager
transaction_manager = TransactionManager(pool)
```

#### Test Performance Optimization

```python
# Use class-scoped fixtures for expensive setup
@pytest.fixture(scope="class")
async def initialized_authly():
    """Initialize Authly once per test class."""
    config = AuthlyConfig.load()
    pool = AsyncConnectionPool(config.database_url)
    authly = await Authly.initialize(pool, config)
    yield authly
    await pool.close()

# Use function-scoped transactions for isolation
@pytest.fixture
async def transaction_manager(initialized_authly):
    """Fresh transaction manager per test."""
    return TransactionManager(initialized_authly.pool)
```

### Error Handling and Debugging

#### Comprehensive Error Handling

```python
async def robust_database_operation(repo: BaseRepository, data: Dict[str, Any]):
    """Database operation with comprehensive error handling."""
    try:
        result = await repo.create(data)
        logger.info(f"Successfully created record: {result.id}")
        return result
        
    except psycopg.IntegrityError as e:
        if "duplicate key" in str(e).lower():
            logger.warning(f"Duplicate key violation: {e}")
            raise OperationError("Record already exists") from e
        elif "foreign key" in str(e).lower():
            logger.warning(f"Foreign key violation: {e}")
            raise OperationError("Referenced record does not exist") from e
        else:
            logger.error(f"Integrity constraint violation: {e}")
            raise OperationError(f"Data integrity error: {e}") from e
            
    except psycopg.DataError as e:
        logger.error(f"Data format error: {e}")
        raise OperationError(f"Invalid data format: {e}") from e
        
    except psycopg.OperationalError as e:
        logger.error(f"Database connection error: {e}")
        raise OperationError(f"Database unavailable: {e}") from e
        
    except Exception as e:
        logger.error(f"Unexpected database error: {e}", exc_info=True)
        raise OperationError(f"Unexpected error: {e}") from e
```

#### Test Debugging

```python
@pytest.mark.asyncio
async def test_with_debugging(
    test_server: AsyncTestServer,
    transaction_manager: TransactionManager,
    caplog
):
    """Test with comprehensive debugging support."""
    
    # Enable debug logging
    import logging
    logging.getLogger("authly").setLevel(logging.DEBUG)
    
    async with transaction_manager.transaction() as conn:
        # Debug: Verify database state
        async with conn.cursor() as cur:
            await cur.execute("SELECT COUNT(*) FROM clients")
            client_count = await cur.fetchone()
            print(f"Debug: {client_count[0]} clients in database")
        
        # Test operations with detailed logging
        with caplog.at_level(logging.DEBUG):
            result = await perform_test_operation()
            
        # Debug: Check log messages
        debug_messages = [record.message for record in caplog.records if record.levelno == logging.DEBUG]
        print(f"Debug messages: {debug_messages}")
        
        # Assertions with debug context
        assert result is not None, f"Operation failed. Debug info: {debug_messages}"
```

## Code Quality Guidelines

### Repository Implementation Standards

```python
class StandardRepository(BaseRepository[ModelClass, UUID]):
    """Standard repository following established patterns."""
    
    def __init__(self, db_connection: AsyncConnection):
        super().__init__(
            db_connection=db_connection,
            table_name="table_name",
            model_class=ModelClass,
            primary_key="id"
        )
    
    async def custom_query_method(self, param: str) -> List[ModelClass]:
        """Custom method following established patterns."""
        try:
            query = PsycopgHelper.build_select_query(
                table_name=self.table_name,
                where_clause={"field": param, "is_active": True}
            )
            
            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [param, True])
                results = await cur.fetchall()
                return [self.model_class(**result) for result in results]
                
        except psycopg.Error as e:
            logger.error(f"Database query failed: {e}")
            raise OperationError(f"Query failed: {e}") from e
    
    async def complex_operation(self, data: Dict[str, Any]) -> ModelClass:
        """Complex operation with proper error handling."""
        try:
            # Handle PostgreSQL arrays
            if "array_field" in data:
                data["array_field"] = list(data["array_field"])
            
            # Use helper methods correctly
            insert_query = PsycopgHelper.build_insert_query(self.table_name, data)
            full_query = insert_query + SQL(" RETURNING *")
            
            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(full_query, list(data.values()))
                result = await cur.fetchone()
                
                if result:
                    return self.model_class(**result)
                raise OperationError("Insert failed - no result returned")
                
        except Exception as e:
            logger.error(f"Complex operation failed: {e}")
            raise
```

### Testing Standards

```python
@pytest.mark.asyncio
async def test_following_standards(
    transaction_manager: TransactionManager,
    test_server: AsyncTestServer
):
    """Test following all established standards."""
    
    async with transaction_manager.transaction() as conn:
        # 1. Create repositories inside transaction
        repo = StandardRepository(conn)
        
        # 2. Use proper test data setup
        test_data = {
            "field1": "value1",
            "field2": ["array", "values"],
            "field3": True
        }
        
        # 3. Test repository operations
        created_record = await repo.create(test_data)
        assert created_record.field1 == test_data["field1"]
        
        # 4. Test API integration
        test_server.app.include_router(api_router, prefix="/api/v1")
        
        response = await test_server.client.get(f"/api/v1/records/{created_record.id}")
        await response.expect_status(200)
        
        api_data = await response.json()
        assert api_data["field1"] == test_data["field1"]
        
        # 5. Test error scenarios
        error_response = await test_server.client.get("/api/v1/records/invalid-id")
        await error_response.expect_status(404)
        
        # 6. No cleanup needed - transaction rolls back automatically
```

This integration guide ensures consistent usage of external libraries throughout Authly's codebase, supporting the high-quality implementation that achieved 171/171 tests passing with comprehensive real-world integration testing.