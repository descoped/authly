# Authly Service Architecture Patterns

## Overview

This document describes the service architecture patterns used in the Authly authentication service. These patterns ensure consistency, testability, and maintainability across the codebase.

## Architecture Layers

```
┌─────────────────────────────────────────────────────┐
│                   API Layer (Routers)                │
│  - FastAPI routers handle HTTP requests             │
│  - Dependency injection for services                │
│  - Request/response validation                      │
└─────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│                  Service Layer                       │
│  - Business logic and orchestration                 │
│  - Transaction management                           │
│  - Cross-repository operations                      │
└─────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│                 Repository Layer                     │
│  - Data access and persistence                      │
│  - SQL query construction                           │
│  - Database transaction handling                    │
└─────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│                    Database                          │
│  - PostgreSQL with async support                    │
│  - Connection pooling via psycopg                   │
└─────────────────────────────────────────────────────┘
```

## Repository Pattern

### Standard Repositories (using BaseRepository)

Most repositories inherit from `psycopg-toolkit`'s `BaseRepository` class, which provides standard CRUD operations:

```python
from psycopg_toolkit import BaseRepository

class UserRepository(BaseRepository[UserModel]):
    """Standard repository using BaseRepository for CRUD operations."""
    
    table_name = "users"
    model_class = UserModel
    
    # Custom methods extend base CRUD operations
    async def find_by_username(self, username: str) -> UserModel | None:
        return await self.get_first({"username": username})
```

**Standard Repositories:**
- `UserRepository` - User CRUD operations
- `ClientRepository` - OAuth client management
- `ScopeRepository` - OAuth scope management
- `TokenRepository` - Token persistence
- `AuthorizationCodeRepository` - Authorization code management

### Special Case Repositories

Some repositories **DO NOT** inherit from `BaseRepository` because they handle specialized operations beyond standard CRUD:

```python
class JWKSRepository:
    """
    SPECIAL CASE: This repository does NOT inherit from BaseRepository because:
    - It manages cryptographic keys, not standard CRUD entities
    - Requires specialized operations like key rotation and cryptographic validation
    - Handles complex key lifecycle management
    """
    
    def __init__(self, conn: AsyncConnection):
        self._conn = conn
```

**Special Case Repositories:**
- `JWKSRepository` - Cryptographic key management, key rotation
- `SessionRepository` - Session state management, complex queries

## Service Layer Pattern

### Service Responsibilities

Services encapsulate business logic and orchestrate operations across repositories:

```python
class ClientService:
    """
    Service layer for OAuth 2.1 client management business logic.
    
    Responsibilities:
    - Business rule validation
    - Cross-repository operations
    - Secret generation and hashing
    - Scope assignment and validation
    """
    
    def __init__(self, client_repo: ClientRepository, scope_repo: ScopeRepository, config: AuthlyConfig):
        self._client_repo = client_repo  # Note: private attributes with underscore
        self._scope_repo = scope_repo
        self._config = config
    
    async def create_client(self, request: OAuthClientCreateRequest) -> OAuthClientCredentialsResponse:
        # Business logic: validate, generate secrets, assign scopes
        # Orchestrate across multiple repositories
        pass
```

### Service Attribute Naming Convention

**IMPORTANT**: Services use private attributes (with underscore prefix) for repositories:

- `ClientService`: `_client_repo`, `_scope_repo`
- `UserService`: `_repo`
- `ScopeService`: `_scope_repo`
- `TokenService`: `_repo`

This convention prevents accidental direct repository access from routers.

## Dependency Injection Pattern

### Service Dependencies

All services are created through FastAPI's dependency injection system:

```python
# In admin_dependencies.py
async def get_admin_client_service(
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
) -> ClientService:
    """
    Get ClientService instance for admin operations.
    
    Creates ClientService with required repositories and configuration,
    following the established service pattern.
    """
    client_repo = ClientRepository(conn)
    scope_repo = ScopeRepository(conn)
    return ClientService(client_repo, scope_repo, config)

# In router
@router.post("/clients")
async def create_client(
    request: OAuthClientCreateRequest,
    client_service: ClientService = Depends(get_admin_client_service),  # Injected
    _admin: UserModel = Depends(require_admin_client_write),
) -> OAuthClientCredentialsResponse:
    return await client_service.create_client(request)
```

### Dependency Files Organization

- `core/dependencies.py` - Core dependencies (database, config, resource manager)
- `api/admin_dependencies.py` - Admin-specific services and auth
- `api/oauth_dependencies.py` - OAuth flow dependencies
- `api/users_dependencies.py` - User management dependencies

## Transaction Management

### Transaction Isolation in Tests

**CRITICAL**: Never keep an open database transaction while making HTTP test server calls:

```python
# ❌ BROKEN - Transaction not visible to HTTP server
async def test_something(test_server, transaction_manager):
    async with transaction_manager.transaction() as conn:
        user = await create_user(conn)  
        response = await test_server.client.get(f"/users/{user.id}")
        # FAILS: User not found - data not committed!

# ✅ CORRECT - Use committed fixtures
async def test_something(test_server, committed_user):
    # committed_user is already committed to database
    response = await test_server.client.get(f"/users/{committed_user.id}")
    # SUCCESS: User is visible to HTTP server
```

### Service Transaction Patterns

Services should handle transactions internally when needed:

```python
class UserService:
    async def cascade_delete_user(self, user_id: UUID) -> dict:
        """Delete user with all related data in a transaction."""
        async with self._repo._conn.transaction():
            # All operations in same transaction
            tokens_deleted = await self._delete_user_tokens(user_id)
            codes_deleted = await self._delete_auth_codes(user_id)
            user_deleted = await self._repo.delete(user_id)
            # Commit happens automatically on context exit
        return {
            "tokens": tokens_deleted,
            "codes": codes_deleted,
            "user": user_deleted
        }
```

## Error Handling Pattern

### Repository Layer
- Raise `RecordNotFoundError` for missing records
- Let database errors bubble up
- No business logic validation

### Service Layer
- Validate business rules
- Raise `HTTPException` with appropriate status codes
- Log operations for audit trail
- Handle cross-cutting concerns (metrics, caching)

### Router Layer
- Minimal logic - just request/response handling
- Rely on FastAPI's automatic validation
- Let service exceptions bubble up to error handlers

## Testing Patterns

### Repository Testing
- Test against real database (not mocks)
- Use transactional fixtures for isolation
- Test both success and error cases
- Verify SQL generation and parameters

### Service Testing
- Test business logic with mock repositories
- Verify orchestration between repositories
- Test error conditions and edge cases
- Ensure proper transaction handling

### Integration Testing
- Use committed fixtures for HTTP tests
- Test full request/response cycle
- Verify authentication and authorization
- Test cross-service interactions

## Best Practices

### DO:
- ✅ Use dependency injection for all services
- ✅ Keep repositories focused on data access
- ✅ Put business logic in services
- ✅ Use private attributes in services (`_repo`)
- ✅ Document special case repositories
- ✅ Use committed fixtures for HTTP tests
- ✅ Handle transactions at service level

### DON'T:
- ❌ Create repositories/services inline in routers
- ❌ Put business logic in repositories
- ❌ Access repositories directly from routers
- ❌ Mix transaction scopes with HTTP calls
- ❌ Use mocks for database testing
- ❌ Ignore error handling patterns

## Migration Guide

### Converting Inline Creation to DI

Before:
```python
@router.get("/clients")
async def list_clients(conn: AsyncConnection = Depends(get_database_connection)):
    client_repo = ClientRepository(conn)  # ❌ Inline creation
    return await client_repo.get_all()
```

After:
```python
@router.get("/clients")
async def list_clients(client_service: ClientService = Depends(get_client_service)):
    return await client_service.list_clients()  # ✅ Dependency injection
```

### Adding New Services

1. Create service class in appropriate module:
```python
# In authly/new_feature/service.py
class NewFeatureService:
    def __init__(self, repo: NewFeatureRepository, config: AuthlyConfig):
        self._repo = repo
        self._config = config
```

2. Add dependency function:
```python
# In api/dependencies.py
async def get_new_feature_service(
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
) -> NewFeatureService:
    repo = NewFeatureRepository(conn)
    return NewFeatureService(repo, config)
```

3. Use in router:
```python
@router.post("/new-feature")
async def create_feature(
    request: NewFeatureRequest,
    service: NewFeatureService = Depends(get_new_feature_service),
):
    return await service.create(request)
```

## Conclusion

These patterns provide a consistent, testable, and maintainable architecture for the Authly service. Following these patterns ensures:

- Clear separation of concerns
- Consistent error handling
- Proper transaction management
- Testable code at all layers
- Maintainable and extensible architecture

When in doubt, follow the existing patterns in the codebase and refer to this documentation for guidance.