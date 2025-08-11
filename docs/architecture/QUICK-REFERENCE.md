# Authly Architecture Quick Reference

## 🏗️ Architecture Layers

| Layer | Purpose | Location | Example |
|-------|---------|----------|---------|
| **Routers** | HTTP endpoints | `src/authly/api/*_router.py` | `admin_router.py` |
| **Services** | Business logic | `src/authly/*/service.py` | `ClientService` |
| **Repositories** | Data access | `src/authly/*/*_repository.py` | `UserRepository` |
| **Models** | Data structures | `src/authly/*/models.py` | `UserModel` |

## 🔌 Dependency Injection

### Creating a Service Dependency

```python
# In api/admin_dependencies.py
async def get_admin_client_service(
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
) -> ClientService:
    client_repo = ClientRepository(conn)
    scope_repo = ScopeRepository(conn)
    return ClientService(client_repo, scope_repo, config)
```

### Using in Router

```python
@router.post("/clients")
async def create_client(
    request: OAuthClientCreateRequest,
    service: ClientService = Depends(get_admin_client_service),  # ✅ DI
):
    return await service.create_client(request)
```

## 📦 Repository Patterns

### Standard Repository (99% of cases)
```python
from psycopg_toolkit import BaseRepository

class UserRepository(BaseRepository[UserModel]):
    table_name = "users"
    model_class = UserModel
```

### Special Case Repository (rare)
```python
class JWKSRepository:
    """
    SPECIAL CASE: Manages cryptographic keys, not CRUD.
    Does NOT inherit from BaseRepository.
    """
    def __init__(self, conn: AsyncConnection):
        self._conn = conn
```

## 🎯 Service Patterns

### Service Structure
```python
class ClientService:
    def __init__(self, client_repo: ClientRepository, scope_repo: ScopeRepository, config: AuthlyConfig):
        self._client_repo = client_repo  # ⚠️ Private with underscore!
        self._scope_repo = scope_repo
        self._config = config
```

### Service Attribute Names

| Service | Repository Attributes |
|---------|----------------------|
| `ClientService` | `_client_repo`, `_scope_repo` |
| `UserService` | `_repo` |
| `ScopeService` | `_scope_repo` |
| `TokenService` | `_repo` |

## 🧪 Testing Patterns

### ❌ WRONG: Transaction + HTTP Call
```python
async def test_broken(test_server, transaction_manager):
    async with transaction_manager.transaction() as conn:
        user = await create_user(conn)  # Not committed!
        response = await test_server.client.get(f"/users/{user.id}")
        # FAILS: User not visible to HTTP server
```

### ✅ CORRECT: Committed Fixtures
```python
async def test_working(test_server, committed_user):
    response = await test_server.client.get(f"/users/{committed_user.id}")
    # SUCCESS: User is committed and visible
```

## 📁 File Organization

```
src/authly/
├── api/
│   ├── admin_router.py         # Admin endpoints
│   ├── admin_dependencies.py   # Admin service DI
│   ├── oauth_router.py         # OAuth endpoints
│   └── oauth_dependencies.py   # OAuth service DI
├── oauth/
│   ├── client_service.py       # Business logic
│   ├── client_repository.py    # Data access
│   └── models.py               # Data models
└── users/
    ├── service.py              # Business logic
    ├── repository.py           # Data access
    └── models.py               # Data models
```

## 🚀 Common Tasks

### Add a New Endpoint
1. Add method to service
2. Add endpoint to router with DI
3. Add tests with committed fixtures

### Add a New Service
1. Create service class with `_repo` attributes
2. Add dependency function in `*_dependencies.py`
3. Use `Depends()` in router

### Fix a Failing Test
1. Check for transaction isolation issues
2. Use committed fixtures for HTTP tests
3. Verify service uses correct attribute names

## ⚠️ Common Pitfalls

| Problem | Solution |
|---------|----------|
| `'ClientService' object has no attribute 'client_repo'` | Use `_client_repo` (with underscore) |
| Test fails with "not found" after creating in transaction | Use committed fixtures |
| Inline service creation in router | Move to dependency function |
| Business logic in repository | Move to service layer |
| Direct repository access from router | Use service layer |

## 📚 Full Documentation

- [Service Patterns](./service-patterns.md) - Detailed architecture guide
- [Testing Guide](../testing/README.md) - Testing best practices
- [API Documentation](../api/README.md) - API endpoint reference