# Psycopg3 Transaction Patterns and Best Practices

## Architecture Overview

The Authly codebase uses a **modern psycopg3 architecture** with:
- **Auto-commit mode** for production endpoints
- **Service layer** for business logic 
- **Repository pattern** with psycopg-toolkit BaseRepository
- **Dependency injection** via FastAPI

## ✅ CORRECT Patterns

### 1. Connection Management
```python
# ✅ CORRECT: Auto-commit connection (production)
async def authly_db_connection() -> AsyncGenerator[AsyncConnection, None]:
    pool = Authly.get_instance().get_pool()
    async with pool.connection() as conn:
        yield conn  # Auto-commit mode

# ✅ CORRECT: Explicit transaction (testing/special cases)
async def authly_db_transaction() -> AsyncGenerator[AsyncTransaction, None]:
    async for conn in authly_db_connection():
        async with conn.transaction() as transaction:
            yield transaction
```

### 2. Repository Operations
```python
# ✅ CORRECT: No manual commits in auto-commit mode
async def create_user(self, user_data: dict) -> UserModel:
    async with self.db_connection.cursor(row_factory=dict_row) as cur:
        await cur.execute(insert_query, values)
        result = await cur.fetchone()
        # No commit() needed - auto-commit handles it
        return UserModel(**result)
```

### 3. Service Layer Usage
```python
# ✅ CORRECT: Use services, not repositories directly
@router.post("/users")
async def create_user(
    user_data: UserCreate,
    user_service: UserService = Depends(get_user_service)
):
    return await user_service.create_user(user_data)
```

### 4. Modern Transaction Control
```python
# ✅ CORRECT: Context manager for transactions
async with conn.transaction():
    await cur.execute("INSERT ...")
    await cur.execute("UPDATE ...")
    # Automatic commit on success, rollback on exception
```

## ❌ INCORRECT Patterns

### 1. Manual Commits in Auto-commit Mode
```python
# ❌ WRONG: Manual commits in auto-commit mode
async def create_user(self, user_data: dict) -> UserModel:
    async with self.db_connection.cursor() as cur:
        await cur.execute(insert_query, values)
        result = await cur.fetchone()
        await self.db_connection.commit()  # ❌ Unnecessary in auto-commit
        return UserModel(**result)
```

### 2. Silent Exception Handling
```python
# ❌ WRONG: Hiding database errors
try:
    await self.db_connection.commit()
except Exception:
    pass  # ❌ Masks legitimate database errors
```

### 3. Manual Transaction Control
```python
# ❌ WRONG: Manual BEGIN/COMMIT (use context managers)
await conn.execute("BEGIN")
try:
    await conn.execute("INSERT ...")
    await conn.execute("COMMIT")
except:
    await conn.execute("ROLLBACK")
```

### 4. Bypassing Service Layer
```python
# ❌ WRONG: Using repositories directly in endpoints
@router.post("/users")
async def create_user(
    user_data: UserCreate,
    user_repo: UserRepository = Depends(get_user_repository)  # ❌ Skip service
):
    return await user_repo.create(user_data)
```

### 5. Cursor Context in Connection Functions
```python
# ❌ WRONG: Cursor context causes transaction issues
async def authly_db_connection() -> AsyncGenerator[AsyncConnection, None]:
    pool = Authly.get_instance().get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as _:  # ❌ Causes implicit rollbacks
            yield conn
```

## 🏗️ Architecture Layers

```
FastAPI Endpoints
       ↓
   Service Layer (Business Logic)
       ↓  
  Repository Layer (Data Access)
       ↓
   psycopg3 Auto-commit Connection
       ↓
  psycopg-toolkit Database/TransactionManager
       ↓
    PostgreSQL Database
```

**Key Components:**
- **authly_db_connection()**: Auto-commit connections for production
- **psycopg-toolkit Database**: Connection pool management and lifecycle
- **psycopg-toolkit TransactionManager**: Advanced transaction control for testing
- **psycopg-toolkit BaseRepository**: Repository pattern with built-in CRUD operations

## 🧪 Testing Patterns

### Production Mode
- Use `authly_db_connection()` (auto-commit)
- Each operation commits immediately
- Simple and efficient for CRUD operations

### Test Mode
- Use `TransactionManager` from psycopg-toolkit for isolation
- Wrap test operations in transactions with automatic rollback
- Support for savepoints, schema management, and test data lifecycle
- See `.claude/external-libraries.md` for complete TransactionManager API

## 🎯 Key Principles

1. **Embrace Auto-commit**: Let psycopg3 handle transaction lifecycle
2. **Use Service Layer**: Business logic belongs in services, not endpoints
3. **Context Managers**: Use `async with conn.transaction():` for explicit transactions
4. **Don't Fight the Framework**: psycopg3 is designed to be simple and safe
5. **Repository Purity**: Repositories should only execute queries, not manage transactions

## 🚨 Red Flags

- Manual `commit()` calls in repositories
- `try/except` around commits to "handle both modes"
- Direct repository usage in FastAPI endpoints
- Manual BEGIN/COMMIT/ROLLBACK statements
- Cursor contexts in connection factory functions

## 📚 References

- [psycopg3 Documentation](https://www.psycopg.org/psycopg3/docs/)
- [psycopg-toolkit Local Repository](../psycopg-toolkit/) - See `.claude/external-libraries.md` for detailed usage patterns
- [fastapi-testing Local Repository](../fastapi-testing/) - See `.claude/external-libraries.md` for testing patterns
- `.claude/external-libraries.md` - Comprehensive documentation of Descoped team libraries
- Clean Architecture principles
- FastAPI Dependency Injection patterns