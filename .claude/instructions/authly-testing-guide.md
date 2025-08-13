# Authly Testing Guide - Compact Memory Reference

## Overview
- **Philosophy**: Real-world integration testing over mocking
- **Coverage**: 97%+ with 100% success rate across 45+ test modules
- **Note**: Tests cover main functionality; edge cases and error scenarios need more coverage. System not production-certified.

## Core Testing Stack
```python
# Core dependencies
fastapi = ">=0.116.1"
psycopg-toolkit = ">=0.2.0"  # Transaction management
psycopg[binary] = ">=3.2.3"
psycopg-pool = ">=3.2.4"
httpx = ">=0.28.1"

# Test dependencies
pytest = ">=8.3.4"
pytest-asyncio = ">=0.25.0"
pytest-cov = ">=6.0.0"
pytest-order = ">=1.3.0"
pytest-xdist = ">=3.8.0"  # Parallel test execution
testcontainers[postgres] = ">=4.10.0"  # Real PostgreSQL
fastapi-testing = ">=0.2.0"  # Real FastAPI server testing

# Security & Auth
python-jose[cryptography] = ">=3.3.0"
cryptography = ">=44.0.1"
bcrypt = "==4.3.0"
pyjwt = ">=2.10.1"

# Optional groups
redis = ">=5.2.0"  # Redis support
ruff = ">=0.8.6"  # Dev linting
```

## Key Testing Principles
1. **Real Database**: PostgreSQL with testcontainers, never SQLite/in-memory
2. **Real HTTP Server**: Actual FastAPI instances with full middleware
3. **Real Connections**: Async database connections with proper pooling
4. **Transaction Isolation**: Each test gets auto-rollback transaction
5. **No Critical Mocking**: Avoid mocking auth, DB ops, or HTTP requests
6. **Development Parity**: Test config matches realistic scenarios

## Test Structure
```
tests/
├── conftest.py                    # Global fixtures
├── fixtures/                      # Test infrastructure
│   └── testing/
│       ├── lifespan.py           # App lifecycle
│       └── postgres.py           # PostgreSQL containers
├── OAuth 2.1 Core Tests (8 files)
├── OpenID Connect Tests (14 files)
├── Authentication Tests (6 files)
├── Administration Tests (7 files)
├── Security & Infrastructure (5 files)
└── Application Tests (4 files)
```

## Essential Fixtures (conftest.py)

### Session-scoped Fixtures
- `event_loop`: Session-scoped async event loop
- `postgres_container`: PostgreSQL testcontainer
- `test_config`: Test configuration with real DB URL
- `resource_manager`: Manages DB connections and resources

### Test-scoped Fixtures
- `transaction_manager`: Fresh transaction with auto-rollback per test
- `test_app`: FastAPI application instance
- `test_server`: Real FastAPI test server with middleware

## Transaction Isolation Pattern
```python
@pytest.mark.asyncio
async def test_with_isolation(transaction_manager, test_server):
    async with transaction_manager.transaction() as conn:
        # 1. Create repositories inside transaction
        user_repo = UserRepository(conn)
        client_repo = ClientRepository(conn)
        
        # 2. Set up test data
        test_user = await user_repo.create({...})
        test_client = await client_repo.create({...})
        
        # 3. Test with real HTTP requests
        response = await test_server.client.post("/oauth/token", ...)
        
        # 4. Assert results
        assert response.status_code == 200
        
        # 5. Transaction auto-rollback - no cleanup needed!
```

## Test Categories & Coverage

### 1. OAuth 2.1 Core
- Authorization code flow with PKCE
- Token lifecycle (access, refresh, revocation)
- Client authentication methods
- Scope management
- Discovery metadata (RFC 8414)
- **Key Tests**: `test_oauth_authorization.py`, `test_oauth_token_flow.py`

### 2. OpenID Connect (OIDC)
- Complete OIDC flows with ID tokens
- UserInfo endpoint
- JWKS endpoint
- Session management
- Logout flows
- Nonce validation
- **Key Tests**: `test_oidc_complete_flows.py`, `test_oidc_id_token.py`

### 3. Security Testing
- Rate limiting/brute force protection
- PKCE validation preventing code interception
- Client authentication security
- Token security validation
- **Key Tests**: `test_security_middleware.py`, `test_token_revocation.py`

### 4. Performance Testing
- Database connection pool under load
- Concurrent OAuth authorization requests
- Target: <100ms per DB operation, <500ms per auth request
- **Pattern**: Test with 25-50 concurrent operations

### 5. Administration
- CLI tools testing
- Admin API endpoints
- System bootstrapping
- Admin middleware validation

## Key Test Patterns

### OAuth Flow Testing
```python
async def test_oauth_flow(transaction_manager, test_server):
    async with transaction_manager.transaction() as conn:
        # Setup: Create client, user, scopes
        # Step 1: Authorization request with PKCE
        # Step 2: User authentication & consent
        # Step 3: Token exchange with code_verifier
        # Step 4: Verify token access
```

### OIDC Testing
```python
async def test_oidc_flow(transaction_manager, test_server):
    # Include: nonce, openid scope, ID token validation
    # Verify: ID token claims (iss, aud, sub, nonce, exp, iat)
    # Test: UserInfo endpoint with access token
```

### Security Testing
```python
async def test_security(transaction_manager, test_server):
    # Test rate limiting (429 responses)
    # Test PKCE validation
    # Test client auth methods (basic, post, public)
    # Test token expiration/revocation
```

## Test Data Factory Pattern
```python
class AuthlyTestDataFactory:
    @staticmethod
    def create_user_data(email=None, password="testpassword", is_verified=True, is_active=True)
    
    @staticmethod
    def create_oauth_client_data(client_type="confidential", client_id=None, client_secret="test-secret")
    
    @staticmethod
    def create_oidc_client_data(client_id=None, client_secret="oidc-secret")
    
    @staticmethod
    def create_scope_data(scope_name, description=None, is_default=False)
    
    @staticmethod
    def create_standard_scopes()  # Returns openid, profile, email, read, write
```

## CI/CD Integration
- GitHub Actions with PostgreSQL service
- Poetry for dependency management
- Coverage requirement: 95%+
- Linting: ruff, black, isort
- Type checking: mypy
- Test results uploaded as artifacts

## Best Practices

### DO:
- Use transaction isolation for every DB test
- Test both success and failure scenarios
- Use real FastAPI test server for HTTP testing
- Include performance assertions in critical paths
- Use descriptive test names explaining what's tested

### DON'T:
- Mock database operations
- Mock authentication/authorization
- Use SQLite for testing
- Skip error scenario testing
- Access database without transaction isolation

## Common Test Commands
```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=src/authly --cov-report=term-missing

# Run specific category
poetry run pytest tests/test_oauth_*.py
poetry run pytest tests/test_oidc_*.py

# Run with verbose output
poetry run pytest -v --tb=short

# Run performance tests
poetry run pytest -k "performance" -v
```

## Key Environment Variables for Testing
```bash
AUTHLY_DATABASE_URL=postgresql://test_user:test_password@localhost:5432/test_authly
AUTHLY_JWT_SECRET_KEY=test-secret-key
AUTHLY_JWT_REFRESH_SECRET_KEY=test-refresh-secret-key
AUTHLY_ADMIN_EMAIL=admin@test.local
AUTHLY_ADMIN_PASSWORD=admin123
```

## Critical Testing Gaps (Per Documentation)
- Edge cases need more coverage
- Error scenarios need expansion
- System not production-certified
- Additional security edge cases needed

## Quick Reference: Most Important Test Files
1. `conftest.py` - All test fixtures and setup
2. `test_oauth_authorization.py` - OAuth 2.1 auth code flow
3. `test_oidc_complete_flows.py` - Full OIDC implementation
4. `test_security_middleware.py` - Security testing
5. `test_admin_cli.py` - CLI administration
6. `test_resource_manager_integration.py` - Resource lifecycle