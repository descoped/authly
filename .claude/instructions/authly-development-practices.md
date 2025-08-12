# Authly Development Practices and Code Hygiene Rules

**Version**: 1.0  
**Created**: 2025-08-12  
**Authority**: Normative reference for all Authly development work  
**Scope**: All code, tests, documentation, and infrastructure changes

---

## 🚨 CRITICAL RULES - NEVER VIOLATE THESE

### Rule #1: Transaction Isolation in Testing

**THE GOLDEN RULE**: If your test uses `AsyncTestServer`, it MUST use committed fixtures, NOT transactions.

```python
# ❌ FORBIDDEN - Will always fail
async def test_something(test_server, transaction_manager):
    async with transaction_manager.transaction() as conn:
        user = await create_user(conn)  # Uncommitted transaction
        response = await test_server.client.get(f"/users/{user.id}")
        # FAILS: HTTP server can't see uncommitted data!

# ✅ REQUIRED - Use committed fixtures
async def test_something(test_server, committed_user):
    response = await test_server.client.get(f"/users/{committed_user.id}")
    # SUCCESS: Data is committed and visible to HTTP server
```

**Why**: `AsyncTestServer` runs with separate database connections. Uncommitted transaction data is invisible to other connections due to transaction isolation.

**Implementation**: Use fixtures from `tests/fixtures/committed_data.py` for all HTTP endpoint tests.

### Rule #2: No Mocking Frameworks

**PROHIBITION**: The use of `AsyncMock`, `patch`, or `@mock` decorators is FORBIDDEN unless specifically documented and approved.

```python
# ❌ FORBIDDEN
@patch('authly.services.email_service.send_email')
async def test_user_registration(mock_send_email):
    mock_send_email.return_value = True
    # This violates Authly's testing philosophy

# ✅ REQUIRED - Real integration testing
async def test_user_registration(test_server, email_test_fixture):
    response = await test_server.client.post("/register", ...)
    # Verify actual email was sent via test fixture
```

**Philosophy**: Authly prioritizes real-world integration testing. We test the system as users experience it.

### Rule #3: Package-by-Feature Organization

**REQUIREMENT**: Tests MUST be organized by business domain, NOT technical layer.

```
# ✅ CORRECT - Package-by-feature
tests/
├── oauth_flows/        # OAuth business logic
├── oidc_features/      # OIDC business logic
├── admin_portal/       # Admin functionality
├── auth_user_journey/  # User authentication flows
└── infrastructure/     # Infrastructure-only tests

# ❌ FORBIDDEN - Technical layer organization
tests/
├── unit/              # Violates package-by-feature
├── integration/       # Violates package-by-feature
└── e2e/              # Violates package-by-feature
```

**Exceptions**: Only `infrastructure/` and `performance/` are allowed as non-feature packages.

### Rule #4: Always Run Tests After Changes

**MANDATORY**: ALWAYS run pytest after modifying the codebase. No exceptions.

```bash
# Test specific file
pytest tests/oauth/test_client_repository.py -v

# Test specific module
pytest tests/oauth/ -v

# Run all tests (for broad changes)
pytest tests/ -v
```

**Requirement**: All tests MUST pass before marking any task complete. Fix failing tests immediately.

### Rule #5: Dependency Injection Pattern

**REQUIREMENT**: Services MUST be created via dependency injection, never inline in routers.

```python
# ✅ CORRECT - In dependencies file
async def get_user_service(
    user_repo: UserRepository = Depends(get_user_repository)
) -> UserService:
    return UserService(user_repo)

# ✅ CORRECT - In router
@router.post("/users")
async def create_user(
    user_service: UserService = Depends(get_user_service)
):
    return await user_service.create_user(...)

# ❌ FORBIDDEN - Inline creation
@router.post("/users")
async def create_user(resource_manager = Depends(get_resource_manager)):
    user_repo = UserRepository(resource_manager.get_pool())
    user_service = UserService(user_repo)  # Inline creation forbidden
    return await user_service.create_user(...)
```

**Location**: All dependency overrides MUST be in `tests/fixtures/testing/lifespan.py`.

---

## 📋 ARCHITECTURE PATTERNS

### Service Layer Patterns

**Services accept repositories as dependencies**:
```python
class UserService:
    def __init__(self, user_repo: UserRepository):
        self._repo = user_repo  # Private attribute with underscore
```

**Service Attribute Naming**:
- `UserService`: `_repo`
- `ClientService`: `_client_repo`, `_scope_repo`
- `ScopeService`: `_scope_repo`
- `TokenService`: `_repo`

### Repository Patterns

**Standard Repositories** (use psycopg-toolkit's BaseRepository):
- `UserRepository`, `ClientRepository`, `AuthorizationCodeRepository`
- `TokenRepository`, `ScopeRepository`

**Special Case Repositories** (DO NOT migrate to BaseRepository):
- `JWKSRepository` - Manages cryptographic keys, not CRUD operations
- `SessionRepository` - Manages session state, requires custom handling

### Testing Architecture

**Testing Philosophy**:
1. **Integration tests are the default** - Test the system as users experience it
2. **Unit tests are rare** - Only when absolutely necessary
3. **Fixture-based testing** - Use fixtures for test data, not mocks
4. **Real components** - Test with real databases, HTTP calls, service interactions

**Test Types**:
```python
# Repository tests (rare) - Use transactions
async def test_user_repository(transaction_manager):
    async with transaction_manager.transaction() as conn:
        user = await user_repo.create_user(...)
        assert user.id is not None

# Integration tests (default) - Use committed fixtures
async def test_oauth_flow(test_server, committed_user, committed_oauth_client):
    response = await test_server.client.post("/oauth/token", ...)
    assert response.status_code == 200
```

---

## 🔧 TECHNICAL STANDARDS

### OAuth 2.1/OIDC Compliance

**REQUIREMENTS**:
- Only authorization code flow supported (no implicit/hybrid)
- PKCE S256 is mandatory for all authorization flows
- State parameter is required for authorization requests
- Client credentials flow for machine-to-machine authentication
- Proper CORS handling (Status 0 for blocked redirects)
- Rate limiting middleware (429 after configurable requests)

### Docker and Infrastructure

**Docker Compose Standards**:
```yaml
# Health checks are mandatory
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 10s
  timeout: 5s
  retries: 5

# Service dependencies
depends_on:
  - authly-standalone:
      condition: service_healthy

# Correct port mapping (understand internal vs external ports)
ports:
  - "8080:80"  # External:Internal
```

**Makefile Standards**:
- Provide consistent, user-friendly commands
- Abstract Docker complexity
- Include help documentation
- Support common aliases

### FastAPI Dependency Override

**Central Location**: `tests/fixtures/testing/lifespan.py`

```python
# Find this dictionary and modify it
dependency_overrides = {
    get_resource_manager: get_test_resource_manager,
    get_config: get_test_config,
    # Add new overrides here
}

# For conditional overrides
if some_condition:
    dependency_overrides[get_user_service] = get_mock_user_service
```

**NEVER** create new override dictionaries in individual test files.

---

## 📝 DOCUMENTATION REQUIREMENTS

### Code Documentation

**Service Classes**:
```python
class UserService:
    """
    Handles user business logic including registration, authentication,
    and profile management.
    
    This service coordinates between UserRepository for data access
    and external services for email verification and password hashing.
    """
    
    def __init__(self, user_repo: UserRepository):
        self._repo = user_repo
```

**Repository Documentation**:
- Document why special repositories don't use BaseRepository
- Include examples of proper usage
- Document transaction handling

**Test Documentation**:
```python
def test_oauth_authorization_flow():
    """
    Tests the complete OAuth 2.1 authorization code flow with PKCE.
    
    Verifies:
    - PKCE S256 challenge/verifier generation
    - State parameter preservation
    - Authorization code exchange
    - Access token generation
    """
```

### Architecture Documentation

**Maintain These Documents**:
- `docs/architecture/service-patterns.md` - Service layer patterns
- `docs/architecture/QUICK-REFERENCE.md` - Developer quick reference
- Status tracking documents in `ai_docs/`

**Update When**:
- Adding new service patterns
- Changing repository structures
- Modifying testing approaches
- Major architectural changes

---

## 🧪 TESTING PRACTICES

### Fixture Guidelines

**Committed Fixtures** (for HTTP tests):
```python
# Use these for any test that makes HTTP calls
@pytest.fixture
async def committed_user():
    """Creates a user committed to the database, visible to HTTP endpoints."""
    # Implementation with autocommit
```

**Transactional Fixtures** (for repository tests only):
```python
# Only use for direct repository testing
@pytest.fixture
async def transactional_user(transaction_manager):
    async with transaction_manager.transaction() as conn:
        # Create user in transaction
        yield user
        # Transaction rolls back automatically
```

### Test Organization

**File Naming**:
- `test_{feature}.py` - Feature-specific tests
- `test_{service}_integration.py` - Service integration tests
- `conftest.py` - Fixtures local to that directory

**Directory Structure**:
```
tests/
├── fixtures/
│   ├── __init__.py          # Resource fixtures (DB, server)
│   ├── committed_data.py    # Committed fixtures for HTTP tests
│   └── testing/
│       └── lifespan.py      # Dependency overrides
├── oauth_flows/             # OAuth business domain
│   ├── conftest.py          # OAuth-specific fixtures
│   └── test_*.py           # OAuth tests
└── oidc_features/          # OIDC business domain
    ├── conftest.py          # OIDC-specific fixtures
    └── test_*.py           # OIDC tests
```

### Browser-Based Testing

**When to Use**:
- OAuth/OIDC compliance verification
- CORS handling validation
- Real-world flow testing
- End-to-end integration testing

**Implementation**:
```bash
# Start services
make stop && make build && make start

# Access compliance tester
open http://localhost:8080

# Run all tests and verify 22/22 passing
```

**Key Considerations**:
- CORS Status 0 is valid for blocked redirects
- Browser behavior differs from test clients
- Real network timeouts and redirects occur

---

## 🚀 DEPLOYMENT AND OPERATIONS

### Make Commands (Required)

```makefile
# Standard commands that MUST be supported
build:    # Build all Docker images
start:    # Start all services with dependencies
stop:     # Stop and clean all services
run:      # Alias for start (user preference)
clean:    # Complete cleanup of containers and volumes
logs:     # Follow logs from main service
test:     # Run test suite
```

### Docker Best Practices

**Auto-Configuration**:
- Bootstrap processes for complex setups
- Health checks for reliable startup
- Service dependencies with conditions
- Proper environment variable handling

**Networking**:
- Understand internal vs external port mapping
- Mount Docker socket when containers need to communicate
- Use proper container networking for service discovery

### Logging and Monitoring

**Enhanced Logging Principles**:
1. **Summary First** - High-level results before details
2. **Failure Prioritization** - Show failures prominently, successes compactly
3. **Smart Truncation** - Preserve important info, truncate verbosity
4. **Actionable Suggestions** - Include fix recommendations

**Implementation**:
```javascript
// Logger configuration
this.config = {
    logLevel: 'info',
    showSuccesses: false,  // Only show summary for passed tests
    maxHttpBodyLength: 200,
    maxHttpHeadersCount: 3
};
```

---

## 🔍 COMPLIANCE AND STANDARDS

### OAuth 2.1 Compliance Verification

**Required Tests**:
- TCK Conformance: 40/40 checks must pass
- Browser Compliance: 22/22 tests must pass
- Integration Tests: 416+ tests must pass
- Zero failures allowed

**Testing Methodology**:
1. **Server-side testing** - Business logic validation
2. **Browser-side testing** - Real-world behavior verification
3. **TCK testing** - Specification compliance verification
4. **Integration testing** - End-to-end flow validation

### Security Requirements

**Authentication**:
- PKCE S256 mandatory for authorization flows
- State parameter required and preserved
- Rate limiting implemented (configurable threshold)
- Client credentials flow for M2M authentication

**Data Handling**:
- No secrets in logs or error messages
- Proper transaction isolation
- Database race condition prevention
- Secure token storage and rotation

---

## 📚 KNOWLEDGE MANAGEMENT

### When Modifying Architecture

**Required Steps**:
1. Update service patterns documentation
2. Update quick reference guide
3. Test changes with full test suite
4. Update dependency injection patterns
5. Document any new patterns or exceptions

### When Adding Features

**Required Steps**:
1. Follow package-by-feature organization
2. Create committed fixtures if HTTP endpoints involved
3. Use dependency injection for services
4. Document the feature in architecture guides
5. Verify OAuth/OIDC compliance if applicable

### When Fixing Bugs

**Required Steps**:
1. Identify root cause (code, test, or environment)
2. Create test that reproduces the bug
3. Fix the issue following architecture patterns
4. Verify fix with comprehensive testing
5. Document the fix and prevention measures

---

## 🎯 SUCCESS CRITERIA

### Code Quality Metrics

**Required Standards**:
- 100% test pass rate (no failing tests allowed)
- Zero production bugs in OAuth/OIDC flows
- 100% OAuth 2.1 compliance (verified via multiple testing methods)
- Clean architecture with proper separation of concerns
- Comprehensive integration test coverage

### Documentation Standards

**Required Documents**:
- Architecture patterns are documented
- Service responsibilities are clear
- Testing practices are standardized
- Deployment procedures are automated
- Compliance status is tracked

### Developer Experience

**Required Features**:
- Consistent make commands for all operations
- Auto-configuration for complex setups
- Enhanced logging with actionable messages
- Clear error messages and debugging information
- Comprehensive fixture library for testing

---

## 🔄 CONTINUOUS IMPROVEMENT

### Regular Reviews

**Monthly**:
- Review test organization and eliminate redundancy
- Update documentation for any pattern changes
- Verify OAuth/OIDC compliance with latest standards
- Review and improve developer tooling

**Quarterly**:
- Full architecture review
- Security compliance audit
- Performance benchmarking
- Tool and framework updates

### Feedback Integration

**Process**:
1. Collect developer feedback on practices
2. Analyze recurring issues and patterns
3. Update practices based on lessons learned
4. Communicate changes to all developers
5. Update tooling and documentation

---

## 📞 SUPPORT AND ESCALATION

### When Rules Are Unclear

1. Consult this document first
2. Check architecture documentation in `/docs/architecture/`
3. Review lessons learned in `/docs/fix-redundancy-lesson-learned.md`
4. Follow established patterns in similar code
5. Document new patterns for future reference

### When Rules Need Changes

1. Document the specific use case and justification
2. Propose the change with alternatives considered
3. Update this document with the new rule
4. Communicate the change to all developers
5. Update related tooling and documentation

---

*This document serves as the normative reference for all Authly development work. All developers working on Authly MUST follow these practices. Updates to this document require explicit approval and communication to all team members.*

**Last Updated**: 2025-08-12  
**Next Review**: 2025-09-12