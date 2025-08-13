# Authly Development Practices - Compact Reference

**Version**: 1.0  
**Authority**: Normative reference for all Authly development  

## ⚠️ MANDATORY PREREQUISITE
**It is a pre-requisite that `.claude/instructions/authly-testing-guide.md` is read first, before you read this document.**

This document builds upon and references the testing guide. You MUST read the testing guide first for complete context.

## 🚨 CRITICAL RULES - NEVER VIOLATE

### Rule #1: Transaction Isolation with AsyncTestServer
**GOLDEN RULE**: AsyncTestServer tests MUST use committed fixtures, NOT transactions.

```python
# ❌ FORBIDDEN - Uncommitted transaction invisible to HTTP server
async def test_something(test_server, transaction_manager):
    async with transaction_manager.transaction() as conn:
        user = await create_user(conn)  # Uncommitted
        response = await test_server.client.get(f"/users/{user.id}")  # FAILS!

# ✅ REQUIRED - Committed fixtures
async def test_something(test_server, committed_user):
    response = await test_server.client.get(f"/users/{committed_user.id}")  # SUCCESS
```
**Why**: Separate DB connections can't see uncommitted transactions.  
**Implementation**: Use `tests/fixtures/committed_data.py` for HTTP tests.

### Rule #2: No Mocking Frameworks
**FORBIDDEN**: `AsyncMock`, `patch`, `@mock` decorators prohibited unless approved.
- Test real integrations, not mocks
- Verify actual behavior, not assumptions

### Rule #3: Package-by-Feature Organization
```
✅ CORRECT                    ❌ FORBIDDEN
tests/                        tests/
├── oauth_flows/              ├── unit/
├── oidc_features/            ├── integration/
├── admin_portal/             └── e2e/
├── auth_user_journey/
└── infrastructure/
```
**Exceptions**: Only `infrastructure/` and `performance/` allowed as non-feature packages.

### Rule #4: Always Run Tests After Changes
```bash
pytest tests/oauth/test_client_repository.py -v  # Specific file
pytest tests/oauth/ -v                           # Module
pytest tests/ -v                                 # All tests
```
**Mandatory**: All tests MUST pass before marking task complete.

### Rule #5: Dependency Injection Pattern
```python
# ✅ CORRECT - In dependencies file
async def get_user_service(
    user_repo: UserRepository = Depends(get_user_repository)
) -> UserService:
    return UserService(user_repo)

# ❌ FORBIDDEN - Inline creation in router
@router.post("/users")
async def create_user(resource_manager = Depends(get_resource_manager)):
    user_service = UserService(UserRepository(...))  # FORBIDDEN inline
```
**Location**: All overrides in `tests/fixtures/testing/lifespan.py`

## 📋 ARCHITECTURE PATTERNS

### Service Layer
```python
class UserService:
    def __init__(self, user_repo: UserRepository):
        self._repo = user_repo  # Private with underscore
```

**Attribute Naming Convention**:
- `UserService`: `_repo`
- `ClientService`: `_client_repo`, `_scope_repo`
- `ScopeService`: `_scope_repo`
- `TokenService`: `_repo`

### Repository Categories

**Standard Repositories** (use BaseRepository):
- `UserRepository`, `ClientRepository`, `AuthorizationCodeRepository`
- `TokenRepository`, `ScopeRepository`

**Special Repositories** (DO NOT migrate):
- `JWKSRepository` - Cryptographic keys, not CRUD
- `SessionRepository` - Custom session handling

### FastAPI Dependency Override
**Central Location**: `tests/fixtures/testing/lifespan.py`
```python
dependency_overrides = {
    get_resource_manager: get_test_resource_manager,
    get_config: get_test_config,
    # Add new overrides HERE only
}
```
**NEVER** create override dictionaries in individual test files.

## 🔧 TECHNICAL STANDARDS

### OAuth 2.1/OIDC Requirements
- **Only** authorization code flow (no implicit/hybrid)
- **PKCE S256** mandatory for all auth flows
- **State parameter** required for auth requests
- **Client credentials** for M2M authentication
- **CORS handling**: Status 0 for blocked redirects
- **Rate limiting**: 429 after threshold

### Docker Standards
```yaml
# Mandatory health checks
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 10s
  timeout: 5s
  retries: 5

# Service dependencies with conditions
depends_on:
  authly-standalone:
    condition: service_healthy

# Port mapping: External:Internal
ports:
  - "8080:80"
```

### Makefile Commands (Required)
```makefile
build    # Build Docker images
start    # Start services with deps
stop     # Stop and clean services
run      # Alias for start
clean    # Complete cleanup
logs     # Follow main service logs
test     # Run test suite
```

## 🧪 TESTING PRACTICES

### Fixture Types

**Committed Fixtures** (HTTP tests):
```python
@pytest.fixture
async def committed_user():
    """User committed to DB, visible to HTTP endpoints."""
    # Uses autocommit
```

**Transactional Fixtures** (repository tests only):
```python
@pytest.fixture
async def transactional_user(transaction_manager):
    async with transaction_manager.transaction() as conn:
        yield user  # Auto-rollback
```

### Browser-Based Testing
**When**: OAuth/OIDC compliance, CORS validation, E2E flows

```bash
make stop && make build && make start
open http://localhost:8080  # Compliance tester
# Verify 22/22 tests pass
```

**Key Points**:
- CORS Status 0 valid for blocked redirects
- Browser behavior differs from test clients
- Real network timeouts occur

## 📝 DOCUMENTATION REQUIREMENTS

### Required Documentation
```python
class UserService:
    """
    Handles user business logic including registration,
    authentication, and profile management.
    """
```

### Maintain These Documents
- `docs/architecture/service-patterns.md`
- `docs/architecture/QUICK-REFERENCE.md`
- Status tracking in `ai_docs/`

## 🔍 COMPLIANCE VERIFICATION

### Required Test Results
- **TCK Conformance**: 40/40 checks
- **Browser Compliance**: 22/22 tests
- **Integration Tests**: 416+ tests
- **Zero failures allowed**

### Testing Methodology
1. Server-side: Business logic validation
2. Browser-side: Real-world behavior
3. TCK: Specification compliance
4. Integration: End-to-end flows

## 🚀 LOGGING PRINCIPLES

### Enhanced Logging
1. **Summary First** - High-level results before details
2. **Failure Prioritization** - Failures prominent, successes compact
3. **Smart Truncation** - Preserve important, truncate verbose
4. **Actionable Suggestions** - Include fix recommendations

```javascript
this.config = {
    logLevel: 'info',
    showSuccesses: false,  // Summary only for passed
    maxHttpBodyLength: 200,
    maxHttpHeadersCount: 3
};
```

## 🎯 SUCCESS CRITERIA

### Required Standards
- 100% test pass rate
- Zero production bugs in OAuth/OIDC
- 100% OAuth 2.1 compliance
- Clean architecture with separation of concerns
- Comprehensive integration test coverage

## 📋 QUICK REFERENCE

### When Modifying Code
1. Follow package-by-feature organization
2. Use committed fixtures for HTTP tests
3. Use dependency injection for services
4. Run tests after changes
5. Update documentation

### When Adding Features
1. Create in appropriate feature package
2. Add committed fixtures if HTTP involved
3. Document in architecture guides
4. Verify OAuth/OIDC compliance
5. Run full test suite

### When Fixing Bugs
1. Create reproducing test first
2. Fix following architecture patterns
3. Verify with comprehensive testing
4. Document fix and prevention

## 🔄 CONTINUOUS IMPROVEMENT

### Monthly Reviews
- Test organization and redundancy
- Documentation updates
- OAuth/OIDC compliance verification
- Developer tooling improvements

### Quarterly Reviews
- Full architecture review
- Security compliance audit
- Performance benchmarking
- Framework updates

## 📞 ESCALATION PATH

### When Unclear
1. Check this document
2. Review `/docs/architecture/`
3. Check `/docs/fix-redundancy-lesson-learned.md`
4. Follow established patterns
5. Document new patterns

### When Changes Needed
1. Document use case and justification
2. Propose with alternatives
3. Update this document
4. Communicate to team
5. Update tooling/documentation

---

*Normative reference for all Authly development. Updates require explicit approval.*

**Last Updated**: 2025-08-12  
**Next Review**: 2025-09-12