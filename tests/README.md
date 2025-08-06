# Authly Test Suite Organization

The Authly test suite is organized by **feature domains and user journeys** to provide better clarity, maintainability, and parallel execution capabilities.

## Test Structure

### 1. Authentication & User Management (`auth_user_journey/`)
Core user authentication lifecycle tests including:
- User registration and login
- Password management and security
- Token generation and revocation
- User data persistence

**Run:** `pytest tests/auth_user_journey/`

### 2. OAuth 2.1 Core Flows (`oauth_flows/`)
Standard OAuth 2.1 implementation tests:
- Authorization and token endpoints
- OAuth discovery and metadata
- Client authentication
- Grant type flows

**Run:** `pytest tests/oauth_flows/`

### 3. OpenID Connect Features (`oidc_features/`)
OIDC-specific functionality tests:
- OIDC discovery endpoints
- ID token handling
- UserInfo endpoint
- JSON Web Key Sets (JWKS)
- OIDC logout flows

**Run:** `pytest tests/oidc_features/`

### 4. OIDC Integration Scenarios (`oidc_scenarios/`)
End-to-end OIDC flow tests:
- Complete authorization code flows
- OIDC compliance testing
- Client registration flows
- Complex multi-step scenarios

**Run:** `pytest tests/oidc_scenarios/`

### 5. Admin Portal (`admin_portal/`)
Administrative interface tests:
- Admin API endpoints
- Admin authentication
- Session management
- CLI tools
- Caching and middleware

**Run:** `pytest tests/admin_portal/`

### 6. Admin User Management (`admin_user_management/`)
Admin-specific user management:
- User CRUD operations
- Bulk user operations
- Password reset flows
- User search and filtering

**Run:** `pytest tests/admin_user_management/`

### 7. Core Infrastructure (`infrastructure/`)
Framework and infrastructure tests:
- Application initialization
- Security middleware
- Logging infrastructure
- Database optimization
- Resource management

**Run:** `pytest tests/infrastructure/`

## Running Tests

### Run all tests
```bash
pytest
```

### Run specific feature area
```bash
pytest tests/oauth_flows/
pytest tests/admin_portal/
```

### Run multiple feature areas
```bash
pytest tests/auth_user_journey/ tests/oauth_flows/
```

### Run with coverage
```bash
pytest --cov=src --cov-report=html
```

### Run in parallel (requires pytest-xdist)
```bash
pytest -n auto
```

### Run specific test file
```bash
pytest tests/auth_user_journey/test_auth_api.py
```

### Run with specific markers
```bash
pytest -m "not slow"              # Skip slow tests
pytest -m "auth and unit"         # Run auth unit tests only
pytest -m "integration"           # Run only integration tests
```

## Test Markers

Tests can be marked with the following markers (defined in `pyproject.toml`):
- `@pytest.mark.auth` - Authentication and user management tests
- `@pytest.mark.oauth` - OAuth 2.1 core flow tests
- `@pytest.mark.oidc` - OpenID Connect feature tests
- `@pytest.mark.oidc_integration` - OIDC integration scenario tests
- `@pytest.mark.admin` - Admin portal tests
- `@pytest.mark.admin_users` - Admin user management tests
- `@pytest.mark.infrastructure` - Core infrastructure tests
- `@pytest.mark.integration` - Integration tests (require database)
- `@pytest.mark.unit` - Unit tests (no external dependencies)
- `@pytest.mark.slow` - Slow running tests

## CI/CD Configuration

For CI/CD pipelines, you can run test suites in parallel:

```yaml
# Example GitHub Actions matrix
strategy:
  matrix:
    test-suite:
      - auth_user_journey
      - oauth_flows
      - oidc_features
      - oidc_scenarios
      - admin_portal
      - admin_user_management
      - infrastructure
```

## Adding New Tests

When adding new tests:
1. Place them in the appropriate feature directory
2. Use clear, descriptive test names
3. Add appropriate markers
4. Follow existing patterns in that directory
5. Update this README if adding new test categories

## Benefits of This Structure

1. **Clear Organization**: Tests are grouped by feature/journey
2. **Easier Navigation**: Find related tests quickly
3. **Parallel Execution**: Run test suites independently
4. **Focused Testing**: Test only what you're working on
5. **Better CI/CD**: Configure different strategies per suite
6. **Scalability**: Easy to add new feature areas