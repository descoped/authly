# Gemini Project Memory: Authly

This file provides comprehensive guidance to Gemini AI when working with code in this repository. It mirrors the understanding provided to Claude Code to ensure consistency across AI assistants.

## 1. Project Overview

**Authly** is a production-ready OAuth 2.1 authentication and authorization service built with modern Python patterns and FastAPI. It provides complete OAuth 2.1 compliance, JWT-based authentication, an admin API with a two-layer security model, comprehensive user management, enterprise-grade security, and PostgreSQL integration.

### Current Implementation Status

**✅ COMPLETED (100% Test Success - 265/265 tests passing):**
- Complete OAuth 2.1 implementation with PKCE support.
- Admin API with a two-layer security model (intrinsic authority + scoped permissions).
- Bootstrap system solving the IAM chicken-and-egg paradox.
- Admin CLI for OAuth client and scope management.
- Production-ready deployment with Docker support.
- Comprehensive test suite with real integration testing.
- JWT token management with revocation and rotation.
- User management with role-based access control.

**📝 NEXT STEPS (Phase 2 Implementation):**
- API-First CLI migration (CLI currently uses direct database access).
- Enhanced admin security features.
- OIDC implementation on the OAuth 2.1 foundation.

### Core Technologies
- **Python 3.13+**: Modern async/await, type annotations, dataclasses
- **FastAPI**: High-performance async web framework with automatic OpenAPI
- **PostgreSQL**: Advanced features with `psycopg3`, `pgvector`, UUID primary keys
- **Pydantic v2**: Modern data validation with constraints and serialization
- **Poetry**: Modern dependency management and packaging
- **JWT**: Token-based authentication with `python-jose` and JTI tracking

### Design Philosophy
- **Package-by-Feature**: Each feature is self-contained with models, repository, and service.
- **Layered Architecture**: Clean separation of API, Service, and Data Access layers.
- **Pluggable Components**: Strategy pattern with abstract base classes for flexible backends.
- **Async-First**: Full async/await implementation throughout the codebase.
- **Type Safety**: Comprehensive type annotations and Pydantic validation.
- **Security-by-Design**: Enterprise-grade security with encrypted secrets and rate limiting.

## 2. Development Commands

### Core Development Tasks
```bash
# Install dependencies
poetry install

# Run tests
pytest
pytest tests/test_auth.py -v          # Run specific test file
pytest tests/test_users.py -v         # Run user tests

# Linting and formatting
poetry run flake8                     # Lint code
poetry run black .                    # Format code
poetry run isort .                    # Sort imports
poetry run ruff check                 # Additional linting with ruff

# Build and distribution
poetry build                          # Build package
```

### Database Setup
The project requires PostgreSQL with specific extensions:
```sql
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

### Testing
- Uses pytest with asyncio support for modern async testing.
- Testcontainers for PostgreSQL integration tests (no mocking).
- fastapi-testing for real HTTP server integration testing.
- psycopg-toolkit for real database transaction testing.
- Run API tests with: `./examples/api-test.sh`
- `examples/embeded.py`: Powerful script to run entire service with database container.
- Comprehensive test suite with realistic database integration testing.
- **See `EXTERNAL_DESCOPED_LIBRARIES.md` for detailed testing patterns and library usage.**

## 3. Architecture Overview

### Project Structure (Package-by-Feature with OAuth 2.1)

```
authly/
├── src/authly/                    # Main package with public API
│   ├── __init__.py               # Public API with async generators
│   ├── authly.py                 # Singleton resource manager
│   ├── main.py                   # Production entry point with lifespan management
│   ├── admin/                    # Admin CLI system (direct database access)
│   │   ├── cli.py                # Main CLI entry point with Click commands
│   │   ├── context.py            # Admin context for database operations
│   │   ├── client_commands.py    # OAuth client management commands
│   │   └── scope_commands.py     # OAuth scope management commands
│   ├── api/                      # API layer (routers, dependencies, middleware)
│   │   ├── admin_dependencies.py # Admin authentication with two-layer security
│   │   ├── admin_middleware.py   # Runtime environment-based middleware security
│   │   ├── admin_router.py       # Admin API endpoints with localhost restriction
│   │   ├── auth_router.py        # Authentication endpoints (password + OAuth)
│   │   ├── oauth_router.py       # OAuth 2.1 endpoints (authorize, token, discovery)
│   │   ├── users_router.py       # User management endpoints
│   │   ├── health_router.py      # Health check endpoints
│   │   ├── auth_dependencies.py  # JWT and OAuth scope validation
│   │   ├── users_dependencies.py # User-related dependencies
│   │   └── rate_limiter.py       # Pluggable rate limiting
│   ├── auth/                     # Authentication core
│   │   └── core.py               # JWT creation, password hashing, OAuth integration
│   ├── bootstrap/                # System initialization
│   │   └── admin_seeding.py      # Admin user bootstrap solving IAM paradox
│   ├── config/                   # Configuration management
│   │   ├── config.py             # Main config with dataclasses
│   │   ├── database_providers.py # Database configuration providers
│   │   ├── secret_providers.py   # Strategy pattern for secrets
│   │   └── secure.py             # Encrypted secrets storage with memory cleanup
│   ├── oauth/                    # OAuth 2.1 implementation (package-by-feature)
│   │   ├── models.py             # OAuth client, scope, authorization code models
│   │   ├── client_repository.py  # OAuth client database operations
│   │   ├── client_service.py     # OAuth client business logic
│   │   ├── scope_repository.py   # OAuth scope database operations
│   │   ├── scope_service.py      # OAuth scope business logic
│   │   ├── authorization_code_repository.py # PKCE authorization code management
│   │   ├── authorization_service.py # OAuth authorization flow logic
│   │   ├── discovery_models.py   # OAuth discovery endpoint models
│   │   └── discovery_service.py  # OAuth discovery service implementation
│   ├── static/                   # Static files for OAuth UI
│   │   └── css/style.css         # Accessible OAuth UI styling
│   ├── templates/                # OAuth UI templates
│   │   ├── base.html             # Base template with accessibility
│   │   └── oauth/                # OAuth-specific templates
│   │       ├── authorize.html    # Authorization consent form
│   │       └── error.html        # OAuth error display
│   ├── tokens/                   # Token management (package-by-feature)
│   │   ├── models.py             # Pydantic models with enums
│   │   ├── repository.py         # Database operations with OAuth support
│   │   ├── service.py            # Business logic layer with OAuth scopes
│   │   └── store/                # Pluggable storage backends
│   │       ├── base.py           # Abstract base class
│   │       └── postgres.py       # PostgreSQL implementation
│   └── users/                    # User management
│       ├── models.py             # Pydantic user models with admin flags
│       ├── repository.py         # User database operations
│       └── service.py            # User business logic layer
├── tests/                        # Comprehensive test suite (265 tests, 100% pass rate)
│   ├── conftest.py               # Test configuration with real integration
│   ├── fixtures/                 # Test fixtures
│   │   └── testing/              # Testing infrastructure
│   │       ├── postgres.py       # Testcontainers PostgreSQL integration
│   │       └── lifespan.py       # Application lifecycle management
│   ├── test_admin_*.py           # Admin API and CLI tests
│   ├── test_oauth_*.py           # OAuth 2.1 implementation tests
│   ├── test_auth*.py             # Authentication and token tests
│   ├── test_users*.py            # User management tests
│   └── test_*.py                 # Additional component tests
├── examples/                     # Usage examples and deployment
│   ├── authly-embedded.py        # Production embedded server with containers
│   ├── api-test.sh               # API testing script
│   └── bruno/                    # Bruno API testing collection (OAuth + Auth)
├── docs/                         # Comprehensive documentation (11 files)
│   ├── oauth-2.1-implementation.md # OAuth 2.1 feature documentation
│   ├── migration-guide.md        # Password-only to OAuth 2.1 migration
│   ├── api-reference.md          # Complete API documentation
│   ├── cli-administration.md     # Admin CLI usage guide
│   ├── deployment-guide.md       # Production deployment instructions
│   ├── security-features.md      # Security implementation details
│   ├── testing-architecture.md   # Testing methodology and patterns
│   └── *.mmd                     # Mermaid diagrams for flows
├── docker/                       # Database initialization
│   └── init-db-and-user.sql      # Complete PostgreSQL schema with OAuth tables
├── refactoring/                  # Implementation planning and validation
│   └── FIX_CLI_AND_APP_LIFECYCLE_TODO_FINAL.md # Validated implementation status
├── Dockerfile                    # Production-ready multi-stage Docker build
└── pyproject.toml                # Modern Python project configuration
```

### Core Components

**Authly Singleton (`src/authly/authly.py`)**
- Central resource manager using singleton pattern.
- Manages async database connection pool and configuration.
- Thread-safe initialization with `Authly.initialize(pool, config)`.

**Configuration System (`src/authly/config/`)**
- `AuthlyConfig`: Main configuration class with dataclasses and type safety.
- `SecretProvider`: Abstract base for secret providers (Env, File, Static).
- `SecureSecrets`: Memory-safe secret storage with Fernet encryption and automatic cleanup.

**Authentication Core (`src/authly/auth/`)**
- JWT token creation and validation with `python-jose`.
- Password hashing with bcrypt and secure salt generation.
- Token management (access/refresh tokens) with JTI tracking.

**Token Management (`src/authly/tokens/` - Package-by-Feature)**
- `TokenModel`: Pydantic v2 model with constraints and validation.
- `TokenService`: High-level async token operations with business logic.
- `TokenRepository`: Async database operations with proper transaction handling.
- `TokenStore`: Abstract storage interface with PostgreSQL implementation.
- Token types: ACCESS, REFRESH with automatic cleanup and rotation.
- JWT tokens use `jti` claims for preventing token replay attacks.

**User Management (`src/authly/users/` - Package-by-Feature)**
- `UserModel`: Pydantic user model with constraints and validation.
- `UserRepository`: Async database operations with UUID primary keys.
- User CRUD operations with role-based access control (admin, verified flags).

**API Layer (`src/authly/api/`)**
- `auth_router`: Authentication endpoints (/auth/token, /auth/refresh, /auth/logout) with OAuth + password grant support.
- `oauth_router`: OAuth 2.1 endpoints (/authorize, /token, /.well-known/oauth-authorization-server, /revoke).
- `admin_router`: Admin API endpoints (/admin/oauth/clients, /admin/oauth/scopes, /admin/system/status).
- `users_router`: User management endpoints (/users/) with proper REST design.
- `health_router`: Health check endpoints for monitoring.
- `admin_middleware`: Runtime security enforcement (localhost-only, API enable/disable).
- `admin_dependencies`: Two-layer security model (intrinsic authority + scoped permissions).
- `auth_dependencies`: JWT validation with OAuth scope extraction and validation.
- `RateLimiter`: Brute force protection (pluggable: in-memory default, Redis for production).
- Dependencies for authentication and authorization with comprehensive OAuth support.

### Data Flow

**OAuth 2.1 Authorization Flow:**
1.  **Client Registration**: Admin → admin_router → ClientService → OAuth client creation.
2.  **Authorization Request**: User → oauth_router → Authorization consent → Authorization code (PKCE).
3.  **Token Exchange**: Client → oauth_router → Code validation → Access/refresh tokens with scopes.
4.  **Resource Access**: API requests → auth_dependencies → Scope validation → Protected resources.

**Password Grant Flow (Backward Compatibility):**
1.  **Authentication**: User credentials → auth_router → UserRepository → TokenService → JWT tokens.
2.  **Token Refresh**: Refresh token → auth_router → TokenService → New access/refresh tokens.
3.  **User Operations**: Protected endpoints → auth_dependencies → current user context.

**Admin Operations:**
1.  **Admin Authentication**: Intrinsic authority via is_admin flag (no OAuth dependency).
2.  **Admin API**: Localhost + admin user → admin_router → Admin scopes → OAuth management.
3.  **CLI Administration**: CLI → AdminContext → Direct database → OAuth client/scope operations.

**Token Storage**: All tokens stored in PostgreSQL with JTI tracking, OAuth client association, and scope management.

### Key Patterns
- **Repository Pattern**: All database operations go through repository classes.
- **Dependency Injection**: FastAPI dependencies for authentication, rate limiting, repositories.
- **Strategy Pattern**: Pluggable components with abstract base classes (TokenStore, RateLimiter).
- **Secure by Default**: All secrets managed through SecureSecrets with memory wiping.
- **Token Rotation**: Automatic refresh token rotation on each refresh.
- **Rate Limiting**: Built-in protection against brute force attacks.
- **Flexible Backends**: In-memory implementations for development, scalable backends for production.

### Database Schema (Modern PostgreSQL)

**Advanced PostgreSQL Features:**
- **UUID Primary Keys**: `gen_random_uuid()` for security and distribution.
- **Extensions**: `pgvector` for vector operations, `uuid-ossp` for UUID generation.
- **Triggers**: Automatic `updated_at` timestamp updates.
- **Constraints**: Check constraints for data integrity and validation.
- **Indexes**: Strategic indexing for performance optimization.

**Core Tables:**
```sql
-- Users table with comprehensive user management and admin authority
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    is_admin BOOLEAN DEFAULT false  -- Intrinsic authority for bootstrap security
);

-- OAuth clients for OAuth 2.1 compliance
CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(255),  -- NULL for public clients
    client_type VARCHAR(20) NOT NULL CHECK (client_type IN ('confidential', 'public')),
    redirect_uris TEXT[] NOT NULL,
    require_pkce BOOLEAN DEFAULT true,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- OAuth scopes for fine-grained permissions
CREATE TABLE scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Authorization codes with PKCE support
CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(255) UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(10) DEFAULT 'S256',
    redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tokens table with OAuth integration and JTI tracking
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,  -- OAuth client association
    token_jti VARCHAR(64) NOT NULL UNIQUE,
    token_type VARCHAR(10) NOT NULL CHECK (token_type IN ('access', 'refresh')),
    token_value TEXT NOT NULL,
    scopes TEXT[],  -- OAuth scopes for this token
    invalidated BOOLEAN NOT NULL DEFAULT false,
    invalidated_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Security Features
- JWT tokens with configurable expiration.
- Secure password hashing with bcrypt.
- Token blacklisting via database JTI tracking.
- Rate limiting on authentication endpoints.
- Memory-safe secret management.
- CORS and security headers middleware.

## 4. Testing Architecture (Modern Async Testing)

**Core Testing Principle**: Every new feature, repository, service, or API endpoint MUST have comprehensive test coverage before being considered complete.

**Test Organization:**
```
tests/
├── conftest.py               # Test configuration and shared fixtures
├── fixtures/                 # Test fixtures and utilities
│   └── testing/              # Testing infrastructure
│       ├── postgres.py       # Testcontainers PostgreSQL integration
│       └── lifespan.py       # Application lifecycle management
├── test_auth.py              # Authentication and token tests
├── test_users.py             # User management tests
├── test_tokens.py            # Token service tests
├── test_oauth_repositories.py # OAuth repository integration tests
├── test_oauth_services.py    # OAuth service integration tests
└── test_*.py                 # Additional component tests
```

**Modern Testing Features:**
- **pytest-asyncio**: Full async test support with proper fixture scoping.
- **Testcontainers**: Real PostgreSQL containers for integration testing.
- **fastapi-testing**: Real FastAPI server instances for API testing (no mocking).
- **psycopg-toolkit**: Real database transactions with proper isolation.
- **Transaction Rollback**: Isolated test transactions for database tests.
- **Fixture Scoping**: Session, function, and module scopes for efficiency.
- **Type Safety**: Proper typing in test functions and fixtures.

**Test-First Development Pattern:**
```python
@pytest.mark.asyncio
async def test_create_oauth_client(
    initialize_authly: Authly,
    test_client_request: OAuthClientCreateRequest,
    transaction_manager: TransactionManager
):
    """Test OAuth client creation with real database integration."""
    async with transaction_manager.transaction() as conn:
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        client_service = ClientService(client_repo, scope_repo)
        
        created_client = await client_service.create_client(test_client_request)
        
        assert created_client.client_name == test_client_request.client_name
        assert created_client.client_secret is not None
```

**Testing Requirements for New Features:**
1.  **Repository Layer**: Must have integration tests with real database.
2.  **Service Layer**: Must have business logic tests with real dependencies.
3.  **API Layer**: Must have endpoint tests with real HTTP requests.
4.  **Error Handling**: Must test both success and failure scenarios.
5.  **Security**: Must test authentication, authorization, and input validation.

**Testing Commands:**
- `pytest` - Run all tests with async support.
- `pytest tests/test_auth.py -v` - Run specific test file with verbose output.
- `pytest tests/test_oauth_*.py -v` - Run OAuth-specific tests.
- `pytest --cov=src/authly` - Run tests with coverage reporting.

**External Testing Libraries:**
See `EXTERNAL_DESCOPED_LIBRARIES.md` for detailed documentation on:
- **psycopg-toolkit**: Database operations, transaction management, repository patterns.
- **fastapi-testing**: API testing, async server lifecycle, real-world integration patterns.

## 5. OAuth 2.1 Implementation - COMPLETED ✅

**Current Status**: Complete OAuth 2.1 implementation with 100% test coverage (265/265 tests passing).

### ✅ FULLY IMPLEMENTED FEATURES

**OAuth 2.1 Core Implementation:**
- ✅ Complete OAuth 2.1 authorization server with PKCE support.
- ✅ Authorization code flow with consent management.
- ✅ Token exchange endpoint with client authentication.
- ✅ OAuth discovery endpoint (.well-known/oauth-authorization-server).
- ✅ Token revocation endpoint with proper cleanup.
- ✅ OAuth scope management and validation.
- ✅ OAuth client registration and management.
- ✅ Professional OAuth UI with accessibility support.
- ✅ Backward compatibility with password grant authentication.

**Admin System with Two-Layer Security:**
- ✅ Bootstrap system solving IAM chicken-and-egg paradox.
- ✅ Intrinsic admin authority via database-level is_admin flag.
- ✅ Admin API with localhost restriction and runtime configuration.
- ✅ Admin CLI for OAuth client and scope management.
- ✅ Admin scopes for fine-grained administrative permissions.
- ✅ Environment-based middleware security (no caching issues).

**Production-Ready Features:**
- ✅ Multi-stage Docker build with security hardening.
- ✅ Production entry point with lifespan management.
- ✅ Comprehensive logging and monitoring.
- ✅ Health check endpoints.
- ✅ Static file serving for OAuth UI.
- ✅ Template rendering with Jinja2.

### 🧪 TEST EXCELLENCE ACHIEVED

**265/265 Tests Passing (100% Success Rate):**
- ✅ Real integration testing with PostgreSQL testcontainers.
- ✅ No mocking - authentic database and HTTP testing.
- ✅ Systematic test isolation with transaction management.
- ✅ OAuth flow end-to-end testing.
- ✅ Admin API comprehensive testing.
- ✅ Security and error handling testing.
- ✅ Performance and scalability testing.

**Key Testing Achievements:**
- ✅ Fixed environment variable caching root cause in middleware.
- ✅ Resolved test isolation issues across admin and bootstrap systems.
- ✅ Implemented proper transaction rollback handling.
- ✅ Achieved perfect test reliability and reproducibility.

### 📋 NEXT PHASE RECOMMENDATIONS

**Phase 2: API-First CLI Migration (Optional)**
- Create AdminAPIClient for HTTP-based CLI operations.
- Add CLI authentication commands (login/logout/whoami).
- Migrate CLI from direct database access to HTTP API calls.
- Implement enhanced security features.

**Phase 3: OIDC Implementation (Recommended)**
- Implement OpenID Connect layer on OAuth 2.1 foundation.
- Add ID token generation with claims processing.
- Implement UserInfo endpoint and discovery enhancements.
- Target: Complete OIDC 1.0 compliance.

**Quality Standards Maintained**: 100% test pass rate, comprehensive database integration testing, security-first design patterns, production-ready architecture.

## 6. CLI Memories

## 7. File and Folder Intentions

### Core Application Files
- **`src/authly/main.py`**: Production entry point with FastAPI app factory, lifespan management, middleware setup, and signal handling.
- **`src/authly/authly.py`**: Singleton resource manager for database pools and configuration with thread-safe initialization.
- **`src/authly/__init__.py`**: Public API exports for library usage with async generators and context managers.

### Admin System (`src/authly/admin/`)
- **Purpose**: Command-line interface for OAuth 2.1 administration using direct database access.
- **`cli.py`**: Main CLI entry point with Click commands, global options, and status reporting.
- **`context.py`**: Admin context providing database connections and configuration for CLI operations.
- **`client_commands.py`**: OAuth client management commands (create, list, update, delete, associate scopes).
- **`scope_commands.py`**: OAuth scope management commands (create, list, update, delete).
- **Note**: CLI currently uses direct database access (not HTTP API) - potential Phase 2 migration target.

### API Layer (`src/authly/api/`)
- **Purpose**: HTTP API endpoints, middleware, and dependencies for OAuth 2.1 and admin operations.
- **`admin_router.py`**: Admin API endpoints for OAuth management with localhost security restrictions.
- **`admin_middleware.py`**: Runtime security enforcement reading environment variables at request time (not import time).
- **`admin_dependencies.py`**: Two-layer security model combining intrinsic authority (is_admin flag) with OAuth scopes.
- **`oauth_router.py`**: Complete OAuth 2.1 endpoints including authorization, token exchange, discovery, and revocation.
- **`auth_router.py`**: Authentication endpoints supporting both password grant and OAuth token operations.
- **`auth_dependencies.py`**: JWT validation with OAuth scope extraction and comprehensive security checks.
- **`users_router.py`**: User management REST API with proper CRUD operations and permissions.
- **`health_router.py`**: Health check endpoints for monitoring and deployment verification.
- **`rate_limiter.py`**: Pluggable rate limiting with in-memory default and Redis production support.

### OAuth 2.1 Implementation (`src/authly/oauth/`)
- **Purpose**: Complete OAuth 2.1 server implementation with repositories, services, and models.
- **`models.py`**: Pydantic models for OAuth clients, scopes, authorization codes with comprehensive validation.
- **`client_repository.py`**: OAuth client database operations with CRUD and association management.
- **`client_service.py`**: OAuth client business logic with validation and secret management.
- **`scope_repository.py`**: OAuth scope database operations with default scope handling.
- **`scope_service.py`**: OAuth scope business logic with validation and client associations.
- **`authorization_code_repository.py`**: PKCE authorization code management with expiration and cleanup.
- **`authorization_service.py`**: OAuth authorization flow orchestration with consent and validation.
- **`discovery_models.py`**: OAuth discovery endpoint metadata models for server capabilities.
- **`discovery_service.py`**: OAuth discovery service providing server metadata and endpoint information.

### Bootstrap System (`src/authly/bootstrap/`)
- **Purpose**: System initialization solving the IAM chicken-and-egg paradox.
- **`admin_seeding.py`**: Creates initial admin user with intrinsic authority and registers admin scopes during startup.
- **Security Strategy**: Admin user has database-level is_admin flag that bypasses OAuth dependency for initial system access.

### Configuration (`src/authly/config/`)
- **Purpose**: Comprehensive configuration management with multiple provider strategies.
- **`config.py`**: Main configuration class with dataclasses, validation, and environment integration.
- **`database_providers.py`**: Database configuration providers supporting multiple connection patterns.
- **`secret_providers.py`**: Strategy pattern for secret management (environment, file, static) with security.
- **`secure.py`**: Encrypted secrets storage with Fernet encryption and automatic memory cleanup.

### Authentication Core (`src/authly/auth/`)
- **Purpose**: Core authentication and cryptographic operations.
- **`core.py`**: JWT creation/validation, password hashing with bcrypt, and OAuth integration.

### Token Management (`src/authly/tokens/`)
- **Purpose**: Token lifecycle management with OAuth integration.
- **`models.py`**: Pydantic token models with enums and validation.
- **`repository.py`**: Token database operations with OAuth client association and JTI tracking.
- **`service.py`**: Token business logic with OAuth scopes, rotation, and revocation.
- **`store/`**: Pluggable storage backends (abstract base class and PostgreSQL implementation).

### User Management (`src/authly/users/`)
- **Purpose**: User account management with role-based access control.
- **`models.py`**: Pydantic user models with admin flags and comprehensive validation.
- **`repository.py`**: User database operations with UUID primary keys and proper indexing.
- **`service.py`**: User business logic layer with password policies and account management.

### OAuth UI (`src/authly/static/` and `src/authly/templates/`)
- **Purpose**: Professional OAuth consent UI with accessibility support.
- **`static/css/style.css`**: Accessible styling for OAuth consent forms.
- **`templates/base.html`**: Base template with proper HTML structure and accessibility.
- **`templates/oauth/authorize.html`**: OAuth authorization consent form with scope display.
- **`templates/oauth/error.html`**: OAuth error display with user-friendly messages.

### Testing Architecture (`tests/`)
- **Purpose**: Comprehensive integration testing with 100% success rate (265/265 tests).
- **`conftest.py`**: Test configuration with real PostgreSQL testcontainers and fixture management.
- **`fixtures/testing/`**: Testing infrastructure with lifecycle management and database setup.
- **`test_admin_*.py`**: Admin API, CLI, and security testing.
- **`test_oauth_*.py`**: OAuth 2.1 flow testing with real authorization and token exchange.
- **`test_auth*.py`**: Authentication, token, and security testing.
- **`test_users*.py`**: User management and repository testing.
- **Testing Philosophy**: Real integration tests with PostgreSQL containers, no mocking, authentic HTTP requests.

### Documentation (`docs/`)
- **Purpose**: Comprehensive project documentation with 11 detailed files.
- **`oauth-2.1-implementation.md`**: Complete OAuth 2.1 feature documentation.
- **`migration-guide.md`**: Detailed guide for migrating from password-only to OAuth 2.1.
- **`api-reference.md`**: Complete API endpoint documentation.
- **`cli-administration.md`**: Admin CLI usage and OAuth management guide.
- **`deployment-guide.md`**: Production deployment instructions and best practices.
- **`security-features.md`**: Security implementation details and threat model.
- **`testing-architecture.md`**: Testing methodology and integration patterns.
- **`*.mmd`**: Mermaid diagrams for OAuth flows, token lifecycle, and user states.

### Deployment and Infrastructure
- **`Dockerfile`**: Multi-stage production Docker build with security hardening and non-root user.
- **`docker/init-db-and-user.sql`**: Complete PostgreSQL schema with OAuth tables and indexes.
- **`examples/authly-embedded.py`**: Production embedded server with database containers.
- **`examples/bruno/`**: Professional API testing collection for OAuth and authentication endpoints.
- **`pyproject.toml`**: Modern Python project configuration with Poetry dependency management.

### Implementation Planning and Analysis
- **`refactoring/FIX_CLI_AND_APP_LIFECYCLE_TODO_FINAL.md`**: Validated implementation status showing Phase 1 complete, Phases 2-3 planned.
- **`FINAL_OAUTH_IMPLEMENTATION_PLAN.md`**: Strategic implementation planning with phase-based approach.
- **`OAUTH_IMPLEMENTATION_LEARNING.md`**: Critical learning patterns and quality standards from implementation.
- **`TODO.md`**: Current task management and implementation priorities.

### Project Files
- **`CHANGELOG.md`**: Version history and release documentation.
- **`README.md`**: Project overview and quick start guide.
- **`CLI_USAGE.md`**: Command-line interface documentation.
- **`EXTERNAL_DESCOPED_LIBRARIES.md`**: External library documentation for psycopg-toolkit and fastapi-testing.

## 8. CLI Memories

### CHANGELOG.md Management Instruction
- When instructed to update CHANGELOG.md, first run `git log` to capture recent changes.
- Systematically review and document changes, ensuring comprehensive coverage of updates.
- Use the `git log` output to inform the CHANGELOG.md update process.
- Maintain a structured and clear format for documenting changes.

### Test Excellence Achievement
- **Root Cause Analysis**: Successfully identified and fixed environment variable caching in admin_middleware.py.
- **Test Isolation**: Resolved database state conflicts between bootstrap and admin dependency fixtures.
- **100% Success Rate**: Achieved 265/265 tests passing through systematic debugging and real integration testing.
- **Quality Standards**: Maintained security-first design with comprehensive error handling and edge case coverage.
