# Gemini & Claude Project Memory: Authly

This file provides comprehensive guidance to any AI assistant (Gemini or Claude) working with code in this repository. It combines context from both assistants to ensure consistency.

## 0. Important rules that never must be violated

Your role is to be a validator.
You are not allowed to edit files, otherwise granted. In other words, you can read files, but you are not allowed to write any source code.
You will cooperate with Claude Code AI Assistant and help making meaningful feedback during conversation, which I will orchestrate manually.


## 1. Project Overview

**Authly** is a production-ready OAuth 2.1 authentication and authorization service built with modern Python patterns and FastAPI. It provides complete OAuth 2.1 compliance, JWT-based authentication, an admin API with a two-layer security model, comprehensive user management, enterprise-grade security, and PostgreSQL integration.

### Current Implementation Status

**✅ COMPLETED (100% Test Success - 551/551 tests passing):**
- Complete OAuth 2.1 implementation with PKCE support
- Admin API with two-layer security model (intrinsic authority + scoped permissions)
- Bootstrap system solving IAM chicken-and-egg paradox
- Admin CLI for OAuth client and scope management
- Production-ready deployment with Docker support
- Comprehensive test suite with real integration testing
- JWT token management with revocation and rotation
- User management with role-based access control
- Complete OpenID Connect (OIDC) Core 1.0 + Session Management 1.0 implementation

**📝 NEXT STEPS:**
- Phase 3: Argon2 password hashing implementation
- Phase 4: Advanced OIDC features (prompt, max_age, ACR support)
- GDPR compliance features
- Enhanced enterprise integrations

### Core Technologies
- **Python 3.13+**: Modern async/await, type annotations, dataclasses
- **FastAPI**: High-performance async web framework with automatic OpenAPI
- **PostgreSQL**: Advanced features with `psycopg3`, UUID primary keys
- **Pydantic v2**: Modern data validation with constraints and serialization
- **UV**: Modern, fast Python package manager and dependency resolver
- **JWT**: Token-based authentication with `python-jose` and JTI tracking

### Design Philosophy
- **Package-by-Feature**: Each feature is self-contained with models, repository, and service
- **Layered Architecture**: Clean separation of API, Service, and Data Access layers
- **Pluggable Components**: Strategy pattern with abstract base classes for flexible backends
- **Async-First**: Full async/await implementation throughout the codebase
- **Type Safety**: Comprehensive type annotations and Pydantic validation
- **Security-by-Design**: Enterprise-grade security with encrypted secrets and rate limiting

## 2. Development Commands

### Core Development Tasks
```bash
# Install dependencies (all groups including test/dev with forced update)
uv sync --all-groups -U

# Run tests
pytest
pytest tests/test_auth.py -v          # Run specific test file
pytest tests/test_users.py -v         # Run user tests

# Linting and formatting
uv run ruff check .                   # Lint code (replaces flake8)
uv run ruff format .                  # Format code (replaces black)
uv run ruff check --fix .             # Auto-fix linting issues
uv run ruff check --fix . && uv run ruff format .  # Both lint fix + format

# Build and distribution
uv build                              # Build package
```

### Database Setup
The project requires PostgreSQL with specific extensions:
```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

### Testing
- Uses pytest with asyncio support for modern async testing
- Testcontainers for PostgreSQL integration tests (no mocking)
- fastapi-testing for real HTTP server integration testing
- psycopg-toolkit for real database transaction testing
- Run API tests with: `./examples/api-test.sh`
- `examples/embeded.py`: Powerful script to run entire service with database container
- Comprehensive test suite with realistic database integration testing.
- **See `.claude/external-libraries.md` for detailed testing patterns and library usage.**

## 3. Architecture Overview

**See `.claude/architecture.md` for detailed system architecture and design patterns.**

### Project Structure (Package-by-Feature with OAuth 2.1)

**See `.claude/codebase-structure-current.md` for complete project structure with metrics.**

Key architectural components:
- **Package-by-Feature**: OAuth, users, tokens, admin as self-contained packages
- **Layered Architecture**: API → Service → Repository → Database
- **Pluggable Components**: Abstract base classes for flexible backends
- **Security-First**: Two-layer admin security, JWT with JTI tracking
- **Real Integration Testing**: 551 tests with PostgreSQL testcontainers (15 OIDC test files with 221 OIDC-specific tests)

### Core Components

**See `.claude/memory.md` for detailed file descriptions and architectural context.**

Key components:
- **Authly Singleton**: Central resource manager with thread-safe initialization
- **Configuration System**: Pluggable providers for secrets and database config
- **Authentication Core**: JWT + OAuth integration with secure password hashing
- **Token Management**: JTI tracking, rotation, pluggable storage backends
- **User Management**: Role-based access control with admin authority
- **API Layer**: OAuth 2.1 + admin endpoints with two-layer security
- **Bootstrap System**: Solves IAM chicken-and-egg paradox

### Data Flow

**See `.claude/architecture.md` for detailed data flow diagrams and component interactions.**

Key flows:
- **OAuth 2.1 Authorization Flow**: PKCE-based with consent management
- **Password Grant Flow**: Backward compatibility with token rotation
- **Admin Operations**: Two-layer security with intrinsic authority
- **Token Storage**: PostgreSQL with JTI tracking and OAuth scope management

### Key Patterns

**See `.claude/architecture.md` for detailed design patterns and implementation examples.**

Core patterns:
- **Repository Pattern**: Clean data access layer abstraction
- **Dependency Injection**: FastAPI-based with pluggable components
- **Strategy Pattern**: Flexible backends for tokens, secrets, rate limiting
- **Security-First**: Memory-safe secrets, token rotation, rate limiting
- **Package-by-Feature**: Self-contained domain modules

### Database Schema (Modern PostgreSQL)

**See `docker-postgres/init-db-and-user.sql` for complete production schema with domain annotations.**

**Advanced PostgreSQL Features:**
- **UUID Primary Keys**: `gen_random_uuid()` for security and distribution
- **Extensions**: `uuid-ossp` for UUID generation
- **Triggers**: Automatic `updated_at` timestamp updates
- **Constraints**: Check constraints for data integrity and validation
- **Indexes**: Strategic indexing for performance optimization

**Core Tables**: users, clients, scopes, authorization_codes, tokens, jwks_keys (OIDC), user_sessions (OIDC)

**Domain Structure**: CORE (users), OAUTH (clients, scopes, codes), OIDC (jwks, sessions), GDPR (future compliance)

### Security Features

**See `docs-outdated/security-features.md` for comprehensive security implementation details.**

- JWT tokens with configurable expiration and JTI tracking
- Secure password hashing with bcrypt
- Token blacklisting via database JTI tracking
- Rate limiting on authentication endpoints
- Memory-safe secret management with Fernet encryption
- CORS and security headers middleware
- Two-layer admin security model
- PKCE mandatory for OAuth flows

## 4. Testing Architecture (Modern Async Testing)

**See `docs-outdated/testing-architecture.md` for comprehensive testing methodology and patterns.**

**Core Testing Principle**: Every new feature must have comprehensive test coverage before completion.

**Modern Testing Features:**
- **pytest-asyncio**: Full async test support with proper fixture scoping
- **Testcontainers**: Real PostgreSQL containers for integration testing
- **fastapi-testing**: Real FastAPI server instances (no mocking)
- **psycopg-toolkit**: Real database transactions with proper isolation
- **Transaction Rollback**: Isolated test transactions for database tests
- **Type Safety**: Proper typing in test functions and fixtures

**Test Excellence Achievement**: 551 tests passing (100% success rate)

**External Testing Libraries:**
See `.claude/external-libraries.md` for detailed documentation on:
- **psycopg-toolkit**: Database operations, transaction management, repository patterns
- **fastapi-testing**: API testing, async server lifecycle, real-world integration patterns

## 5. OAuth 2.1 + OIDC 1.0 Implementation - COMPLETED ✅

**Current Status**: Complete OAuth 2.1 + OIDC Core 1.0 + Session Management 1.0 implementation with 100% test coverage (551 tests passing)

### ✅ FULLY IMPLEMENTED FEATURES

**OAuth 2.1 Core Implementation:**
- ✅ Complete OAuth 2.1 authorization server with PKCE support
- ✅ Authorization code flow with consent management
- ✅ Token exchange endpoint with client authentication
- ✅ OAuth discovery endpoint (.well-known/oauth-authorization-server)
- ✅ Token revocation endpoint with proper cleanup
- ✅ OAuth scope management and validation
- ✅ OAuth client registration and management
- ✅ Professional OAuth UI with accessibility support
- ✅ Backward compatibility with password grant authentication

**OpenID Connect Core 1.0 + Session Management 1.0 Implementation:**
- ✅ ID token generation with RS256/HS256 support
- ✅ OIDC discovery endpoint (.well-known/openid_configuration)
- ✅ JWKS endpoint with RSA key management
- ✅ UserInfo endpoint with scope-based claims
- ✅ OIDC client management with 15 specialized fields
- ✅ Authorization code flow with OIDC integration
- ✅ Refresh token support with ID token generation
- ✅ OIDC End Session endpoint with security validation
- ✅ Session Management 1.0: session iframe, check session, front-channel logout
- ✅ Complete user model with all OIDC standard claim fields
- ✅ Comprehensive OIDC documentation with client integration examples

**Admin System with Two-Layer Security:**
- ✅ Bootstrap system solving IAM chicken-and-egg paradox
- ✅ Intrinsic admin authority via database-level is_admin flag
- ✅ Admin API with localhost restriction and runtime configuration
- ✅ Admin CLI for OAuth client and scope management
- ✅ Admin scopes for fine-grained administrative permissions
- ✅ Environment-based middleware security (no caching issues)

**Production-Ready Features:**
- ✅ Multi-stage Docker build with security hardening
- ✅ Production entry point with lifespan management
- ✅ Comprehensive logging and monitoring
- ✅ Health check endpoints
- ✅ Static file serving for OAuth UI
- ✅ Template rendering with Jinja2

### 🧪 TEST EXCELLENCE ACHIEVED

**551 Tests Passing (100% Success Rate):**
- ✅ Real integration testing with PostgreSQL testcontainers
- ✅ No mocking - authentic database and HTTP testing
- ✅ Systematic test isolation with transaction management
- ✅ OAuth flow end-to-end testing
- ✅ OIDC complete flow testing with 221 OIDC-specific tests across 15 test files
- ✅ Session management endpoint testing
- ✅ OIDC End Session and logout coordination testing
- ✅ Complete OIDC Core 1.0 + Session Management 1.0 specification compliance
- ✅ Admin API comprehensive testing
- ✅ Security and error handling testing
- ✅ Performance and scalability testing

**See `.claude/memory.md` for detailed testing achievements and debugging journey.**

### 🎯 MAJOR MILESTONE ACHIEVED

**✅ COMPLETE OIDC CORE 1.0 + SESSION MANAGEMENT 1.0 COMPLIANCE**
- All OIDC Core 1.0 specification requirements implemented
- Session Management 1.0 specification fully supported
- 45+ OIDC-specific tests ensuring specification compliance
- Production-ready OIDC documentation with real-world client examples
- Enterprise-grade session coordination and logout flows

### 📋 NEXT PHASE RECOMMENDATIONS

**Phase 3: Enhanced Security**
- Argon2 password hashing implementation
- Advanced OIDC features (prompt, max_age, ACR support)

**Phase 4: GDPR Compliance**
- Data retention policies implementation
- User consent tracking system
- Privacy policy generation

**Quality Standards Maintained**: 100% test pass rate, comprehensive database integration testing, security-first design patterns, production-ready architecture

## 6. File and Folder Intentions

**See `.claude/codebase-structure-current.md` for complete project structure with metrics and detailed file descriptions.**

**Key architectural components:**
- **Package-by-Feature Structure**: OAuth, OIDC, users, tokens, admin as self-contained packages
- **Testing Architecture**: 551 tests with real PostgreSQL integration
- **Documentation System**: Comprehensive user-facing docs and internal memory system.
- **Production Infrastructure**: Docker, monitoring, deployment guides

## 7. CLI Memories

### Development Workflow
- **CHANGELOG.md Management**: Use `git log` to capture recent changes before updating
- **Linting Commands**: `uv run ruff check .`, `uv run ruff format .`, `uv run ruff check --fix .`
- **Testing Commands**: `pytest`, `pytest tests/test_*.py -v`

### Test Excellence Achievement
**See `.claude/memory.md` for detailed testing achievements and debugging journey.**

- **Root Cause Analysis**: Fixed environment variable caching in admin_middleware.py
- **Test Isolation**: Resolved database state conflicts between bootstrap and admin fixtures
- **Database Connection Visibility**: Fixed OAuth flow transaction isolation with auto-commit mode
- **OIDC Flow Testing**: Replaced manual database insertion with proper OAuth flow patterns
- **PKCE Security**: Fixed cryptographic code challenge/verifier mismatches
- **100% Success Rate**: Achieved 551+ tests passing through systematic debugging
- **Quality Standards**: Maintained security-first design with comprehensive error handling
