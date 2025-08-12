# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Authly** is an OAuth 2.1 and OpenID Connect authorization server in active development. It provides JWT-based authentication, admin API with two-layer security, user management, and PostgreSQL integration. The project aims for standards compliance but is currently a work in progress.

**Version**: 1.0.0-dev  
**Status**: Development/Testing - Not Production Certified  
**Last Updated**: 2025-08-12

### Current Implementation Status

**✅ IMPLEMENTED FEATURES:**
- OAuth 2.1 implementation with mandatory PKCE support
- OAuth 2.0 Token Introspection (RFC 7662) for resource server validation
- Admin API with two-layer security model (intrinsic authority + scoped permissions)
- Bootstrap system solving IAM chicken-and-egg paradox
- Admin CLI for OAuth client and scope management
- Docker support for development and testing (standalone and compose modes)
- JWT token management with revocation and rotation
- User management with role-based access control
- OpenID Connect (OIDC) Core 1.0 basic implementation
- Redis integration for distributed deployments
- Structured JSON logging with correlation IDs
- Security headers middleware
- Prometheus metrics for monitoring
- Docker standalone deployment with embedded PostgreSQL and Redis
- OAuth 2.1 Compliance Testing Suite (browser-based)
- OIDC Debugger Integration

**⚠️ KNOWN LIMITATIONS:**
- OIDC conformance: 100% specification compliance achieved (not officially certified)
- UserInfo endpoint doesn't support POST method (GET only)
- Not all OIDC test scenarios implemented
- Performance optimization ongoing
- Some edge cases in OAuth flows not fully tested
- Rate limiting middleware in development
- CORS configuration being refined

**📝 WORK IN PROGRESS:**
- Full OIDC certification compliance
- Argon2 password hashing implementation
- Advanced OIDC features (prompt, max_age, ACR support)
- GDPR compliance features
- Enterprise integrations
- Comprehensive error handling improvements
- OAuth 2.1 compliance tester enhancements
- Browser-based login UI implementation
- Rate limiting refinements

### Core Technologies
- **Python 3.11+**: Modern async/await, type annotations, dataclasses
- **FastAPI**: High-performance async web framework with automatic OpenAPI
- **PostgreSQL**: Advanced features with `psycopg3`, UUID primary keys
- **Pydantic v2**: Modern data validation with constraints and serialization
- **UV**: Modern, fast Python package manager and dependency resolver
- **JWT**: Token-based authentication with `python-jose` and JTI tracking
- **Docker**: Multi-stage builds, compose orchestration, standalone images
- **Redis**: Optional caching and session storage
- **psycopg-toolkit**: Enhanced PostgreSQL operations (local development)
- **fastapi-testing**: Async-first testing utilities (local development)

### Design Philosophy
- **Package-by-Feature**: Each feature is self-contained with models, repository, and service
- **Layered Architecture**: Clean separation of API, Service, and Data Access layers
- **Pluggable Components**: Strategy pattern with abstract base classes for flexible backends
- **Async-First**: Full async/await implementation throughout the codebase
- **Type Safety**: Comprehensive type annotations and Pydantic validation
- **Security-by-Design**: Enterprise-grade security with encrypted secrets and rate limiting

### Important Rules - DO NOT REMOVE

**CRITICAL: These rules ensure accurate and honest communication about the project:**

1. **No Production Claims**: NEVER claim the system is "production-ready" or "fully compliant" until it achieves 100% certification test coverage. The system is a work in progress.

2. **Source Code is Truth**: Only make claims that can be verified in the source code. If tests fail or features are incomplete, acknowledge this honestly.

3. **Accurate Test Reporting**: When documenting test outcomes:
   - State actual numbers if all pass (e.g., "708/708 tests passing")
   - If any fail, state "Test suite with X failures" or similar
   - Never hide or obscure test failures

4. **Compliance Honesty**: 
   - Current OIDC compliance: 100% (all 40 conformance checks passing, not officially certified)
   - OAuth 2.1: Implemented with full error compliance but not officially certified
   - Always clarify this is not officially certified when discussing compliance

5. **Git Rules**: You may read from git history, but never write to git. The user handles this manually. Provide semantic commit messages when asked.

6. **Feature Status Accuracy**: 
   - Mark features as "implemented" only if fully working with tests
   - Mark as "partial" if some aspects work but others don't
   - Mark as "planned" if not yet started
   - Be explicit about known issues and limitations

## Development Commands

### Core Development Tasks
```bash
# Install dependencies (all groups including test/dev with forced update)
uv sync --all-groups -U

# Run tests
pytest
pytest tests/test_auth.py -v          # Run specific test file
pytest tests/test_users.py -v         # Run user tests
pytest tests/oauth_flows/ -v          # Run OAuth test suite
pytest tests/oidc_features/ -v        # Run OIDC test suite

> Note: Run `source .venv/bin/activate` to use `pytest` directly, otherwise use `uv run pytest`

# Linting and formatting
uv run ruff check .                   # Lint code
uv run ruff format .                  # Format code
uv run ruff check --fix .             # Auto-fix linting issues

# Build and distribution
uv build                              # Build package

# Docker operations
make build                            # Build Docker images
make start                            # Start all services
make stop                             # Stop all services
make test                             # Run compliance test suite
```

### Database Setup
The project requires PostgreSQL with specific extensions:
```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

### Testing
- Uses pytest with asyncio support for async testing
- Testcontainers for PostgreSQL integration tests
- Real database transaction testing (no mocking)
- Run API tests with: `./scripts/run-integration-tests.sh`
- Comprehensive test suite organized by feature domains
- Browser-based compliance testing at http://localhost:8080

**Current Test Status**: Core tests passing, ongoing work on edge cases and browser compliance

## Architecture Overview

### Project Structure (Package-by-Feature)
- **Package-by-Feature**: OAuth, users, tokens, admin as self-contained packages
- **Layered Architecture**: API → Service → Repository → Database
- **Pluggable Components**: Abstract base classes for flexible backends
- **Security-First**: Two-layer admin security, JWT with JTI tracking

### Core Components
- **Authly Singleton**: Central resource manager with thread-safe initialization
- **Configuration System**: Pluggable providers for secrets and database config
- **Authentication Core**: JWT + OAuth integration with password hashing
- **Token Management**: JTI tracking, rotation, pluggable storage backends
- **User Management**: Role-based access control with admin authority
- **API Layer**: OAuth 2.1 + admin endpoints with two-layer security
- **Bootstrap System**: Solves IAM chicken-and-egg paradox

### Database Schema
PostgreSQL with modern features:
- UUID Primary Keys for security and distribution
- Triggers for automatic timestamp updates
- Check constraints for data integrity
- Strategic indexing for performance

Core tables: users, clients, scopes, authorization_codes, tokens, jwks_keys, user_sessions

### Security Features
- JWT tokens with configurable expiration and JTI tracking
- Secure password hashing with bcrypt (Argon2 planned)
- Token blacklisting via database JTI tracking
- Rate limiting on authentication endpoints
- Memory-safe secret management with Fernet encryption
- CORS and security headers middleware
- Two-layer admin security model
- PKCE mandatory for OAuth flows

## Current Limitations and Known Issues

### OIDC Conformance (100% Compliant)
**What Works:**
- Discovery endpoints (100% compliant)
- JWKS validation (100% compliant)
- PKCE enforcement with OAuth-compliant errors
- Token endpoint with proper OAuth error format
- Authorization endpoint with correct parameter validation
- Basic UserInfo (GET only)
- Core OAuth flows with specification-compliant error handling

**What Still Needs Work:**
- UserInfo POST method (returns 405)
- Full OAuth flow simulation for testing
- Some advanced OIDC test scenarios not implemented

### Testing Gaps
- Edge cases in OAuth flows
- Error scenario coverage
- Performance under load
- Security penetration testing
- Full end-to-end OIDC certification tests

## Repository Organization

### Folder Structure and Purposes

**📁 `.claude/`** - **Permanent Institutional Memory**
- `CLAUDE.md` - This file, primary project memory
- `architecture.md` - System architecture documentation
- `implementation-status.md` - Current development status
- `codebase-structure.md` - Detailed project structure
- `external-libraries.md` - psycopg-toolkit and fastapi-testing docs
- `capabilities.md` - AI assistant configuration
- `task-management.md` - TodoWrite patterns
- `psycopg3-transaction-patterns.md` - Database patterns
- `evolution/` - Historical implementation journey
- `roadmap/` - Future development plans
- `instructions/` - Development practices and rules
- NEVER REMOVE - Contains project knowledge and context

**📁 `src/authly/`** - **Source Code**
- OAuth 2.1 + OIDC authorization server implementation
- Package-by-feature architecture
- Admin CLI and API implementation
- Authentication and token management

**📁 `tests/`** - **Test Suite**
- `oauth_flows/` - OAuth 2.1 test suite
- `oidc_features/` - OIDC test suite
- `admin_portal/` - Admin interface tests
- `auth_user_journey/` - User authentication tests
- `infrastructure/` - Core infrastructure tests
- Real database integration tests (no mocking)

**📁 `docs/`** - **User Documentation**
- API references, implementation guides
- Deployment and security documentation
- Docker standalone image guide (`docker-standalone.md`)
- Architecture patterns and quick reference

**📁 `docker-standalone/`** - **Docker Infrastructure**
- `authly-compliance-tester/` - Browser-based OAuth/OIDC tester
- `oidc-debugger/` - OIDC debugging interface
- Standalone deployment configurations

**📁 `tck/`** - **Test Conformance Kit**
- OIDC/OAuth conformance testing
- Currently achieves 100% spec compliance (40/40 checks)

**📁 `ai_docs/`** - **AI Development Documentation**
- `TODO.md` - Current tasks and priorities
- Implementation status tracking
- Phase planning documents

**📁 `scripts/`** - **Automation Scripts**
- Integration test runners
- Setup and deployment scripts
- Development utilities

## Development Status Summary

**This is a work-in-progress authorization server:**
- ✅ Core OAuth 2.1 features work with compliant error handling
- ✅ OIDC implementation with 100% conformance (40/40 checks)
- ✅ Browser-based compliance testing suite available
- ✅ Docker standalone deployment with embedded dependencies
- ⚠️ Not ready for production use without thorough testing
- ⚠️ Not officially OIDC certified (but 100% compliant)
- 🚧 Active development ongoing on `feature/odic-debugger` branch

**Recommended Use Cases:**
- Development and testing environments
- Learning OAuth/OIDC implementations
- Prototype applications
- Internal tools with additional testing

**NOT Recommended For:**
- Production systems without extensive testing
- High-security environments without security audit
- Systems requiring certified OIDC compliance

## Contributing Guidelines

When working on this codebase:
1. Be honest about implementation status
2. Document known issues and limitations
3. Write tests for new features
4. Don't claim compliance without verification
5. Follow existing patterns and conventions
6. Update documentation to reflect reality
7. **Follow development practices**: See `.claude/instructions/authly-development-practices.md` for detailed rules

**Key Development Rules:**
- Always use committed fixtures for HTTP tests (no transactions)
- No mocking frameworks - real integration testing only
- Package-by-feature organization for tests
- Always run pytest after code changes
- Use dependency injection patterns

Remember: The source code is the truth. Make claims only about what is actually implemented and tested.

## Quick Reference - Important Files

### Memory System (.claude/)
- **Primary**: `.claude/CLAUDE.md` - This file
- **Architecture**: `.claude/architecture.md` - System design
- **Status**: `.claude/implementation-status.md` - Current progress
- **Structure**: `.claude/codebase-structure.md` - Project layout
- **Libraries**: `.claude/external-libraries.md` - psycopg-toolkit & fastapi-testing
- **Practices**: `.claude/instructions/authly-development-practices.md` - Development rules

### Current Work
- **Tasks**: `ai_docs/TODO.md` - Current priorities
- **Branch**: `feature/odic-debugger` - Active development branch

### Key Source Files
- **App Entry**: `src/authly/__main__.py` - CLI entry point
- **FastAPI App**: `src/authly/app.py` - Application factory
- **OAuth Router**: `src/authly/api/oauth_router.py` - OAuth endpoints
- **OIDC Router**: `src/authly/api/oidc_router.py` - OIDC endpoints
- **Admin CLI**: `src/authly/admin/cli.py` - Admin commands

### Testing
- **OAuth Tests**: `tests/oauth_flows/` - OAuth 2.1 test suite
- **OIDC Tests**: `tests/oidc_features/` - OIDC test suite
- **Fixtures**: `tests/fixtures/committed_data.py` - Test data fixtures
- **Lifespan**: `tests/fixtures/testing/lifespan.py` - Dependency overrides

### Docker & Tools
- **Compliance Tester**: `docker-standalone/authly-compliance-tester/` - Browser testing
- **OIDC Debugger**: `docker-standalone/oidc-debugger/` - OIDC debugging
- **Integration Tests**: `scripts/integration-tests/` - Test runners
- **Makefile**: Root directory - Docker orchestration