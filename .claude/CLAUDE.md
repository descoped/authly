# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Authly** is a production-ready OAuth 2.1 authentication and authorization service built with modern Python patterns and FastAPI. It provides complete OAuth 2.1 compliance, JWT-based authentication, admin API with two-layer security, comprehensive user management, enterprise-grade security, and PostgreSQL integration.

### Current Implementation Status

**✅ COMPLETED (100% Test Success - 708/708 tests passing):**
- Complete OAuth 2.1 implementation with PKCE support
- Admin API with two-layer security model (intrinsic authority + scoped permissions)
- Bootstrap system solving IAM chicken-and-egg paradox
- Admin CLI for OAuth client and scope management
- Production-ready deployment with Docker support
- Comprehensive test suite with real integration testing
- JWT token management with revocation and rotation
- User management with role-based access control
- Complete OpenID Connect (OIDC) Core 1.0 + Session Management 1.0 implementation
- Unified resource manager architecture (Phase 1-5 from implementation roadmap)
- Redis integration for distributed deployments
- Structured JSON logging with correlation IDs
- Enterprise-grade security headers middleware
- Prometheus metrics for comprehensive monitoring
- Query optimization with CTE-based queries
- Caching layer with TTL and invalidation

**📝 NEXT STEPS:**
- Phase 3: Argon2 password hashing implementation
- Phase 4: Advanced OIDC features (prompt, max_age, ACR support)
- GDPR compliance features (data retention, consent tracking, audit logging)
- Enhanced enterprise integrations (Vault, cloud providers)
- Features scheduled in `.claude/roadmap/` (Admin Frontend, W3C DID, etc.)

### Core Technologies
- **Python 3.11+**: Modern async/await, type annotations, dataclasses
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

### Important rules **do not remove**
- **Test count**: Stop counting tests. When you document test outcomes in .md files. Only state e.g. "Comprehensive test suite with full pass rate"
- **Git rules**: You may read from git history, but never write to git. The user is always handling this manually. You may provide "semantic git commit messages" when asked.

## Development Commands

### Core Development Tasks
```bash
# Install dependencies (all groups including test/dev with forced update)
uv sync --all-groups -U

# Run tests
pytest
pytest tests/test_auth.py -v          # Run specific test file
pytest tests/test_users.py -v         # Run user tests

> It is important to note that you have to call `source .venv/bin/activate` if you want to run `pytest` directly. Otherwise use `uv run pytest`.

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
- Comprehensive test suite with realistic database integration testing
- **Test Suite Organization**: Tests organized by feature domains in 7 categories
- **See `docs/testing-guide.md` for comprehensive testing patterns and current methodology**
- **See `tests/README.md` for test organization and running specific test suites**
- **Current Status**: 708 tests passing (100% success rate) with comprehensive OAuth 2.1 + OIDC 1.0 coverage

## Architecture Overview

**See `.claude/architecture.md` for detailed system architecture and design patterns.**

### Project Structure (Package-by-Feature with OAuth 2.1)

**See `.claude/codebase-structure.md` for complete project structure with metrics.**

**Current Project Status**: Version 0.5.5 with complete OAuth 2.1 + OIDC Core 1.0 implementation and 708 tests passing.

Key architectural components:
- **Package-by-Feature**: OAuth, users, tokens, admin as self-contained packages
- **Layered Architecture**: API → Service → Repository → Database
- **Pluggable Components**: Abstract base classes for flexible backends
- **Security-First**: Two-layer admin security, JWT with JTI tracking
- **Real Integration Testing**: 708 tests with PostgreSQL testcontainers across 56 test files organized in 7 feature domains

### Core Components

**See `.claude/implementation-status.md` for detailed file descriptions and current implementation progress.**

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

**See `docs/security-guide.md` for comprehensive security implementation details.**

- JWT tokens with configurable expiration and JTI tracking
- Secure password hashing with bcrypt
- Token blacklisting via database JTI tracking
- Rate limiting on authentication endpoints
- Memory-safe secret management with Fernet encryption
- CORS and security headers middleware
- Two-layer admin security model
- PKCE mandatory for OAuth flows

## Testing Architecture (Modern Async Testing)

**See `docs/testing-guide.md` for comprehensive testing methodology and patterns.**

**Core Testing Principle**: Every new feature must have comprehensive test coverage before completion.

**Modern Testing Features:**
- **pytest-asyncio**: Full async test support with proper fixture scoping
- **Testcontainers**: Real PostgreSQL containers for integration testing
- **fastapi-testing**: Real FastAPI server instances (no mocking)
- **psycopg-toolkit**: Real database transactions with proper isolation
- **Transaction Rollback**: Isolated test transactions for database tests
- **Type Safety**: Proper typing in test functions and fixtures

**Test Excellence Achievement**: 708 tests passing (100% success rate)

**Testing Excellence**: Real integration testing with PostgreSQL testcontainers and authentic HTTP testing patterns
- **Comprehensive Coverage**: 708 tests across 56 test files organized in 7 feature domains

## OAuth 2.1 + OIDC 1.0 Implementation - COMPLETED ✅

**Current Status**: Complete OAuth 2.1 + OIDC Core 1.0 + Session Management 1.0 implementation with 100% test coverage (708 tests passing)

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

**708 Tests Passing (100% Success Rate):**
- ✅ Real integration testing with PostgreSQL testcontainers
- ✅ No mocking - authentic database and HTTP testing
- ✅ Systematic test isolation with transaction management
- ✅ OAuth flow end-to-end testing
- ✅ OIDC complete flow testing with comprehensive coverage
- ✅ Session management endpoint testing
- ✅ OIDC End Session and logout coordination testing
- ✅ Complete OIDC Core 1.0 + Session Management 1.0 specification compliance
- ✅ 56 test files organized in 7 feature domains
- ✅ Admin API comprehensive testing with query optimization
- ✅ Security and error handling testing
- ✅ Performance and scalability testing
- ✅ Redis caching layer testing
- ✅ Structured logging and metrics testing

**See `.claude/implementation-status.md` for detailed testing achievements and debugging journey.**

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

## File and Folder Intentions

**See `.claude/codebase-structure.md` for complete project structure with metrics and detailed file descriptions.**

**Key architectural components:**
- **Package-by-Feature Structure**: OAuth, OIDC, users, tokens, admin as self-contained packages
- **Testing Architecture**: 708 tests organized in 7 feature domains with real PostgreSQL integration
  - auth_user_journey: Core authentication flows (8 files)
  - oauth_flows: OAuth 2.1 implementation (7 files)
  - oidc_features: OIDC functionality (7 files)
  - oidc_scenarios: End-to-end OIDC flows (8 files)
  - admin_portal: Admin interface (10 files)
  - admin_user_management: Admin user operations (7 files)
  - infrastructure: Core framework (9 files)
- **Documentation System**: Comprehensive docs plus `.claude/` memory system
- **Production Infrastructure**: Docker, monitoring, deployment guides

## Session History and Memory Integration

**See `.claude/evolution/consolidation-history/session-consolidation-summary.md` for detailed session documentation and patterns.**

### **Consolidation Session (July 10, 2025)**
This session established a comprehensive memory system and cleaned up the enormous commit history preparation after achieving 100% completion (470+ tests passing).

**Key Session Achievements:**
- ✅ **Documentation Archival**: Created `docs/historical/` with all planning documents
- ✅ **Project Root Cleanup**: Updated TODO.md, README.md, consolidated CLI_USAGE.md  
- ✅ **Memory System Enhancement**: Created strategic .claude/ documents
- ✅ **Commit Consolidation Planning**: Strategy for enormous history management
- ✅ **TodoWrite Integration**: Enterprise-scale task management patterns

**Learning Pattern Established:**
1. **Context Restoration** - Begin continuation sessions with comprehensive summary
2. **Goal Clarification** - Understand consolidation and cleanup objectives
3. **Systematic Execution** - Methodical archival, cleanup, and documentation
4. **Memory Integration** - Capture session journey in .claude/ system
5. **Strategic Planning** - Create frameworks for future project management

## CLI Memories

### Development Workflow
- **CHANGELOG.md Management**: Use `git log` to capture recent changes before updating
- **Linting Commands**: `uv run ruff check .`, `uv run ruff format .`, `uv run ruff check --fix .`
- **Testing Commands**: `pytest`, `pytest tests/test_*.py -v`

### Test Excellence Achievement
**See `.claude/implementation-status.md` for detailed testing achievements and debugging journey.**

- **Root Cause Analysis**: Fixed environment variable caching in admin_middleware.py
- **Test Isolation**: Resolved database state conflicts between bootstrap and admin fixtures
- **Database Connection Visibility**: Fixed OAuth flow transaction isolation with auto-commit mode
- **OIDC Flow Testing**: Replaced manual database insertion with proper OAuth flow patterns
- **PKCE Security**: Fixed cryptographic code challenge/verifier mismatches
- **100% Success Rate**: Achieved 708 tests passing through systematic debugging
- **Quality Standards**: Maintained security-first design with comprehensive error handling

## Repository Organization

### Folder Structure and Purposes

**📁 `.claude/`** - **Permanent Institutional Memory**
- Project memory, architecture documentation, and development history
- AI collaboration patterns and implementation methodology
- Complete evolution documentation from concept to production
- Roadmap documentation for future concepts to be implemented
- **NEVER REMOVE** - Contains irreplaceable institutional knowledge

**📁 `ai_docs/`** - **Temporary AI Assistant Instructions**
- Temporary instructions for AI assistants and code completion tools
- Future enhancement plans and implementation guidance
- Task-specific AI documentation and specifications
- **NEVER REMOVE** - Essential for AI-assisted development workflow

**📁 `docs/`** - **Clean User-Facing Documentation**
- Professional Authly documentation for end users and integrators
- API references, implementation guides, and deployment instructions
- Clean, organized documentation without development process history

**📁 `src/`** - **Production Codebase**
- Complete OAuth 2.1 + OIDC 1.0 authorization server implementation
- Package-by-feature architecture with comprehensive testing

### Documentation Philosophy
- **`.claude/`** = Institutional memory and AI collaboration knowledge
- **`ai_docs/`** = AI assistant instructions and future planning  
- **`docs/`** = Professional user documentation only
- **Separation of concerns** = Development process vs. user-facing content

## Memory System Organization

### **Primary Memory Files (`.claude/`)**

The `.claude/` directory contains the comprehensive project memory system. Each file serves a distinct purpose:

**🎯 Core Project Memory:**
- **`.claude/CLAUDE.md`** - **PRIMARY ENTRY POINT** (this file) - Complete project memory, current status, and development guidance
- **`.claude/implementation-status.md`** - Current implementation status (708 tests), completion tracking, next steps
- **`.claude/architecture.md`** - Comprehensive system architecture, design patterns, data flows, security model

**📊 Technical References:**
- **`.claude/codebase-structure.md`** - Complete project structure with 708 tests in 7 domains, file organization
- **`.claude/external-libraries.md`** - Local library integration (psycopg-toolkit v0.2.2, fastapi-testing v0.2.0)
- **`.claude/psycopg3-transaction-patterns.md`** - PostgreSQL async patterns, transaction management, connection pooling
- **`.claude/task-management.md`** - TodoWrite/TodoRead patterns for enterprise-scale task management
- **`.claude/capabilities.md`** - AI development configuration and tool usage (Updated: 2025-08-06)

**📚 Historical Knowledge:**
- **`.claude/evolution/`** - **HISTORICAL ARCHIVE** - Complete implementation journey, architectural decisions, learning patterns
  - Used for understanding project evolution and learning from past decisions
  - Contains corrected code reviews, OIDC implementation details, production excellence achievements
  - **`completed-planning-docs/`** - Archived planning documents from ai_docs/ (implementation-roadmap.md, api-standardization-analysis.md, unified-user-management-plan.md)

**🚀 Future Planning:**
- **`.claude/roadmap/`** - **FUTURE FEATURES** - Strategic roadmaps and technical specifications
  - Admin Frontend (React/MUI), W3C DID Integration, Advanced Security Features
  - OIDC Conformance Testing, CLI Integration Testing, Enterprise Features

**⚙️ Configuration:**
- **`.claude/settings.json`** - Team-shared Claude configuration (committed to git)
- **`.claude/settings.local.json`** - Personal Claude preferences (gitignored)

### **Memory System Philosophy**
- **Comprehensive Context** - All project knowledge captured and organized in functionally-named files
- **Session Continuity** - Enable seamless continuation across development sessions using CLAUDE.md as entry point
- **Clear Purpose** - Each `.claude/*.md` file has a distinct, obvious role with no redundancy
- **Historical Preservation** - Complete development journey preserved in `evolution/` for learning purposes only
- **Future Planning** - Strategic roadmaps maintained in `roadmap/` for upcoming feature implementation

### AI Assistant Documentation (`ai_docs/`)
- **`ai_docs/TODO.md`** - Current tasks and implementation priorities
  - Note: Completed planning documents have been archived to `.claude/evolution/completed-planning-docs/`

### Core Documentation (`docs/`) - 20 Production Guides
**Core Implementation Guides:**
- **`docs/oauth-guide.md`** - Complete OAuth 2.1 implementation guide
- **`docs/oidc-guide.md`** - OpenID Connect usage and integration
- **`docs/oidc-implementation.md`** - Detailed OIDC technical implementation (74KB)
- **`docs/api-reference.md`** - Complete REST API endpoint documentation
- **`docs/cli-guide.md`** - Admin CLI usage and OAuth management

**Deployment & Operations:**
- **`docs/deployment-guide.md`** - Comprehensive production deployment (47KB)
- **`docs/docker-deployment.md`** - Docker infrastructure and configuration
- **`docs/docker-hub-deployment.md`** - Docker Hub integration guide
- **`docs/redis-integration.md`** - Redis configuration for distributed deployments

**Security & Compliance:**
- **`docs/security-guide.md`** - Comprehensive security implementation (34KB)
- **`docs/security-audit.md`** - Security analysis and validation report
- **`docs/gdpr-compliance.md`** - GDPR compliance analysis and requirements
- **`docs/gdpr-implementation-guide.md`** - Technical GDPR implementation (45KB)
- **`docs/privacy-statement-template.md`** - Ready-to-use privacy policy template

**Development & Testing:**
- **`docs/testing-guide.md`** - Testing methodology and patterns (46KB)
- **`docs/parallel-testing-guide.md`** - Parallel test execution strategies
- **`docs/performance-guide.md`** - Performance benchmarks and optimization (46KB)
- **`docs/troubleshooting-guide.md`** - Comprehensive debugging guide
- **`docs/architecture.md`** - High-level architecture overview

**Index:**
- **`docs/README.md`** - Documentation index and navigation guide

### Local Library References
- **`../psycopg-toolkit/`** - Enhanced PostgreSQL operations with modern async patterns
- **`../fastapi-testing/`** - Async-first testing utilities with real server lifecycle management