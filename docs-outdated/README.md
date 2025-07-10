# Authly Documentation

Welcome to the comprehensive documentation for Authly, a standalone OAuth 2.1 authorization server with JWT-based authentication, user management, and enterprise-grade security features.

## 🚀 Quick Start

- **[Main README](../README.md)** - Project overview, installation, and quick start guide
- **[OAuth 2.1 Implementation](oauth-2.1-implementation.md)** - Complete technical implementation guide
- **[CLI Administration](cli-administration.md)** - Enterprise-grade command-line interface for OAuth management

## 📚 Documentation Index

### Core Implementation

| Document | Description | Audience |
|----------|-------------|----------|
| **[OAuth 2.1 Implementation](oauth-2.1-implementation.md)** | Comprehensive technical guide covering the complete OAuth 2.1 architecture, security features, and standards compliance that achieved 171/171 tests passing | Developers, Security Engineers |
| **[Testing Architecture](testing-architecture.md)** | Detailed coverage of real-world integration testing philosophy, test organization, and the approach that delivered 100% test success rates | QA Engineers, Developers |
| **[External Libraries Integration](external-libraries.md)** | Integration patterns for psycopg-toolkit and fastapi-testing libraries, including database operations and async testing utilities | Developers, DevOps |

### Administration and Operations

| Document | Description | Audience |
|----------|-------------|----------|
| **[CLI Administration](cli-administration.md)** | Complete guide to the `authly-admin` CLI tool with OAuth client management, scope administration, and automation examples | System Administrators, DevOps |

### Architecture and Flows

#### 🎯 System Architecture

| Document | Diagram | Description |
|----------|---------|-------------|
| **[Component Architecture](component-architecture.md)** | [📊 Architecture Diagram](component-architecture.mmd) | Complete system architecture showing OAuth 2.1 components, services, and data flow |

#### 🔐 Authentication and Authorization Flows

| Document | Diagram | Description |
|----------|---------|-------------|
| **[User Authentication Flow](user-authentication-flow.md)** | [📊 Auth Flow Diagram](user-authentication-flow.mmd) | Multi-grant authentication supporting both password and OAuth authorization code flows |
| **[OAuth Authorization Flow](oauth-authorization-flow.md)** | [📊 OAuth Flow Diagram](oauth-authorization-flow.mmd) | Complete OAuth 2.1 authorization code flow with PKCE implementation |
| **[OAuth Discovery Flow](oauth-discovery-flow.md)** | [📊 Discovery Diagram](oauth-discovery-flow.mmd) | RFC 8414 server discovery and auto-configuration for different client types |

#### 🎫 Token Management

| Document | Diagram | Description |
|----------|---------|-------------|
| **[Token Lifecycle](state-diagram-for-token-lifecycle.md)** | [📊 Token States Diagram](token-lifecycle.mmd) | Enhanced token lifecycle with OAuth revocation, scopes, and PKCE integration |
| **[Token Refresh Flow](token-refresh-flow.md)** | [📊 Refresh Diagram](token-refresh-flow.mmd) | Token refresh mechanics with automatic rotation and security measures |
| **[Logout Flow](logout-flow.md)** | [📊 Logout Diagram](logout-flow.mmd) | Secure logout with token invalidation and session cleanup |

#### 👥 User and Client Management

| Document | Diagram | Description |
|----------|---------|-------------|
| **[User Account State](state-diagram-for-user-account.md)** | [📊 User States Diagram](user-account-state.mmd) | User account lifecycle and state transitions |
| **[User Registration Flow](user-registration-and-verification-flow.md)** | [📊 Registration Diagram](user-registration-and-verification-flow.mmd) | User registration and email verification process |
| **[OAuth Client Management](oauth-client-management-flow.md)** | [📊 Client Management Diagram](oauth-client-management-flow.mmd) | CLI admin interface workflow for OAuth client operations |

## 🎯 Documentation by Use Case

### For Developers

**Getting Started:**
1. [Main README](../README.md) - Project overview and setup
2. [OAuth 2.1 Implementation](oauth-2.1-implementation.md) - Technical architecture
3. [External Libraries Integration](external-libraries.md) - Development patterns
4. [Testing Architecture](testing-architecture.md) - Testing approach

**API Integration:**
- [User Authentication Flow](user-authentication-flow.md) - Implement authentication
- [OAuth Authorization Flow](oauth-authorization-flow.md) - OAuth 2.1 integration
- [Token Lifecycle](state-diagram-for-token-lifecycle.md) - Token management

### For System Administrators

**Setup and Configuration:**
1. [Main README](../README.md) - Installation and initial setup
2. [CLI Administration](cli-administration.md) - OAuth management tools

**Operations:**
- [OAuth Client Management](oauth-client-management-flow.md) - Client administration
- [OAuth Discovery Flow](oauth-discovery-flow.md) - Server configuration

### For Security Engineers

**Security Analysis:**
1. [OAuth 2.1 Implementation](oauth-2.1-implementation.md) - Security features and compliance
2. [Testing Architecture](testing-architecture.md) - Security testing approach

**Security Flows:**
- [OAuth Authorization Flow](oauth-authorization-flow.md) - PKCE and security measures
- [Token Lifecycle](state-diagram-for-token-lifecycle.md) - Token security and revocation

### For QA Engineers

**Testing Guidance:**
1. [Testing Architecture](testing-architecture.md) - Comprehensive testing approach
2. [External Libraries Integration](external-libraries.md) - Testing patterns and utilities

**Flow Testing:**
- [User Authentication Flow](user-authentication-flow.md) - Authentication testing
- [OAuth Authorization Flow](oauth-authorization-flow.md) - OAuth flow testing

## 🏗️ Architecture Overview

Authly implements a layered architecture with clean separation of concerns:

```
┌─────────────────────────────────────────┐
│              API Layer                  │
│  ┌─────────────┬─────────────────────┐  │
│  │ auth_router │    oauth_router     │  │
│  │             │    users_router     │  │
│  └─────────────┴─────────────────────┘  │
├─────────────────────────────────────────┤
│             Service Layer               │
│  ┌─────────────┬─────────────────────┐  │
│  │ TokenService│   ClientService     │  │
│  │ UserService │   ScopeService      │  │
│  │             │ AuthorizationService│  │
│  └─────────────┴─────────────────────┘  │
├─────────────────────────────────────────┤
│           Repository Layer              │
│  ┌─────────────┬─────────────────────┐  │
│  │UserRepository│  ClientRepository  │  │
│  │TokenRepository│  ScopeRepository  │  │
│  └─────────────┴─────────────────────┘  │
├─────────────────────────────────────────┤
│           Database Layer                │
│        PostgreSQL + psycopg            │
└─────────────────────────────────────────┘
```

## 📊 Key Metrics and Achievements

### Test Coverage and Quality
- **171/171 Tests Passing** (100% success rate)
- **97.8% Code Coverage** across all modules
- **Real-World Integration Testing** with PostgreSQL and FastAPI

### OAuth 2.1 Compliance
- **Full RFC Compliance** - RFC 6749, 7636, 7009, 8414, 8252
- **Mandatory PKCE** for all authorization code flows
- **Standards-Compliant Security** - No implicit flow, short authorization codes

### Performance and Scalability
- **Async Architecture** with connection pooling
- **Efficient Database Queries** with proper indexing
- **CLI Administration** for enterprise deployment

## 🔧 Development Tools

### CLI Administration
The `authly-admin` CLI provides comprehensive OAuth 2.1 management:

```bash
# Client management
authly-admin client create --name "Web App" --type confidential
authly-admin client list --output json

# Scope management  
authly-admin scope create --name "read" --description "Read access" --default
authly-admin scope list

# System status
authly-admin status --verbose
```

### Testing Commands
```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/test_oauth_*.py -v

# Run with coverage
pytest --cov=src/authly --cov-report=html
```

### Code Quality
```bash
# Linting and formatting
poetry run ruff check
poetry run black .
poetry run isort .
poetry run flake8
```

## 📝 Contributing to Documentation

### Documentation Standards
- **Consistent Format**: Use standard headers and cross-references
- **Code Examples**: Include working examples for all major features
- **Diagrams**: Maintain standalone .mmd files for all visual documentation
- **Audience-Specific**: Tailor content to specific user roles

### Adding New Documentation
1. **Create Feature Documentation** in `docs/feature-name.md`
2. **Add Diagrams** as `docs/feature-name.mmd` files
3. **Update This Index** with appropriate categorization
4. **Cross-Reference** from related documents

### Documentation Workflow
1. Follow established patterns from existing documentation
2. Include practical examples and use cases
3. Maintain links between related documents
4. Update this index when adding new documentation

## 🔗 External Resources

### Standards and RFCs
- [OAuth 2.1 Authorization Framework (Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-09)
- [RFC 7636: PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 7009: Token Revocation](https://tools.ietf.org/html/rfc7009)
- [RFC 8414: Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)

### External Libraries
- [psycopg-toolkit](https://github.com/descoped/psycopg-toolkit) - Enhanced PostgreSQL operations
- [fastapi-testing](https://github.com/descoped/fastapi-testing) - Async FastAPI testing utilities

---

## 📞 Support and Questions

For questions about implementation details, security considerations, or deployment guidance:

1. **Review Relevant Documentation** - Use this index to find specific guides
2. **Check Architecture Diagrams** - Visual documentation for system understanding  
3. **Examine Test Examples** - See [Testing Architecture](testing-architecture.md) for patterns
4. **CLI Help** - Use `authly-admin --help` for command-line assistance

This documentation represents the complete implementation journey of Authly's OAuth 2.1 compliance, providing both high-level guidance and detailed technical implementation details for all stakeholders.