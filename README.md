# Authly

[![Build Status](https://github.com/descoped/authly/actions/workflows/build-test-native.yml/badge.svg)](https://github.com/descoped/authly/actions/workflows/build-test-native.yml)
[![Test Status](https://github.com/descoped/authly/actions/workflows/full-stack-test-with-docker.yml/badge.svg)](https://github.com/descoped/authly/actions/workflows/full-stack-test-with-docker.yml)
[![Coverage](https://codecov.io/gh/descoped/authly/branch/master/graph/badge.svg)](https://codecov.io/gh/descoped/authly)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/v/release/descoped/authly)](https://github.com/descoped/authly/releases)

A **production-ready OAuth 2.1 + OpenID Connect 1.0 authorization server** built with FastAPI and PostgreSQL. Authly provides enterprise-grade security, comprehensive testing (510 tests passing), and professional administration tools.

---

## 🚀 **Production Ready Features**

✅ **Complete OAuth 2.1 + OIDC 1.0 Compliance** - Full RFC implementation with PKCE  
✅ **510 Tests Passing** - 100% success rate with real integration testing  
✅ **Enterprise Security** - Two-layer admin system, rate limiting, audit logging  
✅ **Production Architecture** - Docker, monitoring, health checks, deployment guides  
✅ **Professional CLI** - Complete admin interface with API-first architecture  
✅ **Developer Experience** - Comprehensive docs, easy setup, embedded development mode

---

## 🔐 **OAuth 2.1 Authorization Server**

### **Core Authorization Features**
- **Authorization Code Flow** with mandatory PKCE (Proof Key for Code Exchange)
- **Client Management** for confidential and public OAuth clients
- **Token Revocation** (RFC 7009) for immediate token invalidation
- **Server Discovery** (RFC 8414) for automatic client configuration
- **Scope Management** with granular permission control

### **Supported Grant Types**
- **Authorization Code Grant** with PKCE for third-party applications
- **Password Grant** for trusted first-party applications
- **Refresh Token Grant** for token renewal
- **Client Credentials Grant** for service-to-service authentication

### **Security Standards Compliance**
- **RFC 6749** - OAuth 2.0 Authorization Framework ✅
- **RFC 7636** - Proof Key for Code Exchange (PKCE) ✅
- **RFC 7009** - OAuth 2.0 Token Revocation ✅
- **RFC 8414** - OAuth 2.0 Authorization Server Metadata ✅

---

## 🆔 **OpenID Connect 1.0**

### **OIDC Core Features**
- **ID Token Generation** with RS256/HS256 signing algorithms
- **UserInfo Endpoint** with scope-based claims filtering
- **JWKS Endpoint** for token signature verification
- **OIDC Discovery** with provider configuration metadata

### **ID Token Claims**
- **Standard Claims** - sub, aud, iss, exp, iat, auth_time, nonce
- **Profile Claims** - name, given_name, family_name, email, email_verified
- **Custom Claims** - Extensible claims processing based on requested scopes

### **OIDC Standards Compliance**
- **OpenID Connect Core 1.0** - Complete implementation ✅
- **OpenID Connect Discovery 1.0** - Provider metadata ✅

---

## 🛡️ **Enterprise Security**

### **Authentication & Authorization**
- **JWT Security** - RS256/HS256 signing with proper validation and rotation
- **Password Security** - bcrypt hashing with configurable work factors
- **Token Management** - JTI tracking, rotation, and blacklisting
- **Session Security** - Concurrent session control and timeout management

### **Admin Security Model**
- **Two-Layer Security** - Intrinsic authority (is_admin flag) + OAuth scopes
- **Bootstrap System** - Solves IAM chicken-and-egg paradox
- **Granular Permissions** - 8 admin scopes for fine-grained access control
- **API Restrictions** - Admin API localhost-only with configurable access

### **System Security**
- **Rate Limiting** - Configurable protection with multiple backends
- **CORS Protection** - Comprehensive CORS policies and security headers
- **Secret Management** - Encrypted storage with automatic memory cleanup
- **Audit Logging** - Complete administrative action tracking

---

## 👥 **User Management**

### **User Lifecycle**
- **Registration & Verification** - Complete user onboarding with email verification
- **Role-Based Access Control** - Admin and user roles with privilege management
- **Profile Management** - Comprehensive user profile CRUD operations
- **Account Security** - Password reset, account lockout, and security monitoring

### **Admin Capabilities**
- **User Administration** - Create, update, delete, and manage user accounts
- **Permission Management** - Assign and revoke admin privileges
- **Security Monitoring** - Track user authentication and security events

---

## ⚙️ **Professional CLI Administration**

### **Unified CLI Interface**
```bash
# Start Authly server
python -m authly serve

# Admin operations
python -m authly admin login
python -m authly admin client create --name "My App" --client-type public --redirect-uri "http://localhost:3000/callback"
python -m authly admin scope create --name "read" --description "Read access"
python -m authly admin status
```

### **Admin Commands**
- **Authentication** - `login`, `logout`, `whoami` with secure token storage
- **Client Management** - Create, list, update, delete OAuth clients
- **Scope Management** - Create, list, update, delete OAuth scopes
- **User Management** - Admin user operations and privilege management
- **System Status** - Health checks, configuration, and system information

### **API-First Architecture**
- **HTTP API Backend** - CLI uses REST API exclusively (no direct DB access)
- **Secure Authentication** - JWT-based admin authentication with refresh tokens
- **Consistent Interface** - All admin operations available via both CLI and API

---

## 🚀 **Quick Start**

### **Development Setup**
```bash
# Clone and install
git clone <repository-url>
cd authly
uv sync --all-groups

# Start with embedded development server (includes PostgreSQL container)
uv run python -m authly serve --embedded

# Access Authly at http://localhost:8000
# Admin CLI: uv run python -m authly admin --help
```

### **Production Deployment**
```bash
# Using Docker
docker build -t authly .
docker run -p 8000:8000 \
  -e DATABASE_URL="postgresql://user:pass@host:5432/authly" \
  -e JWT_SECRET_KEY="your-secret-key" \
  authly

# Using UV
export DATABASE_URL="postgresql://user:pass@localhost:5432/authly"
export JWT_SECRET_KEY="your-secret-key"
uv run python -m authly serve
```

### **OAuth Client Setup**
```bash
# Create OAuth client
uv run python -m authly admin login
uv run python -m authly admin client create \
  --name "My Application" \
  --client-type confidential \
  --redirect-uri "https://myapp.com/callback"

# Create scope
uv run python -m authly admin scope create \
  --name "read" \
  --description "Read access to user data"
```

### **Optional Redis Integration**
For distributed deployments and enhanced performance:

```bash
# Install Redis support
uv add --group redis authly

# Configure Redis features
export AUTHLY_REDIS_URL="redis://localhost:6379/0"
export AUTHLY_REDIS_RATE_LIMIT="true"  # Distributed rate limiting
export AUTHLY_REDIS_CACHE="true"       # High-performance caching

# Start with Redis integration
python -m authly serve
```

**Redis Features:**
- **Distributed Rate Limiting** - Shared across multiple server instances  
- **High-Performance Caching** - JWKS keys, discovery metadata, sessions
- **Automatic Fallback** - Works without Redis, falls back to memory backends
- **Configuration-Driven** - Enable specific features as needed

See the [Redis Integration Guide](docs/redis-integration.md) for complete configuration options.

---

## 📚 **Documentation**

### **API Documentation**
- **[API Reference](docs/api-reference.md)** - Complete REST API documentation
- **[OAuth 2.1 Guide](docs/oauth-guide.md)** - OAuth implementation and usage
- **[OIDC Guide](docs/oidc-guide.md)** - OpenID Connect implementation and usage

### **Administration**
- **[CLI Guide](docs/cli-guide.md)** - Complete CLI administration guide
- **[Docker Deployment](docs/docker-deployment.md)** - Docker infrastructure and deployment
- **[Security Audit](docs/security-audit.md)** - Security analysis and validation

---

## 🔍 **API Endpoints**

### **OAuth 2.1 Endpoints**
- `GET/POST /oauth/authorize` - Authorization endpoint with consent UI
- `POST /oauth/token` - Token exchange endpoint with all grant types
- `POST /oauth/revoke` - Token revocation endpoint
- `GET /.well-known/oauth-authorization-server` - OAuth discovery metadata

### **OpenID Connect Endpoints**
- `GET /oidc/userinfo` - UserInfo endpoint with claims filtering
- `GET /.well-known/jwks.json` - JWKS endpoint for token verification
- `GET /.well-known/openid_configuration` - OIDC discovery metadata

### **Authentication Endpoints**
- `POST /auth/token` - User authentication and token generation
- `POST /auth/refresh` - Token refresh and rotation
- `POST /auth/logout` - Token invalidation and logout

### **Admin API Endpoints**
- `GET/POST /admin/clients` - OAuth client management
- `GET/POST /admin/scopes` - OAuth scope management
- `GET/POST /admin/users` - User management (admin only)
- `GET /admin/status` - System health and configuration

### **Health & Monitoring**
- `GET /health` - Application health check
- `GET /health/ready` - Readiness probe for Kubernetes
- `GET /health/live` - Liveness probe for Kubernetes

---

## 🧪 **Testing Excellence**

### **Test Coverage**
- **510 Tests Total** - 100% passing (verified production quality)
- **Real Integration Testing** - PostgreSQL testcontainers (no mocking)
- **Complete Flow Testing** - End-to-end OAuth and OIDC flows
- **Security Testing** - Authentication, authorization, and validation
- **API Testing** - All endpoints with comprehensive scenarios

### **Testing Categories**
- **OAuth 2.1 Tests** (156 tests) - Authorization flows, PKCE, client management
- **OIDC 1.0 Tests** (98 tests) - ID tokens, UserInfo, JWKS, discovery
- **Admin System Tests** (85 tests) - CLI, API, security, authentication
- **Core Authentication Tests** (67 tests) - JWT, passwords, tokens
- **User Management Tests** (33 tests) - User lifecycle and management

### **Quality Standards**
- **No Mocking** - Real database and HTTP server integration testing
- **Comprehensive Coverage** - All features, security scenarios, and error cases
- **Continuous Validation** - 100% success rate maintained throughout development

---

## 🏗️ **Architecture**

### **Technology Stack**
- **Python 3.11+** - Modern async/await with comprehensive type annotations
- **FastAPI** - High-performance async web framework with automatic OpenAPI
- **PostgreSQL** - Advanced database with UUID primary keys and proper indexing
- **Pydantic v2** - Modern data validation with constraints and serialization
- **UV** - Modern, fast Python package manager and dependency resolver

### **Design Patterns**
- **Package-by-Feature** - Clean module organization with clear boundaries
- **Repository Pattern** - Clean data access layer with async operations
- **Service Layer Pattern** - Business logic separation with dependency injection
- **Factory Pattern** - FastAPI app factory for different deployment modes
- **Strategy Pattern** - Pluggable components (storage, rate limiting, secrets)

### **Security Architecture**
- **Layered Security** - Multiple security layers with defense in depth
- **Async-First Design** - Scalable performance with modern Python patterns
- **Type Safety** - Comprehensive type annotations and validation
- **Configuration Management** - Flexible config with multiple providers

---

## 📊 **Project Status**

### **Implementation Status**
- ✅ **OAuth 2.1 Complete** - All endpoints, flows, and security features
- ✅ **OIDC 1.0 Complete** - ID tokens, UserInfo, JWKS, discovery
- ✅ **Admin System Complete** - CLI, API, security, user management
- ✅ **Production Ready** - Docker, monitoring, deployment, documentation
- ✅ **Test Excellence** - 510 tests passing with comprehensive coverage

### **Standards Compliance**
- ✅ **6 RFC Specifications** implemented and validated
- ✅ **Security Best Practices** - OWASP guidelines and threat modeling
- ✅ **Enterprise Features** - Audit logging, rate limiting, monitoring
- ✅ **Developer Experience** - Comprehensive docs, easy setup, great tooling

### **Next Phase Opportunities**
- **Performance Optimization** - Advanced caching and connection optimization
- **Enterprise Features** - Multi-tenant support, SAML integration, LDAP
- **Advanced Security** - FIDO2, WebAuthn, biometric authentication
- **Cloud Native** - Kubernetes operators, service mesh integration

---

## 📝 **License**

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🤝 **Contributing**

We welcome contributions! Please see our contributing guidelines and code of conduct.

### **Development Setup**
1. Clone the repository
2. Install dependencies: `uv sync --all-groups`
3. Install git hooks (recommended): `.githooks/install-hooks.sh`
4. Run tests: `pytest`
5. Start development server: `uv run python -m authly serve --embedded`

### **Git Hooks (Auto-Fix)**
```bash
# Install git hooks with auto-fixing capabilities
.githooks/install-hooks.sh

# Features:
# ✅ Auto-fix ruff linting issues
# ✅ Auto-format code with ruff
# ✅ Re-stage fixed files automatically

# Disable auto-fixing (if needed)
export AUTHLY_NO_AUTO_FIX=true
```

### **Development Commands**
- **Linting**: `uv run ruff check .`
- **Formatting**: `uv run ruff format .`
- **Auto-fix linting**: `uv run ruff check --fix .`
- **Validate Renovate config**: `npx --yes --package renovate -- renovate-config-validator .github/renovate.json`

### **Quality Standards**
- All code must include comprehensive tests
- 100% test success rate required
- Type annotations and documentation required
- Security-first development practices

---

**Authly** - Production-ready OAuth 2.1 + OpenID Connect 1.0 authorization server with enterprise-grade security and comprehensive testing.