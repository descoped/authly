# Authly

[![Build Status](https://github.com/descoped/authly/actions/workflows/build-test-native.yml/badge.svg)](https://github.com/descoped/authly/actions/workflows/build-test-native.yml)
[![Test Status](https://github.com/descoped/authly/actions/workflows/full-stack-test-with-docker.yml/badge.svg)](https://github.com/descoped/authly/actions/workflows/full-stack-test-with-docker.yml)
[![Coverage](https://codecov.io/gh/descoped/authly/branch/master/graph/badge.svg)](https://codecov.io/gh/descoped/authly)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/v/release/descoped/authly)](https://github.com/descoped/authly/releases)
[![PyPI - Version](https://img.shields.io/pypi/v/authly?color=blue)](https://pypi.org/project/authly/)
[![Docker Hub](https://img.shields.io/docker/v/descoped/authly?label=Docker%20Hub&color=blue)](https://hub.docker.com/r/descoped/authly/tags)

## A Modern OAuth 2.1 & OIDC Server Built with AI Collaboration

An **OAuth 2.1 and OpenID Connect authorization server** in active development. Built with FastAPI, PostgreSQL and Redis, Authly aims to provide standards-compliant authentication and authorization services.

---

Built through close collaboration between human developers and AI assistants (Claude, Gemini, and OpenAI), this authorization server follows a specification-driven development methodology. RFC standards and OpenID specifications guide our implementation choices, ensuring decisions are grounded in established protocols rather than arbitrary preferences.

The project began with traditional development to establish the foundational architecture. As it evolved, we adopted a hybrid approach where human developers maintain full control – reviewing, testing, and refactoring code in partnership with AI assistants. This collaborative workflow has proven particularly effective for navigating complex specifications and achieving compliance.

Through systematic testing and validation, we've achieved 100% conformance with OIDC Core requirements.

---

## ⚠️ Development Status

**This project is a work in progress:**
- Core OAuth 2.1 features are implemented with compliant error handling
- [OpenID Connect support with 100% conformance testing](https://github.com/descoped/authly/actions/workflows/conformance-tests.yml) (40/40 checks pass)
- OAuth 2.0 specification-compliant error responses
- Suitable for development and testing environments
- NOT recommended for production use without extensive testing and security audit

**Known Limitations:**
- UserInfo endpoint doesn't support POST method
- Some advanced OIDC test scenarios not fully implemented
- Edge cases in OAuth flows need more testing
- Not officially certified by OpenID Foundation

---

## 🔐 OAuth 2.1 Implementation

### **Core Features (Working)**
- **Authorization Code Flow** with mandatory PKCE (Proof Key for Code Exchange)
- **Client Management** for confidential and public OAuth clients
- **Token Revocation** (RFC 7009) for immediate token invalidation
- **Server Discovery** (RFC 8414) for automatic client configuration
- **Scope Management** with granular permission control

### **Supported Grant Types**
- **Authorization Code Grant** with PKCE for third-party applications
- **Password Grant** for trusted first-party applications (legacy support)
- **Refresh Token Grant** for token renewal
- **Client Credentials Grant** for service-to-service authentication

### **Standards Compliance (Partial)**
- **RFC 6749** - OAuth 2.0 Authorization Framework ✅ Implemented
- **RFC 7636** - Proof Key for Code Exchange (PKCE) ✅ Implemented
- **RFC 7009** - OAuth 2.0 Token Revocation ✅ Implemented
- **RFC 8414** - OAuth 2.0 Authorization Server Metadata ✅ Implemented
- **Official Certification**: ❌ Not certified

---

## 🆔 OpenID Connect Support

### **Basic OIDC Features (Working)**
- **ID Token Generation** with RS256/HS256 signing algorithms
- **UserInfo Endpoint** (GET method only)
- **JWKS Endpoint** for token signature verification
- **OIDC Discovery** with provider configuration metadata

### **OIDC Compliance Status**
- **Discovery**: 100% compliant ✅
- **JWKS**: 100% compliant ✅
- **Core Endpoints**: 100% compliant ✅
- **Security**: 100% compliant ✅
- **Overall**: 100% conformance (40/40 checks pass) ✅
- **Official Certification**: ❌ Not certified by OpenID Foundation

### **What Still Needs Work**
- UserInfo POST method support
- Advanced OIDC features (claims aggregation, request objects)
- Full end-to-end flow testing
- Official certification process

---

## 🛡️ Security Features

### **Implemented Security**
- **JWT Security** - RS256/HS256 signing with validation
- **Password Security** - bcrypt hashing (Argon2 planned)
- **Token Management** - JTI tracking and blacklisting
- **Rate Limiting** - Basic protection on auth endpoints
- **CORS Protection** - Configurable CORS policies

### **Admin Security Model**
- **Two-Layer Security** - Intrinsic authority + OAuth scopes
- **Bootstrap System** - Solves IAM chicken-and-egg paradox
- **API Restrictions** - Admin API localhost-only by default

### **Security Limitations**
- Not penetration tested
- No security audit performed
- Some edge cases not fully handled
- Performance under attack not tested

---

## 👥 User Management

### **Basic Features (Working)**
- User registration and authentication
- Role-based access control (admin/user)
- Profile management CRUD operations
- Password reset functionality

### **Admin Tools**
- CLI for OAuth client management
- Admin API for user management
- Scope management interface
- Basic monitoring endpoints

---

## 🚀 Quick Start

### **Development Setup**

```bash
# Clone repository
git clone https://github.com/descoped/authly.git
cd authly

# Install dependencies with uv
uv sync --all-groups

# Run with Docker Compose (recommended for development)
docker compose up

# Or run tests
uv run pytest
```

### **Docker Installation**

```bash
# Standard multi-service deployment
docker pull descoped/authly:latest
docker run -p 8000:8000 descoped/authly:latest

# All-in-one standalone container (includes PostgreSQL + Redis)
docker pull descoped/authly-standalone:latest
docker run -it --rm -p 8000:8000 descoped/authly-standalone:latest

# Using Docker Compose
docker compose up
```

The service will be available at `http://localhost:8000`

---

## 🧪 Testing

The project includes a comprehensive test suite:
- Integration tests with real PostgreSQL
- OAuth flow testing
- Basic OIDC compliance tests
- ~90% specification compliance achieved

```bash
# Run all tests
uv run pytest

# Run specific test category
uv run pytest tests/test_oauth.py -v

# Check conformance (90% compliance)
cd tck && make validate
```

---

## 📚 Documentation

- **[OAuth Implementation Guide](docs/oauth-guide.md)** - OAuth 2.1 features and usage
- **[OIDC Implementation Guide](docs/oidc-guide.md)** - OpenID Connect features
- **[API Reference](docs/api-reference.md)** - Complete API documentation
- **[Security Guide](docs/security-guide.md)** - Security features and best practices
- **[Deployment Guide](docs/deployment-guide.md)** - Deployment instructions
- **[Docker Standalone Guide](docs/docker-standalone.md)** - All-in-one container documentation

---

## 🛠️ Technology Stack

- **Python 3.11+** - Modern async/await with type annotations
- **FastAPI** - High-performance async web framework
- **PostgreSQL** - Primary data store with UUID support
- **Redis** - Optional caching and session storage
- **JWT** - Token-based authentication
- **Docker** - Containerized deployment

---

## 📋 Roadmap

### **Current Focus**
- [ ] Fix token endpoint error response format
- [ ] Add UserInfo POST method support
- [ ] Improve authorization endpoint error handling
- [ ] Complete OIDC test scenario coverage

### **Future Plans**
- [ ] Achieve 100% OIDC specification compliance
- [ ] Self-certification for OIDC compliance testing
- [ ] Argon2 password hashing
- [ ] Advanced OIDC features (prompt, max_age, ACR)
- [ ] GDPR compliance features
- [ ] Performance optimization
- [ ] Security audit

---

## 🤝 Contributing

This project is in active development and welcomes contributions. However, please note:

1. The codebase is evolving rapidly
2. Breaking changes may occur
3. Not all features are fully tested
4. Documentation may lag behind implementation

Please read the [Contributing Guidelines](.github/CONTRIBUTING.md) before submitting PRs.

---

## ⚖️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**This software is provided as-is, without warranty of any kind.** It is a work in progress and should not be used in production environments without thorough testing and security review. The developers are not responsible for any security breaches or data loss that may occur from using this software.

**Current Status:**
- ✅ Suitable for: Development, testing, learning, prototypes
- ❌ NOT suitable for: Production systems, high-security environments, certified compliance requirements

For production OAuth/OIDC needs, consider established solutions like Keycloak, Auth0, or Okta until this project reaches maturity.