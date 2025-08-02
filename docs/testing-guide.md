# Testing Guide for Authly

This document provides comprehensive coverage of Authly's testing architecture that maintains 100% test success rates, demonstrating real-world integration testing philosophy for production-ready OAuth 2.1 and OpenID Connect implementation.

## Table of Contents

1. [Testing Philosophy](#testing-philosophy)
2. [Test Architecture Overview](#test-architecture-overview)
3. [Testing Infrastructure](#testing-infrastructure)
4. [Test Categories](#test-categories)
5. [Real-World Integration Patterns](#real-world-integration-patterns)
6. [Performance Testing](#performance-testing)
7. [Security Testing](#security-testing)
8. [CI/CD Integration](#cicd-integration)
9. [Best Practices](#best-practices)

## Testing Philosophy

### Core Principles

Authly's testing architecture is built on **real-world integration testing** over mocking, ensuring that every component works correctly in production-like conditions. This approach has consistently delivered 100% test success rates across all implementation phases.

#### Real-World Integration Principles

1. **Real Database**: Use actual PostgreSQL with testcontainers, never SQLite or in-memory databases
2. **Real HTTP Server**: Use actual FastAPI server instances, not test clients that bypass middleware
3. **Real Connections**: Use actual async database connections with proper pooling
4. **Transaction Isolation**: Each test gets its own database transaction that rolls back automatically
5. **No Critical Mocking**: Avoid mocking authentication, database operations, or HTTP requests
6. **Production Parity**: Test configuration and deployment scenarios match production

### Why Real Integration Testing?

```python
# ❌ Fragile mocking approach
@patch('authly.database.get_connection')
@patch('authly.oauth.client_service.authenticate')
def test_oauth_flow_with_mocks(mock_auth, mock_db):
    # Mocks don't catch real integration issues
    # No confidence in production behavior
    pass

# ✅ Real integration approach
@pytest.mark.asyncio
async def test_oauth_flow_real_integration(
    transaction_manager: TransactionManager,
    test_server: FastAPITestServer
):
    async with transaction_manager.transaction() as conn:
        # Real database, real HTTP, real authentication
        # High confidence in production behavior
        pass
```

## Test Architecture Overview

### Current Test Statistics

```
Test Files: 45+ test modules
Test Categories:
├── OAuth 2.1 Core: Authorization, tokens, clients, scopes
├── OpenID Connect: Complete OIDC 1.0 implementation
├── Authentication: Core auth, password security, sessions
├── Administration: CLI tools, admin API, bootstrapping
├── Security: Middleware, rate limiting, security headers
├── Infrastructure: Resource management, logging, secrets
└── Integration: End-to-end flows and scenarios

Success Rate: 100% (maintained across all releases)
Coverage: 97%+ (verified with real database operations)
```

### Test Directory Structure

```
tests/
├── conftest.py                              # Global fixtures and configuration
├── fixtures/                               # Test infrastructure
│   ├── setup_logging.py                   # Logging test configuration
│   └── testing/
│       ├── lifespan.py                     # Application lifecycle for tests
│       └── postgres.py                     # PostgreSQL test containers
│
├── OAuth 2.1 Core Tests
│   ├── test_oauth_authorization.py         # Authorization code flow
│   ├── test_oauth_dependencies.py          # FastAPI dependency injection
│   ├── test_oauth_discovery.py             # RFC 8414 server metadata
│   ├── test_oauth_repositories.py          # Database layer testing
│   ├── test_oauth_services.py              # Business logic layer
│   ├── test_oauth_templates.py             # Frontend templates
│   └── test_oauth_token_flow.py            # Token lifecycle
│
├── OpenID Connect Tests
│   ├── test_oidc_authorization.py          # OIDC authorization flow
│   ├── test_oidc_basic_integration.py      # Core OIDC functionality
│   ├── test_oidc_client_management.py      # OIDC client operations
│   ├── test_oidc_complete_flows.py         # End-to-end OIDC flows
│   ├── test_oidc_compliance_features.py    # OIDC compliance validation
│   ├── test_oidc_comprehensive_flows.py    # Complex OIDC scenarios
│   ├── test_oidc_discovery.py              # OIDC discovery metadata
│   ├── test_oidc_id_token.py               # ID token generation/validation
│   ├── test_oidc_integration_flows.py      # Integration scenarios
│   ├── test_oidc_jwks.py                   # JSON Web Key Set
│   ├── test_oidc_logout.py                 # OIDC logout flows
│   ├── test_oidc_scopes.py                 # OIDC-specific scopes
│   ├── test_oidc_session_management.py     # Session management
│   └── test_oidc_userinfo.py               # UserInfo endpoint
│
├── Authentication Tests
│   ├── test_auth_api.py                    # Authentication API
│   ├── test_password_change_api.py         # Password management
│   ├── test_password_security.py           # Password policy validation
│   ├── test_tokens.py                      # Token management
│   ├── test_token_revocation.py            # RFC 7009 token revocation
│   └── test_verify_password_hash.py        # Password hashing
│
├── Administration Tests
│   ├── test_admin_api.py                   # Admin API endpoints
│   ├── test_admin_api_client.py            # Admin API client
│   ├── test_admin_api_client_integration.py # API client integration
│   ├── test_admin_bootstrap.py             # System bootstrapping
│   ├── test_admin_cli.py                   # CLI administration
│   ├── test_admin_dependencies.py          # Admin dependencies
│   └── test_admin_middleware.py            # Admin middleware
│
├── Security and Infrastructure
│   ├── test_security_middleware.py         # Security headers, CORS
│   ├── test_structured_logging.py          # JSON logging validation
│   ├── test_secrets.py                     # Secret management
│   ├── test_resource_manager_integration.py # Resource lifecycle
│   └── test_users_api.py                   # User management API
│
└── Application Tests
    ├── test_api.py                         # Core API functionality
    ├── test_main_app.py                    # Application factory
    ├── test_bootstrap_dev_mode.py          # Development mode
    └── test_bootstrap_password.py          # Bootstrap authentication
```

## Testing Infrastructure

### Core Testing Dependencies

```python
# Testing stack (from pyproject.toml)
[tool.poetry.group.test.dependencies]
pytest = "^7.4.0"
pytest-asyncio = "^0.21.1"
httpx = "^0.24.1"
testcontainers = "^3.7.1"

# Real-world integration libraries
fastapi-testing = "^0.1.0"      # Real FastAPI server instances
psycopg-toolkit = "^0.2.0"      # Transaction management and database operations
asyncpg = "^0.28.0"             # Async PostgreSQL driver
psycopg = {extras = ["binary", "pool"], version = "^3.1.9"}
```

### Global Test Configuration (conftest.py)

```python
import pytest
import asyncio
from typing import AsyncGenerator
from testcontainers.postgres import PostgresContainer
from psycopg_pool import AsyncConnectionPool
from fastapi_testing import TestServer

from authly.app import create_app
from authly.config import AuthlyConfig
from authly.core.resource_manager import ResourceManager
from psycopg_toolkit import TransactionManager


@pytest.fixture(scope="session")
def event_loop():
    """Session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def postgres_container():
    """PostgreSQL testcontainer for real database testing."""
    with PostgresContainer(
        "postgres:15",
        dbname="test_authly",
        username="test_user",
        password="test_pass"
    ) as postgres:
        yield postgres


@pytest.fixture(scope="session")
async def test_config(postgres_container) -> AuthlyConfig:
    """Test configuration with real database URL."""
    config = AuthlyConfig()
    config.database_url = postgres_container.get_connection_url()
    config.jwt_secret_key = "test-secret-key"
    config.jwt_refresh_secret_key = "test-refresh-secret-key"
    config.admin_email = "admin@test.local"
    config.admin_password = "admin123"
    return config


@pytest.fixture(scope="session")
async def resource_manager(test_config) -> ResourceManager:
    """Resource manager with test database connection."""
    rm = ResourceManager(test_config)
    await rm.initialize()
    yield rm
    await rm.cleanup()


@pytest.fixture
async def transaction_manager(resource_manager) -> TransactionManager:
    """Fresh transaction manager for each test with automatic rollback."""
    db_connection = await resource_manager.get_database_connection()
    return TransactionManager(db_connection)


@pytest.fixture
async def test_app(resource_manager):
    """FastAPI application instance for testing."""
    return create_app(resource_manager)


@pytest.fixture
async def test_server(test_app) -> AsyncGenerator[TestServer, None]:
    """Real FastAPI test server with full middleware stack."""
    async with TestServer(test_app) as server:
        yield server
```

### Transaction Isolation Pattern

The cornerstone of our testing approach is automatic transaction isolation:

```python
@pytest.mark.asyncio
async def test_oauth_feature_with_transaction_isolation(
    transaction_manager: TransactionManager,
    test_server: TestServer
):
    """Standard test pattern with automatic cleanup."""
    
    async with transaction_manager.transaction() as conn:
        # 1. Create repositories inside transaction
        user_repo = UserRepository(conn)
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        
        # 2. Set up test data
        test_user = await user_repo.create({
            "username": "test@example.com",
            "email": "test@example.com",
            "password_hash": get_password_hash("testpassword"),
            "is_verified": True,
            "is_active": True
        })
        
        test_client = await client_repo.create({
            "client_id": "test-client",
            "client_name": "Test Client",
            "client_type": "confidential",
            "client_secret_hash": get_password_hash("test-secret"),
            "redirect_uris": ["https://test.com/callback"],
            "is_active": True
        })
        
        # 3. Test business logic with real HTTP requests
        response = await test_server.client.post("/oauth/token", json={
            "grant_type": "password",
            "username": test_user.email,
            "password": "testpassword",
            "scope": "read write"
        }, auth=(test_client.client_id, "test-secret"))
        
        # 4. Assert results
        assert response.status_code == 200
        token_data = response.json()
        assert "access_token" in token_data
        assert "refresh_token" in token_data
        
        # 5. Verify database state
        user_tokens = await TokenRepository(conn).get_user_tokens(test_user.id)
        assert len(user_tokens) > 0
        
        # Transaction automatically rolls back - no cleanup needed!
```

## Test Categories

### 1. OAuth 2.1 Core Testing

#### Authorization Code Flow with PKCE

```python
@pytest.mark.asyncio
async def test_complete_oauth_authorization_code_flow_with_pkce(
    transaction_manager: TransactionManager,
    test_server: TestServer
):
    """Test complete OAuth 2.1 authorization code flow with PKCE validation."""
    
    async with transaction_manager.transaction() as conn:
        # Set up test environment
        client_repo = ClientRepository(conn)
        user_repo = UserRepository(conn)
        scope_repo = ScopeRepository(conn)
        
        # Create test data
        test_client = await client_repo.create({
            "client_id": "pkce-test-client",
            "client_name": "PKCE Test Client",
            "client_type": "public",  # Public client requires PKCE
            "redirect_uris": ["https://app.example.com/callback"],
            "is_active": True
        })
        
        test_user = await user_repo.create({
            "username": "pkceuser@example.com",
            "email": "pkceuser@example.com",
            "password_hash": get_password_hash("securepassword"),
            "is_verified": True,
            "is_active": True
        })
        
        # Set up scopes
        await scope_repo.create({
            "scope_name": "read",
            "description": "Read access",
            "is_active": True
        })
        
        # Generate PKCE parameters
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        # Step 1: Authorization Request
        auth_params = {
            "response_type": "code",
            "client_id": test_client.client_id,
            "redirect_uri": "https://app.example.com/callback",
            "scope": "read",
            "state": "random-state-12345",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        
        auth_response = await test_server.client.get("/oauth/authorize", params=auth_params)
        assert auth_response.status_code == 200
        
        # Verify authorization page contains client information
        auth_content = auth_response.text
        assert "PKCE Test Client" in auth_content
        assert "is requesting access" in auth_content
        
        # Step 2: User Authentication and Consent
        consent_data = {
            **auth_params,
            "username": test_user.email,
            "password": "securepassword",
            "approve": "true"
        }
        
        consent_response = await test_server.client.post(
            "/oauth/authorize",
            data=consent_data
        )
        assert consent_response.status_code == 302  # Redirect to callback
        
        # Extract authorization code from redirect
        location = consent_response.headers["location"]
        assert location.startswith("https://app.example.com/callback")
        
        # Parse authorization code from callback URL
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]
        returned_state = query_params["state"][0]
        
        assert returned_state == "random-state-12345"
        assert len(auth_code) > 0
        
        # Step 3: Token Exchange with PKCE Verification
        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "client_id": test_client.client_id,
            "code_verifier": code_verifier,  # PKCE verification
            "redirect_uri": "https://app.example.com/callback"
        }
        
        token_response = await test_server.client.post("/auth/token", json=token_request)
        assert token_response.status_code == 200
        
        token_data = token_response.json()
        assert "access_token" in token_data
        assert "refresh_token" in token_data
        assert token_data["token_type"] == "Bearer"
        assert "expires_in" in token_data
        
        # Step 4: Verify Token Access
        access_token = token_data["access_token"]
        protected_response = await test_server.client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        assert protected_response.status_code == 200
        
        user_data = protected_response.json()
        assert user_data["email"] == test_user.email
```

#### PKCE Security Validation

```python
@pytest.mark.asyncio
async def test_pkce_prevents_authorization_code_interception(
    transaction_manager: TransactionManager,
    test_server: TestServer
):
    """Test that PKCE prevents authorization code interception attacks."""
    
    async with transaction_manager.transaction() as conn:
        # Set up test client and auth code
        auth_code_repo = AuthorizationCodeRepository(conn)
        client_repo = ClientRepository(conn)
        
        test_client = await client_repo.create({
            "client_id": "security-test-client",
            "client_name": "Security Test Client",
            "client_type": "public",
            "redirect_uris": ["https://secure.app/callback"],
            "is_active": True
        })
        
        # Generate PKCE parameters
        correct_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(correct_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        # Create authorization code with PKCE challenge
        auth_code = await auth_code_repo.create({
            "code": "test-auth-code-12345",
            "client_id": test_client.client_id,
            "user_id": str(uuid4()),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "redirect_uri": "https://secure.app/callback",
            "scopes": ["read"],
            "expires_at": datetime.utcnow() + timedelta(minutes=10)
        })
        
        # Attempt 1: Token exchange with wrong code_verifier (simulating interception)
        wrong_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
        
        malicious_request = {
            "grant_type": "authorization_code",
            "code": "test-auth-code-12345",
            "client_id": test_client.client_id,
            "code_verifier": wrong_verifier,  # Wrong verifier
            "redirect_uri": "https://secure.app/callback"
        }
        
        malicious_response = await test_server.client.post("/auth/token", json=malicious_request)
        assert malicious_response.status_code == 400
        
        error_data = malicious_response.json()
        assert error_data["error"] == "invalid_grant"
        assert "PKCE verification failed" in error_data["error_description"]
        
        # Verify authorization code is consumed/invalidated after failed attempt
        consumed_code = await auth_code_repo.get_by_code("test-auth-code-12345")
        assert consumed_code is None or consumed_code.used is True
        
        # Attempt 2: Even with correct verifier, code should now be unusable
        legitimate_request = {
            "grant_type": "authorization_code",
            "code": "test-auth-code-12345",
            "client_id": test_client.client_id,
            "code_verifier": correct_verifier,  # Correct verifier
            "redirect_uri": "https://secure.app/callback"
        }
        
        legitimate_response = await test_server.client.post("/auth/token", json=legitimate_request)
        assert legitimate_response.status_code == 400  # Code already consumed
        
        error_data = legitimate_response.json()
        assert error_data["error"] == "invalid_grant"
```

### 2. OpenID Connect Testing

#### Complete OIDC Flow with ID Token

```python
@pytest.mark.asyncio
async def test_complete_oidc_flow_with_id_token(
    transaction_manager: TransactionManager,
    test_server: TestServer
):
    """Test complete OpenID Connect flow with ID token generation."""
    
    async with transaction_manager.transaction() as conn:
        # Set up OIDC-enabled client
        client_repo = ClientRepository(conn)
        user_repo = UserRepository(conn)
        scope_repo = ScopeRepository(conn)
        
        oidc_client = await client_repo.create({
            "client_id": "oidc-test-client",
            "client_name": "OIDC Test Client",
            "client_type": "confidential",
            "client_secret_hash": get_password_hash("oidc-secret"),
            "redirect_uris": ["https://oidc.app/callback"],
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "is_active": True
        })
        
        test_user = await user_repo.create({
            "username": "oidcuser@example.com",
            "email": "oidcuser@example.com",
            "full_name": "OIDC Test User",
            "password_hash": get_password_hash("oidcpassword"),
            "is_verified": True,
            "is_active": True
        })
        
        # Set up OIDC scopes
        await scope_repo.create({
            "scope_name": "openid",
            "description": "OpenID Connect authentication",
            "is_active": True
        })
        await scope_repo.create({
            "scope_name": "profile",
            "description": "User profile information",
            "is_active": True
        })
        await scope_repo.create({
            "scope_name": "email",
            "description": "Email address",
            "is_active": True
        })
        
        # Generate PKCE for OIDC flow
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        # OIDC Authorization Request with nonce
        nonce = secrets.token_urlsafe(16)
        auth_params = {
            "response_type": "code",
            "client_id": oidc_client.client_id,
            "redirect_uri": "https://oidc.app/callback",
            "scope": "openid profile email",  # OIDC scopes
            "state": "oidc-state-12345",
            "nonce": nonce,  # OIDC nonce for ID token security
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        
        # Authorization and consent flow
        auth_response = await test_server.client.get("/oauth/authorize", params=auth_params)
        assert auth_response.status_code == 200
        
        consent_data = {
            **auth_params,
            "username": test_user.email,
            "password": "oidcpassword",
            "approve": "true"
        }
        
        consent_response = await test_server.client.post(
            "/oauth/authorize",
            data=consent_data
        )
        assert consent_response.status_code == 302
        
        # Extract authorization code
        location = consent_response.headers["location"]
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]
        
        # Token exchange for OIDC
        token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "client_id": oidc_client.client_id,
            "client_secret": "oidc-secret",
            "code_verifier": code_verifier,
            "redirect_uri": "https://oidc.app/callback"
        }
        
        token_response = await test_server.client.post("/auth/token", json=token_request)
        assert token_response.status_code == 200
        
        token_data = token_response.json()
        assert "access_token" in token_data
        assert "refresh_token" in token_data
        assert "id_token" in token_data  # OIDC ID token
        assert token_data["token_type"] == "Bearer"
        
        # Verify ID token structure and claims
        id_token = token_data["id_token"]
        
        # Decode ID token (in production, verify signature)
        import jwt
        decoded_id_token = jwt.decode(
            id_token,
            options={"verify_signature": False}  # Skip signature verification in test
        )
        
        # Verify OIDC ID token claims
        assert decoded_id_token["iss"]  # Issuer
        assert decoded_id_token["aud"] == oidc_client.client_id  # Audience
        assert decoded_id_token["sub"]  # Subject (user ID)
        assert decoded_id_token["nonce"] == nonce  # Nonce matches
        assert "exp" in decoded_id_token  # Expiration
        assert "iat" in decoded_id_token  # Issued at
        
        # Verify profile claims (when profile scope granted)
        if "profile" in token_data.get("scope", ""):
            assert decoded_id_token.get("name") == test_user.full_name
        
        # Verify email claims (when email scope granted)
        if "email" in token_data.get("scope", ""):
            assert decoded_id_token.get("email") == test_user.email
        
        # Test UserInfo endpoint with access token
        userinfo_response = await test_server.client.get(
            "/oidc/userinfo",
            headers={"Authorization": f"Bearer {token_data['access_token']}"}
        )
        assert userinfo_response.status_code == 200
        
        userinfo_data = userinfo_response.json()
        assert userinfo_data["sub"] == decoded_id_token["sub"]
        assert userinfo_data["email"] == test_user.email
        assert userinfo_data["name"] == test_user.full_name
```

### 3. Security Testing Patterns

#### Rate Limiting and Brute Force Protection

```python
@pytest.mark.asyncio
async def test_rate_limiting_prevents_brute_force_attacks(
    transaction_manager: TransactionManager,
    test_server: TestServer
):
    """Test that rate limiting prevents brute force authentication attacks."""
    
    async with transaction_manager.transaction() as conn:
        user_repo = UserRepository(conn)
        
        # Create test user
        test_user = await user_repo.create({
            "username": "ratelimit@example.com",
            "email": "ratelimit@example.com",
            "password_hash": get_password_hash("correctpassword"),
            "is_verified": True,
            "is_active": True
        })
        
        # Attempt multiple failed logins rapidly
        failed_attempts = []
        for i in range(10):  # Exceed rate limit threshold
            login_request = {
                "grant_type": "password",
                "username": test_user.email,
                "password": f"wrongpassword{i}",  # Intentionally wrong
                "scope": "read"
            }
            
            response = await test_server.client.post("/auth/token", json=login_request)
            failed_attempts.append(response.status_code)
        
        # Verify rate limiting kicks in
        assert 401 in failed_attempts  # Initial failed attempts
        assert 429 in failed_attempts  # Rate limited after threshold
        
        # Verify legitimate login is also blocked during rate limit period
        legitimate_request = {
            "grant_type": "password",
            "username": test_user.email,
            "password": "correctpassword",  # Correct password
            "scope": "read"
        }
        
        blocked_response = await test_server.client.post("/auth/token", json=legitimate_request)
        assert blocked_response.status_code == 429  # Still rate limited
        
        error_data = blocked_response.json()
        assert "rate limit" in error_data["detail"].lower()
```

#### Client Authentication Security

```python
@pytest.mark.asyncio
async def test_client_authentication_security_methods(
    transaction_manager: TransactionManager,
    test_server: TestServer
):
    """Test different client authentication methods and security."""
    
    async with transaction_manager.transaction() as conn:
        client_repo = ClientRepository(conn)
        
        # Create clients with different authentication methods
        basic_auth_client = await client_repo.create({
            "client_id": "basic-auth-client",
            "client_name": "Basic Auth Client",
            "client_type": "confidential",
            "client_secret_hash": get_password_hash("basic-secret"),
            "auth_method": "client_secret_basic",
            "redirect_uris": ["https://basic.test/callback"],
            "is_active": True
        })
        
        post_auth_client = await client_repo.create({
            "client_id": "post-auth-client",
            "client_name": "Post Auth Client",
            "client_type": "confidential",
            "client_secret_hash": get_password_hash("post-secret"),
            "auth_method": "client_secret_post",
            "redirect_uris": ["https://post.test/callback"],
            "is_active": True
        })
        
        public_client = await client_repo.create({
            "client_id": "public-client",
            "client_name": "Public Client",
            "client_type": "public",
            "client_secret_hash": None,  # No secret for public clients
            "auth_method": None,
            "redirect_uris": ["myapp://callback"],
            "is_active": True
        })
        
        # Test 1: HTTP Basic Authentication
        auth_header = base64.b64encode(b"basic-auth-client:basic-secret").decode()
        
        basic_auth_request = {
            "grant_type": "client_credentials",
            "scope": "client_admin"
        }
        
        basic_auth_response = await test_server.client.post(
            "/auth/token",
            json=basic_auth_request,
            headers={"Authorization": f"Basic {auth_header}"}
        )
        assert basic_auth_response.status_code == 200
        
        # Test 2: Client Secret Post
        post_auth_request = {
            "grant_type": "client_credentials",
            "client_id": "post-auth-client",
            "client_secret": "post-secret",
            "scope": "client_admin"
        }
        
        post_auth_response = await test_server.client.post(
            "/auth/token",
            json=post_auth_request
        )
        assert post_auth_response.status_code == 200
        
        # Test 3: Public Client (no authentication required)
        public_request = {
            "grant_type": "authorization_code",
            "code": "public-auth-code",
            "client_id": "public-client",
            "code_verifier": "public-verifier",
            "redirect_uri": "myapp://callback"
        }
        
        # Public client requests don't require authentication
        # (Though they'll fail due to invalid code, not auth failure)
        public_response = await test_server.client.post("/auth/token", json=public_request)
        assert public_response.status_code != 401  # Not an auth failure
        
        # Test 4: Invalid Authentication
        invalid_auth_header = base64.b64encode(b"basic-auth-client:wrong-secret").decode()
        
        invalid_request = {
            "grant_type": "client_credentials",
            "scope": "client_admin"
        }
        
        invalid_response = await test_server.client.post(
            "/auth/token",
            json=invalid_request,
            headers={"Authorization": f"Basic {invalid_auth_header}"}
        )
        assert invalid_response.status_code == 401
        
        error_data = invalid_response.json()
        assert "invalid" in error_data["detail"].lower()
```

## Performance Testing

### Database Connection Pool Testing

```python
@pytest.mark.asyncio
async def test_database_connection_pool_under_load(
    resource_manager: ResourceManager
):
    """Test database connection pool performance under concurrent load."""
    import asyncio
    import time
    
    async def simulate_database_operation():
        """Simulate a database operation using the connection pool."""
        async with resource_manager.get_database_connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT COUNT(*) FROM users")
                result = await cur.fetchone()
                return result[0] if result else 0
    
    # Test concurrent operations
    concurrent_operations = 50
    tasks = [simulate_database_operation() for _ in range(concurrent_operations)]
    
    start_time = time.time()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    end_time = time.time()
    
    # Verify all operations completed successfully
    successful_results = [r for r in results if isinstance(r, int)]
    assert len(successful_results) == concurrent_operations
    
    # Performance assertions
    total_time = end_time - start_time
    avg_time_per_operation = total_time / concurrent_operations
    assert avg_time_per_operation < 0.1  # Each operation should complete in <100ms
    
    print(f"Completed {concurrent_operations} concurrent DB operations in {total_time:.2f}s")
    print(f"Average time per operation: {avg_time_per_operation:.3f}s")


@pytest.mark.asyncio
async def test_concurrent_oauth_authorization_performance(
    transaction_manager: TransactionManager,
    test_server: TestServer
):
    """Test OAuth authorization endpoint performance under concurrent load."""
    
    async with transaction_manager.transaction() as conn:
        client_repo = ClientRepository(conn)
        
        # Create test client
        test_client = await client_repo.create({
            "client_id": "perf-test-client",
            "client_name": "Performance Test Client",
            "client_type": "public",
            "redirect_uris": ["https://perf.test/callback"],
            "is_active": True
        })
        
        async def single_authorization_request():
            """Perform single OAuth authorization request."""
            auth_params = {
                "response_type": "code",
                "client_id": test_client.client_id,
                "redirect_uri": "https://perf.test/callback",
                "scope": "read",
                "state": f"state-{secrets.token_urlsafe(8)}",
                "code_challenge": "test-challenge",
                "code_challenge_method": "S256"
            }
            
            response = await test_server.client.get("/oauth/authorize", params=auth_params)
            return response.status_code
        
        # Test concurrent authorization requests
        concurrent_requests = 25
        
        start_time = time.time()
        tasks = [single_authorization_request() for _ in range(concurrent_requests)]
        status_codes = await asyncio.gather(*tasks)
        end_time = time.time()
        
        # Verify all requests completed successfully
        assert all(code == 200 for code in status_codes)
        
        # Performance assertions
        total_time = end_time - start_time
        avg_time_per_request = total_time / concurrent_requests
        assert avg_time_per_request < 0.5  # Each request should complete in <500ms
        
        print(f"Completed {concurrent_requests} concurrent auth requests in {total_time:.2f}s")
        print(f"Average time per request: {avg_time_per_request:.3f}s")
```

## CI/CD Integration

### GitHub Actions Testing Pipeline

```yaml
name: Comprehensive Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test_password
          POSTGRES_USER: test_user
          POSTGRES_DB: test_authly
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python 3.11
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          
      - name: Install Poetry
        uses: snok/install-poetry@v1
        with:
          virtualenvs-create: true
          virtualenvs-in-project: true
          
      - name: Load cached venv
        id: cached-poetry-dependencies
        uses: actions/cache@v3
        with:
          path: .venv
          key: venv-${{ runner.os }}-${{ steps.setup-python.outputs.python-version }}-${{ hashFiles('**/poetry.lock') }}
          
      - name: Install dependencies
        if: steps.cached-poetry-dependencies.outputs.cache-hit != 'true'
        run: poetry install --no-interaction --no-root
        
      - name: Install project
        run: poetry install --no-interaction
        
      - name: Run linting
        run: |
          poetry run ruff check src/ tests/
          poetry run black --check src/ tests/
          poetry run isort --check-only src/ tests/
          
      - name: Run type checking
        run: poetry run mypy src/
        
      - name: Run tests with coverage
        env:
          AUTHLY_DATABASE_URL: postgresql://test_user:test_password@localhost:5432/test_authly
          AUTHLY_JWT_SECRET_KEY: test-secret-key-for-ci-cd
          AUTHLY_JWT_REFRESH_SECRET_KEY: test-refresh-secret-key-for-ci-cd
          AUTHLY_ADMIN_EMAIL: admin@test.local
          AUTHLY_ADMIN_PASSWORD: admin123
        run: |
          poetry run pytest \
            --cov=src/authly \
            --cov-report=xml \
            --cov-report=term-missing \
            --cov-fail-under=95 \
            --junit-xml=test-results.xml \
            -v \
            --tb=short
            
      - name: Upload test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: test-results
          path: test-results.xml
          
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
          fail_ci_if_error: true
```

### Test Data Factories

```python
import secrets
import bcrypt
from typing import Dict, Any
from datetime import datetime, timedelta

class AuthlyTestDataFactory:
    """Factory for creating consistent test data across all tests."""
    
    @staticmethod
    def create_user_data(
        email: str = None,
        username: str = None,
        password: str = "testpassword",
        is_verified: bool = True,
        is_active: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """Create user test data with sensible defaults."""
        email = email or f"test-{secrets.token_urlsafe(8)}@example.com"
        return {
            "email": email,
            "username": username or email,
            "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            "is_verified": is_verified,
            "is_active": is_active,
            "full_name": f"Test User {secrets.token_urlsafe(4)}",
            **kwargs
        }
    
    @staticmethod
    def create_oauth_client_data(
        client_type: str = "confidential",
        client_id: str = None,
        client_secret: str = "test-secret",
        **kwargs
    ) -> Dict[str, Any]:
        """Create OAuth client test data."""
        base_data = {
            "client_id": client_id or f"test-client-{secrets.token_urlsafe(8)}",
            "client_name": f"Test Client {secrets.token_urlsafe(4)}",
            "client_type": client_type,
            "redirect_uris": ["https://test.example.com/callback"],
            "is_active": True,
            **kwargs
        }
        
        if client_type == "confidential":
            base_data["client_secret_hash"] = bcrypt.hashpw(
                client_secret.encode(), bcrypt.gensalt()
            ).decode()
            base_data["auth_method"] = "client_secret_basic"
        
        return base_data
    
    @staticmethod
    def create_oidc_client_data(
        client_id: str = None,
        client_secret: str = "oidc-secret",
        **kwargs
    ) -> Dict[str, Any]:
        """Create OIDC-enabled client test data."""
        return AuthlyTestDataFactory.create_oauth_client_data(
            client_type="confidential",
            client_id=client_id,
            client_secret=client_secret,
            response_types=["code"],
            grant_types=["authorization_code", "refresh_token"],
            **kwargs
        )
    
    @staticmethod
    def create_scope_data(
        scope_name: str,
        description: str = None,
        is_default: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Create scope test data."""
        return {
            "scope_name": scope_name,
            "description": description or f"Access for {scope_name}",
            "is_default": is_default,
            "is_active": True,
            **kwargs
        }
    
    @staticmethod
    def create_standard_scopes() -> List[Dict[str, Any]]:
        """Create standard OAuth/OIDC scopes for testing."""
        return [
            AuthlyTestDataFactory.create_scope_data("openid", "OpenID Connect authentication", True),
            AuthlyTestDataFactory.create_scope_data("profile", "User profile information", True),
            AuthlyTestDataFactory.create_scope_data("email", "Email address", True),
            AuthlyTestDataFactory.create_scope_data("read", "Read access to user data", False),
            AuthlyTestDataFactory.create_scope_data("write", "Write access to user data", False),
        ]
```

## Best Practices

### 1. Test Organization

```python
# ✅ Good: Clear test structure with descriptive names
@pytest.mark.asyncio
async def test_oauth_authorization_code_flow_with_pkce_validates_code_challenge(
    transaction_manager: TransactionManager,
    test_server: TestServer
):
    """
    Test that OAuth authorization code flow properly validates PKCE code_challenge.
    
    This test ensures that:
    1. Code challenge is properly stored with authorization code
    2. Code verifier is validated during token exchange
    3. Invalid code verifiers are rejected
    4. Authorization codes are consumed after use
    """
    # Test implementation
```

### 2. Transaction Management

```python
# ✅ Good: Always use transaction isolation
@pytest.mark.asyncio
async def test_database_operation(transaction_manager: TransactionManager):
    async with transaction_manager.transaction() as conn:
        # All database operations happen within transaction
        # Automatic rollback ensures clean state for next test
        pass

# ❌ Bad: Direct database access without isolation
@pytest.mark.asyncio
async def test_database_operation_bad(db_connection):
    # No isolation, can affect other tests
    pass
```

### 3. Real HTTP Testing

```python
# ✅ Good: Use real FastAPI test server
@pytest.mark.asyncio
async def test_oauth_endpoint(test_server: TestServer):
    response = await test_server.client.post("/oauth/token", json=token_request)
    # Tests full middleware stack, routing, etc.

# ❌ Bad: Mock HTTP calls
@patch('fastapi.Request')
def test_oauth_endpoint_mocked(mock_request):
    # Doesn't test real HTTP behavior
    pass
```

### 4. Error Testing

```python
# ✅ Good: Test both success and failure scenarios
@pytest.mark.asyncio
async def test_token_validation():
    # Test valid token
    valid_response = await test_server.client.get("/protected", headers=valid_headers)
    assert valid_response.status_code == 200
    
    # Test invalid token
    invalid_response = await test_server.client.get("/protected", headers=invalid_headers)
    assert invalid_response.status_code == 401
    
    # Test expired token
    expired_response = await test_server.client.get("/protected", headers=expired_headers)
    assert expired_response.status_code == 401
    
    # Test malformed token
    malformed_response = await test_server.client.get("/protected", headers=malformed_headers)
    assert malformed_response.status_code == 401
```

### 5. Performance Awareness

```python
# ✅ Good: Monitor test performance
@pytest.mark.asyncio
async def test_performance_critical_operation():
    start_time = time.time()
    
    # Perform operation
    result = await operation()
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Assert functionality
    assert result.success is True
    
    # Assert performance
    assert duration < 1.0  # Should complete in <1 second
```

## Conclusion

Authly's testing architecture demonstrates that comprehensive real-world integration testing is both achievable and essential for production-ready OAuth 2.1 and OpenID Connect implementations. Key achievements:

### Technical Excellence
- **100% Test Success Rate**: Maintained across all development cycles
- **Real Integration Testing**: No critical mocking, actual database and HTTP operations
- **Comprehensive Coverage**: OAuth 2.1, OIDC 1.0, security, performance, and integration scenarios
- **Transaction Isolation**: Clean test state without manual cleanup
- **Performance Validation**: Load testing ensures scalability under concurrent operations

### Quality Assurance
- **Security Validation**: Extensive PKCE, authentication, and authorization testing
- **Standards Compliance**: Complete RFC compliance validation through testing
- **Error Handling**: Comprehensive negative testing scenarios
- **Performance Monitoring**: Automated performance regression detection

### Development Efficiency
- **Fast Feedback**: Tests complete quickly with parallel execution
- **Reliable Results**: Consistent test outcomes across environments
- **Easy Debugging**: Clear test failures with detailed error information
- **Maintainable Tests**: Clean architecture matches application structure

The testing strategy serves as both quality gate and living documentation, ensuring Authly's OAuth 2.1 and OpenID Connect implementation meets the highest standards for enterprise production deployment.