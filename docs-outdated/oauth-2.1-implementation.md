# OAuth 2.1 Implementation Guide

> **Audience**: Developers, Technical Architects, Security Engineers  
> **Prerequisites**: Understanding of OAuth 2.1 concepts and Authly architecture  
> **Related Documentation**: [API Reference](api-reference.md) • [Security Features](security-features.md) • [CLI Administration](cli-administration.md)

This document provides a comprehensive guide to the OAuth 2.1 implementation in Authly, detailing the architecture, features, and technical implementation that achieved full RFC compliance with 171/171 tests passing.

## Table of Contents

- [Overview](#overview)
- [Implementation Architecture](#implementation-architecture)
- [Core Components](#core-components)
- [OAuth 2.1 Features](#oauth-21-features)
- [Security Implementation](#security-implementation)
- [Testing Strategy](#testing-strategy)
- [Integration Examples](#integration-examples)
- [Troubleshooting](#troubleshooting)

## Overview

Authly implements a complete OAuth 2.1 authorization server with enterprise-grade security, PKCE support, and comprehensive scope management. The implementation follows a layered architecture approach while maintaining backward compatibility with existing authentication methods.

## Implementation Architecture

### Layered Design

The OAuth 2.1 implementation follows a clean layered architecture:

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
│  │             │  DiscoveryService   │  │
│  └─────────────┴─────────────────────┘  │
├─────────────────────────────────────────┤
│           Repository Layer              │
│  ┌─────────────┬─────────────────────┐  │
│  │UserRepository│  ClientRepository  │  │
│  │TokenRepository│  ScopeRepository  │  │
│  │             │AuthorizationCodeRepo│  │
│  └─────────────┴─────────────────────┘  │
├─────────────────────────────────────────┤
│           Database Layer                │
│        PostgreSQL + psycopg            │
└─────────────────────────────────────────┘
```

### Core Components

#### OAuth Models
- **OAuthClient**: Represents OAuth 2.1 clients (confidential and public)
- **OAuthScope**: Permission scopes with descriptions and default flags
- **AuthorizationCode**: Short-lived codes for authorization flow
- **OAuthServerMetadata**: RFC 8414 server discovery metadata

#### Services
- **ClientService**: OAuth client management and authentication
- **ScopeService**: Scope validation and association management
- **AuthorizationService**: Authorization code flow with PKCE
- **DiscoveryService**: RFC 8414 metadata endpoint

#### Repositories
- **ClientRepository**: Database operations for OAuth clients
- **ScopeRepository**: Scope CRUD and association management
- **AuthorizationCodeRepository**: Authorization code lifecycle

## OAuth 2.1 Features

### 1. Authorization Code Flow with PKCE

**Mandatory PKCE Implementation:**
```python
# PKCE is required for all authorization code flows
@router.post("/authorize")
async def authorization_endpoint(
    code_challenge: str,
    code_challenge_method: str = "S256"  # Only S256 supported per OAuth 2.1
):
    # Validate PKCE parameters
    if code_challenge_method != "S256":
        raise HTTPException(400, "Only S256 challenge method supported")
    
    # Store challenge with authorization code
    auth_code = await authorization_service.create_authorization_code(
        client_id=client_id,
        user_id=current_user.id,
        code_challenge=code_challenge,
        redirect_uri=redirect_uri,
        scopes=granted_scopes
    )
```

**PKCE Verification:**
```python
# Token exchange validates PKCE proof
@router.post("/auth/token")
async def token_endpoint(
    grant_type: str,
    code: str,
    code_verifier: str,
    client_id: str
):
    if grant_type == "authorization_code":
        # Verify PKCE challenge
        valid = await authorization_service.verify_pkce(
            code=code,
            code_verifier=code_verifier,
            client_id=client_id
        )
        if not valid:
            raise HTTPException(400, "Invalid PKCE verification")
```

### 2. Client Types and Authentication

**Confidential Clients:**
```python
class OAuthClientCreateRequest(BaseModel):
    client_name: str
    client_type: ClientType = ClientType.CONFIDENTIAL
    redirect_uris: List[str]
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    auth_method: str = "client_secret_basic"
    require_pkce: bool = True  # Always true for OAuth 2.1
```

**Public Clients:**
```python
# Public clients don't have secrets but still require PKCE
public_client = OAuthClientCreateRequest(
    client_name="Mobile App",
    client_type=ClientType.PUBLIC,
    redirect_uris=["com.example.app://callback"],
    require_pkce=True  # Mandatory for OAuth 2.1
)
```

**Client Authentication Methods:**
- `client_secret_basic`: HTTP Basic authentication
- `client_secret_post`: Secret in request body
- Public clients: No authentication required

### 3. Scope Management

**Scope Definition:**
```python
@dataclass
class OAuthScope:
    scope_name: str
    description: str
    is_default: bool = False
    is_active: bool = True
```

**Dynamic Scope Discovery:**
```python
async def get_supported_scopes() -> List[str]:
    """Dynamically retrieve available scopes for discovery endpoint."""
    active_scopes = await scope_repository.get_active_scopes()
    return [scope.scope_name for scope in active_scopes]
```

**Scope Validation:**
```python
async def validate_token_scopes(required_scope: str, token_scopes: List[str]) -> bool:
    """Validate if token has required scope for API access."""
    return required_scope in token_scopes
```

### 4. Token Revocation (RFC 7009)

**Revocation Endpoint:**
```python
@router.post("/auth/revoke")
async def revoke_token(
    request: TokenRevocationRequest,
    client: Optional[OAuthClient] = Depends(get_current_client)
):
    """RFC 7009 compliant token revocation."""
    
    # Always return 200 to prevent token enumeration
    try:
        success = await token_service.revoke_token(
            token=request.token,
            token_type_hint=request.token_type_hint,
            client=client
        )
        return {"revoked": success}
    except Exception:
        # Always return success to prevent enumeration
        return {"revoked": True}
```

### 5. Server Discovery (RFC 8414)

**Metadata Endpoint:**
```python
@router.get("/.well-known/oauth-authorization-server")
async def oauth_server_metadata(request: Request) -> OAuthServerMetadata:
    """RFC 8414 OAuth Authorization Server Metadata."""
    
    base_url = get_base_url(request)
    scopes = await scope_service.get_active_scope_names()
    
    return OAuthServerMetadata(
        issuer=base_url,
        authorization_endpoint=f"{base_url}/authorize",
        token_endpoint=f"{base_url}/auth/token",
        revocation_endpoint=f"{base_url}/auth/revoke",
        scopes_supported=scopes,
        response_types_supported=["code"],
        grant_types_supported=["authorization_code", "password", "refresh_token"],
        code_challenge_methods_supported=["S256"],
        token_endpoint_auth_methods_supported=[
            "client_secret_basic", 
            "client_secret_post"
        ]
    )
```

## Database Schema

### OAuth Tables

```sql
-- OAuth clients (confidential and public)
CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(255), -- NULL for public clients
    client_type VARCHAR(20) NOT NULL, -- 'confidential' or 'public'
    redirect_uris TEXT[] NOT NULL,
    client_uri VARCHAR(255),
    logo_uri VARCHAR(255),
    auth_method VARCHAR(50) DEFAULT 'client_secret_basic',
    require_pkce BOOLEAN DEFAULT true,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- OAuth scopes with descriptions
CREATE TABLE scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Client-scope associations
CREATE TABLE client_scopes (
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, scope_id)
);

-- Authorization codes for OAuth flow
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

-- Performance indexes
CREATE INDEX idx_clients_client_id ON clients(client_id);
CREATE INDEX idx_authorization_codes_code ON authorization_codes(code);
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX idx_client_scopes_client_id ON client_scopes(client_id);
```

### Enhanced Token Table

```sql
-- Enhanced tokens table with OAuth support
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    jti VARCHAR(64) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE, -- For OAuth tokens
    token_type VARCHAR(20) NOT NULL, -- 'access', 'refresh'
    scopes TEXT[], -- Granted scopes for OAuth tokens
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    invalidated BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tokens_jti ON tokens(jti);
CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_client_id ON tokens(client_id);
```

## Security Implementation

### 1. PKCE Security

**Code Challenge Generation:**
```python
import hashlib
import base64
import secrets

def generate_pkce_pair():
    """Generate PKCE code_verifier and code_challenge."""
    # Generate cryptographically secure verifier
    code_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')
    
    # Generate S256 challenge
    challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
    
    return code_verifier, code_challenge
```

**PKCE Verification:**
```python
def verify_pkce(code_verifier: str, stored_challenge: str) -> bool:
    """Verify PKCE code_verifier against stored challenge."""
    challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    computed_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
    
    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(computed_challenge, stored_challenge)
```

### 2. Client Authentication

**Confidential Client Authentication:**
```python
async def authenticate_client(
    client_id: str,
    client_secret: Optional[str],
    auth_method: str
) -> Optional[OAuthClient]:
    """Authenticate OAuth client based on authentication method."""
    
    client = await client_repository.get_by_client_id(client_id)
    if not client or not client.is_active:
        return None
    
    if client.client_type == ClientType.PUBLIC:
        # Public clients don't require authentication
        return client
    
    if not client_secret:
        return None
    
    # Verify client secret with bcrypt
    if not verify_client_secret(client_secret, client.client_secret_hash):
        return None
    
    return client
```

### 3. Authorization Code Security

**Short-lived Codes:**
```python
AUTHORIZATION_CODE_EXPIRE_MINUTES = 10  # OAuth 2.1 maximum

async def create_authorization_code(
    client_id: str,
    user_id: str,
    code_challenge: str,
    redirect_uri: str,
    scopes: List[str]
) -> str:
    """Create authorization code with short expiration."""
    
    code = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=AUTHORIZATION_CODE_EXPIRE_MINUTES)
    
    await authorization_code_repository.create(
        code=code,
        client_id=client_id,
        user_id=user_id,
        code_challenge=code_challenge,
        redirect_uri=redirect_uri,
        scopes=scopes,
        expires_at=expires_at
    )
    
    return code
```

**Single-use Enforcement:**
```python
async def exchange_authorization_code(code: str) -> Optional[AuthorizationCodeData]:
    """Exchange authorization code (single use)."""
    
    # Atomic read and delete operation
    auth_data = await authorization_code_repository.get_and_delete(code)
    
    if not auth_data:
        return None
    
    # Check expiration
    if auth_data.expires_at < datetime.utcnow():
        return None
    
    return auth_data
```

## Frontend Implementation

### Simple Template Strategy

The OAuth 2.1 implementation uses server-side templates for user interaction:

**Authorization Template:**
```html
<!-- authorization.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Request</title>
    <link rel="stylesheet" href="/static/css/oauth.css">
</head>
<body>
    <div class="auth-container">
        <h2>{{ client.client_name }} is requesting access</h2>
        
        <div class="scope-list">
            <h3>This application would like to:</h3>
            <ul>
                {% for scope in requested_scopes %}
                <li>{{ scopes[scope].description }}</li>
                {% endfor %}
            </ul>
        </div>
        
        <form method="post" action="/authorize">
            <!-- Hidden form fields -->
            {% for key, value in form_data.items() %}
            <input type="hidden" name="{{ key }}" value="{{ value }}">
            {% endfor %}
            
            <div class="auth-actions">
                <button type="submit" name="approve" value="true" class="btn-approve">
                    Allow
                </button>
                <button type="submit" name="approve" value="false" class="btn-deny">
                    Deny
                </button>
            </div>
        </form>
    </div>
</body>
</html>
```

**CSS Styling:**
```css
/* oauth.css */
.auth-container {
    max-width: 400px;
    margin: 100px auto;
    padding: 40px;
    border: 1px solid #ddd;
    border-radius: 8px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
}

.scope-list {
    margin: 20px 0;
    padding: 20px;
    background-color: #f8f9fa;
    border-radius: 4px;
}

.auth-actions {
    display: flex;
    gap: 12px;
    margin-top: 30px;
}

.btn-approve, .btn-deny {
    flex: 1;
    padding: 12px 24px;
    border: none;
    border-radius: 4px;
    font-weight: 600;
    cursor: pointer;
}

.btn-approve {
    background-color: #28a745;
    color: white;
}

.btn-deny {
    background-color: #dc3545;
    color: white;
}
```

## CLI Administration

### OAuth Client Management

```bash
# Create confidential OAuth client
authly-admin client create \
  --name "Web Application" \
  --type confidential \
  --redirect-uri "https://webapp.example.com/callback" \
  --scope "read write admin"

# Create public OAuth client (mobile/SPA)
authly-admin client create \
  --name "Mobile App" \
  --type public \
  --redirect-uri "com.example.app://callback" \
  --scope "read"

# List all clients
authly-admin client list --output json

# Show client details
authly-admin client show "client-id-uuid"

# Regenerate client secret
authly-admin client regenerate-secret "client-id-uuid"
```

### Scope Management

```bash
# Create OAuth scopes
authly-admin scope create --name "read" --description "Read access" --default
authly-admin scope create --name "write" --description "Write access"
authly-admin scope create --name "admin" --description "Administrative access"

# List all scopes
authly-admin scope list

# Show default scopes
authly-admin scope defaults
```

## Testing Architecture

### Comprehensive Test Coverage

**171/171 Tests Passing (100% Success Rate)**

Test organization:
```
tests/
├── test_oauth_repositories.py     # 18 tests - Database integration
├── test_oauth_services.py         # 28 tests - Business logic
├── test_oauth_dependencies.py     # 15 tests - FastAPI dependencies
├── test_oauth_discovery.py        # 16 tests - Discovery endpoint
├── test_oauth_authorization.py    # 11 tests - Authorization flow
├── test_oauth_apis.py             # OAuth API endpoints
├── test_oauth_revocation.py       # 11 tests - Token revocation
├── test_oauth_templates.py        # 11 tests - Frontend templates
├── test_admin_cli.py              # 14 tests - CLI administration
└── test_auth.py                   # Enhanced with OAuth support
```

### Test Examples

**Authorization Flow Test:**
```python
@pytest.mark.asyncio
async def test_complete_oauth_flow():
    """Test complete OAuth 2.1 authorization code flow with PKCE."""
    
    # Generate PKCE pair
    code_verifier, code_challenge = generate_pkce_pair()
    
    # Step 1: Authorization request
    auth_response = await client.get("/authorize", params={
        "response_type": "code",
        "client_id": test_client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "read write",
        "state": "random-state",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    })
    assert auth_response.status_code == 200
    
    # Step 2: User consent (simulate form submission)
    consent_response = await client.post("/authorize", data={
        "approve": "true",
        "client_id": test_client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "read write",
        "state": "random-state",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    })
    
    # Extract authorization code from redirect
    assert consent_response.status_code == 302
    location = consent_response.headers["location"]
    auth_code = extract_code_from_callback_url(location)
    
    # Step 3: Token exchange
    token_response = await client.post("/auth/token", data={
        "grant_type": "authorization_code",
        "code": auth_code,
        "client_id": test_client.client_id,
        "client_secret": test_client_secret,
        "code_verifier": code_verifier,
        "redirect_uri": "https://example.com/callback"
    })
    
    assert token_response.status_code == 200
    token_data = token_response.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    assert token_data["scope"] == "read write"
```

**PKCE Security Test:**
```python
@pytest.mark.asyncio
async def test_pkce_verification_failure():
    """Test PKCE verification prevents code interception attacks."""
    
    # Create authorization code with valid PKCE challenge
    code_verifier, code_challenge = generate_pkce_pair()
    auth_code = await create_test_authorization_code(
        code_challenge=code_challenge
    )
    
    # Try to exchange with wrong code_verifier
    wrong_verifier, _ = generate_pkce_pair()
    
    token_response = await client.post("/auth/token", data={
        "grant_type": "authorization_code",
        "code": auth_code,
        "client_id": test_client.client_id,
        "client_secret": test_client_secret,
        "code_verifier": wrong_verifier,
        "redirect_uri": "https://example.com/callback"
    })
    
    assert token_response.status_code == 400
    assert "invalid_grant" in token_response.json()["error"]
```

## Standards Compliance

### RFC Compliance Matrix

| RFC | Feature | Status | Implementation |
|-----|---------|--------|----------------|
| RFC 6749 | OAuth 2.0 Authorization Framework | ✅ Complete | Core authorization code flow |
| RFC 7636 | PKCE | ✅ Complete | Mandatory S256 method |
| RFC 7009 | Token Revocation | ✅ Complete | `/auth/revoke` endpoint |
| RFC 8414 | Authorization Server Metadata | ✅ Complete | `/.well-known/oauth-authorization-server` |
| RFC 8252 | OAuth 2.0 for Native Apps | ✅ Complete | PKCE requirements met |

### OAuth 2.1 Security Requirements

- ✅ **Mandatory PKCE**: All authorization code flows require PKCE
- ✅ **No Implicit Flow**: Only authorization code flow supported
- ✅ **Short Authorization Codes**: 10-minute maximum lifetime
- ✅ **Exact Redirect URI Matching**: No partial URI matching
- ✅ **State Parameter**: CSRF protection for authorization requests
- ✅ **Client Authentication**: Secure methods for confidential clients

## Performance Optimizations

### Database Optimizations

**Efficient Queries:**
```sql
-- Optimized client lookup with scopes
SELECT c.*, array_agg(s.scope_name) as scopes
FROM clients c
LEFT JOIN client_scopes cs ON c.id = cs.client_id
LEFT JOIN scopes s ON cs.scope_id = s.id
WHERE c.client_id = $1 AND c.is_active = true
GROUP BY c.id;

-- Fast authorization code cleanup
DELETE FROM authorization_codes 
WHERE expires_at < NOW() - INTERVAL '1 hour';
```

**Connection Pooling:**
```python
# Async connection pool for high performance
pool = AsyncConnectionPool(
    conninfo=config.database_url,
    min_size=5,
    max_size=20,
    timeout=30.0
)
```

### Caching Strategies

**Scope Caching:**
```python
@lru_cache(maxsize=1, ttl=3600)
async def get_cached_active_scopes() -> List[OAuthScope]:
    """Cache active scopes for discovery endpoint."""
    return await scope_repository.get_active_scopes()
```

**Client Validation Caching:**
```python
@lru_cache(maxsize=100, ttl=300)
async def get_cached_client(client_id: str) -> Optional[OAuthClient]:
    """Cache frequently accessed clients."""
    return await client_repository.get_by_client_id(client_id)
```

## Migration and Deployment

### Backward Compatibility

The OAuth 2.1 implementation maintains full backward compatibility:

```python
@router.post("/auth/token")
async def enhanced_token_endpoint(
    grant_type: str,
    # Existing password grant parameters
    username: Optional[str] = None,
    password: Optional[str] = None,
    # New OAuth 2.1 parameters
    code: Optional[str] = None,
    code_verifier: Optional[str] = None,
    client_id: Optional[str] = None
):
    """Multi-grant token endpoint supporting both password and authorization_code."""
    
    if grant_type == "password":
        # Existing password grant logic (unchanged)
        return await handle_password_grant(username, password)
    
    elif grant_type == "authorization_code":
        # New OAuth 2.1 authorization code grant
        return await handle_authorization_code_grant(code, code_verifier, client_id)
    
    else:
        raise HTTPException(400, "Unsupported grant type")
```

### Deployment Procedures

**Database Migration:**
```sql
-- Add OAuth tables to existing database
\i oauth_schema.sql

-- Create default scopes
INSERT INTO scopes (scope_name, description, is_default) VALUES
('read', 'Read access to user data', true),
('write', 'Write access to user data', false),
('admin', 'Administrative access', false);
```

**Configuration Updates:**
```bash
# Add OAuth-specific environment variables
export OAUTH_ENABLED=true
export AUTHORIZATION_CODE_EXPIRE_MINUTES=10
export PKCE_REQUIRED=true
export OAUTH_TEMPLATES_DIR="/app/templates/oauth"
```

### Monitoring and Metrics

**OAuth-specific Metrics:**
```python
# Prometheus metrics for OAuth operations
oauth_authorizations_total = Counter('oauth_authorizations_total', 'OAuth authorization requests')
oauth_token_exchanges_total = Counter('oauth_token_exchanges_total', 'OAuth token exchanges')
oauth_revocations_total = Counter('oauth_revocations_total', 'OAuth token revocations')
oauth_discovery_requests_total = Counter('oauth_discovery_requests_total', 'OAuth discovery requests')

# Track authorization code lifetime
authorization_code_duration = Histogram(
    'oauth_authorization_code_duration_seconds',
    'Time between authorization code creation and exchange'
)
```

## Integration Examples

### JavaScript Web Application

```javascript
// Complete OAuth 2.1 authorization code flow with PKCE
class AuthlyOAuthClient {
    constructor(clientId, redirectUri, authServerUrl) {
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.authServerUrl = authServerUrl;
    }
    
    // Generate PKCE pair
    async generatePKCE() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        const codeVerifier = btoa(String.fromCharCode(...array))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        
        return { codeVerifier, codeChallenge };
    }
    
    // Start authorization flow
    async authorize(scopes = ['read', 'profile']) {
        const { codeVerifier, codeChallenge } = await this.generatePKCE();
        const state = crypto.getRandomValues(new Uint32Array(1))[0].toString(16);
        
        // Store for later use
        sessionStorage.setItem('oauth_code_verifier', codeVerifier);
        sessionStorage.setItem('oauth_state', state);
        
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            scope: scopes.join(' '),
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        window.location.href = `${this.authServerUrl}/authorize?${params}`;
    }
    
    // Handle callback and exchange code for tokens
    async handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');
        
        if (error) {
            throw new Error(`OAuth error: ${error}`);
        }
        
        // Verify state
        const storedState = sessionStorage.getItem('oauth_state');
        if (state !== storedState) {
            throw new Error('Invalid state parameter');
        }
        
        // Exchange code for tokens
        const codeVerifier = sessionStorage.getItem('oauth_code_verifier');
        const tokenResponse = await fetch(`${this.authServerUrl}/auth/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                grant_type: 'authorization_code',
                code: code,
                client_id: this.clientId,
                code_verifier: codeVerifier,
                redirect_uri: this.redirectUri
            })
        });
        
        if (!tokenResponse.ok) {
            throw new Error('Token exchange failed');
        }
        
        const tokens = await tokenResponse.json();
        
        // Store tokens securely
        localStorage.setItem('access_token', tokens.access_token);
        localStorage.setItem('refresh_token', tokens.refresh_token);
        
        // Clean up
        sessionStorage.removeItem('oauth_code_verifier');
        sessionStorage.removeItem('oauth_state');
        
        return tokens;
    }
}

// Usage example
const client = new AuthlyOAuthClient(
    'your-client-id',
    'https://yourapp.com/callback',
    'https://auth.example.com'
);

// Start authorization
await client.authorize(['read', 'write', 'profile']);

// In callback page
try {
    const tokens = await client.handleCallback();
    console.log('Authentication successful!', tokens);
} catch (error) {
    console.error('Authentication failed:', error);
}
```

### Python Client Application

```python
import asyncio
import base64
import hashlib
import secrets
import urllib.parse
from typing import Dict, Optional

import httpx

class AuthlyOAuthClient:
    """Python OAuth 2.1 client with PKCE support."""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, auth_server_url: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.auth_server_url = auth_server_url
        
    def generate_pkce_pair(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge
    
    def get_authorization_url(self, scopes: list[str] = None) -> tuple[str, str, str]:
        """Get authorization URL with PKCE parameters."""
        if scopes is None:
            scopes = ['read', 'profile']
            
        code_verifier, code_challenge = self.generate_pkce_pair()
        state = secrets.token_urlsafe(32)
        
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(scopes),
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{self.auth_server_url}/authorize?{urllib.parse.urlencode(params)}"
        return auth_url, code_verifier, state
    
    async def exchange_code_for_tokens(self, code: str, code_verifier: str) -> Dict[str, any]:
        """Exchange authorization code for access tokens."""
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.auth_server_url}/auth/token",
                json={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'code_verifier': code_verifier,
                    'redirect_uri': self.redirect_uri
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Token exchange failed: {response.text}")
            
            return response.json()
    
    async def refresh_tokens(self, refresh_token: str) -> Dict[str, any]:
        """Refresh access tokens."""
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.auth_server_url}/auth/token",
                json={
                    'grant_type': 'refresh_token',
                    'refresh_token': refresh_token,
                    'client_id': self.client_id,
                    'client_secret': self.client_secret
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Token refresh failed: {response.text}")
            
            return response.json()

# Usage example
async def main():
    client = AuthlyOAuthClient(
        client_id="your-client-id",
        client_secret="your-client-secret",
        redirect_uri="https://yourapp.com/callback",
        auth_server_url="https://auth.example.com"
    )
    
    # Step 1: Get authorization URL
    auth_url, code_verifier, state = client.get_authorization_url(['read', 'write'])
    print(f"Visit this URL: {auth_url}")
    
    # Step 2: User visits URL, grants permission, gets redirected with code
    authorization_code = input("Enter the authorization code from callback: ")
    
    # Step 3: Exchange code for tokens
    tokens = await client.exchange_code_for_tokens(authorization_code, code_verifier)
    print(f"Access token: {tokens['access_token']}")
    print(f"Refresh token: {tokens['refresh_token']}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Troubleshooting

### Common Issues and Solutions

#### 1. PKCE Verification Failures

**Problem**: `invalid_grant` error during token exchange
```json
{
  "error": "invalid_grant",
  "error_description": "PKCE verification failed - code_verifier does not match code_challenge"
}
```

**Solutions**:
- Ensure code_verifier used in token exchange matches the one used to generate code_challenge
- Verify SHA256 hashing is implemented correctly: `base64url(sha256(code_verifier))`
- Check that code_challenge_method is set to "S256"

**Debug Steps**:
```python
# Verify PKCE generation
import base64
import hashlib

code_verifier = "your-code-verifier"
expected_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().rstrip('=')

print(f"Code verifier: {code_verifier}")
print(f"Expected challenge: {expected_challenge}")
```

#### 2. Client Authentication Failures

**Problem**: `invalid_client` error
```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

**Solutions**:
- For confidential clients, ensure client_secret is provided
- Verify client_id and client_secret are correct
- Check if client is active: `authly-admin client show <client-id>`
- Ensure proper authentication method (Basic Auth or POST body)

#### 3. Authorization Code Expiration

**Problem**: Authorization code has expired
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired or invalid"
}
```

**Solutions**:
- Authorization codes expire in 10 minutes - exchange them promptly
- Implement proper error handling for expired codes
- Consider the time between authorization and token exchange

#### 4. Scope Validation Issues

**Problem**: Invalid or unauthorized scopes
```json
{
  "error": "invalid_scope",
  "error_description": "Requested scope not available for client"
}
```

**Solutions**:
- Check available scopes: `authly-admin scope list`
- Verify client has access to requested scopes: `authly-admin client show <client-id>`
- Ensure scope names are exact matches (case-sensitive)

#### 5. Redirect URI Mismatches

**Problem**: Redirect URI validation fails
```json
{
  "error": "invalid_request",
  "error_description": "Invalid redirect_uri"
}
```

**Solutions**:
- Ensure redirect_uri in authorization request exactly matches registered URI
- Check for typos, trailing slashes, and protocol differences
- Use `authly-admin client show <client-id>` to verify registered URIs

### Debug Tools

#### Check OAuth Client Configuration
```bash
# Verify client exists and is active
authly-admin client show "your-client-id"

# List all available scopes
authly-admin scope list

# Check system status
authly-admin status --verbose
```

#### Test OAuth Flow with curl
```bash
# Test discovery endpoint
curl -s https://auth.example.com/.well-known/oauth-authorization-server | jq

# Test authorization endpoint (will return HTML form)
curl -v "https://auth.example.com/authorize?response_type=code&client_id=test&redirect_uri=https://example.com/callback&scope=read&state=test&code_challenge=test&code_challenge_method=S256"

# Test token endpoint
curl -X POST https://auth.example.com/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "authorization-code",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "code_verifier": "code-verifier",
    "redirect_uri": "https://example.com/callback"
  }'
```

#### Database Debugging
```sql
-- Check authorization codes
SELECT * FROM authorization_codes WHERE expires_at > NOW();

-- Check client configuration
SELECT c.*, array_agg(s.scope_name) as scopes
FROM clients c
LEFT JOIN client_scopes cs ON c.id = cs.client_id
LEFT JOIN scopes s ON cs.scope_id = s.id
WHERE c.client_id = 'your-client-id'
GROUP BY c.id;

-- Check active tokens
SELECT * FROM tokens WHERE expires_at > NOW() ORDER BY created_at DESC LIMIT 10;
```

For additional troubleshooting, see the [Troubleshooting Guide](troubleshooting-guide.md).

## Conclusion

The OAuth 2.1 implementation in Authly represents a comprehensive, standards-compliant authorization server with:

### Key Achievements

- **Full OAuth 2.1 Compliance**: All required features implemented
- **Enterprise Security**: PKCE, client authentication, token revocation
- **100% Test Coverage**: 171/171 tests passing with comprehensive scenarios
- **Production Ready**: Performance optimizations, monitoring, scalability
- **Backward Compatible**: Existing authentication methods preserved
- **Professional Admin Tools**: CLI interface for OAuth management

### Technical Excellence

- **Clean Architecture**: Layered design with clear separation of concerns
- **Security First**: All security requirements exceeded
- **Performance Optimized**: Efficient database queries and caching
- **Standards Compliant**: Full RFC implementation with validation
- **Comprehensive Testing**: Real database integration testing

### Future Enhancements

The implementation provides a solid foundation for:
- Enhanced frontend user experience
- Advanced security features (DPoP, mTLS)
- Enterprise integrations (LDAP, SAML)
- Performance scaling (Redis caching)
- Monitoring and analytics enhancements

This OAuth 2.1 implementation transforms Authly into a production-ready authorization server suitable for enterprise deployment while maintaining its core strengths in simplicity, security, and reliability.