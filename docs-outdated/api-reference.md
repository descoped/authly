# API Reference

> **Audience**: Developers, Integration Engineers, API Consumers  
> **Prerequisites**: Understanding of OAuth 2.1 flows and HTTP APIs  
> **Related Documentation**: [OAuth 2.1 Implementation](oauth-2.1-implementation.md) • [Security Features](security-features.md) • [Troubleshooting Guide](troubleshooting-guide.md)

This comprehensive API reference covers all endpoints in Authly's OAuth 2.1 authorization server, including authentication, authorization, token management, and administrative operations.

## Table of Contents

- [Base Information](#base-information)
- [OAuth 2.1 Authorization](#oauth-21-authorization)
- [Token Management](#token-management)
- [User Management](#user-management)
- [Client Administration](#client-administration)
- [System Information](#system-information)
- [Error Handling](#error-handling)
- [Authentication Methods](#authentication-methods)
- [Rate Limiting](#rate-limiting)

## Base Information

**Base URL:** `https://auth.example.com`  
**API Version:** `v1`  
**Authentication:** Bearer Token or OAuth 2.1 flows  
**Content-Type:** `application/json`  
**Standards Compliance:** OAuth 2.1, RFC 6749, RFC 7636, RFC 7009, RFC 8414

**Endpoint Categories:**
- OAuth 2.1 Authorization
- Token Management  
- User Management
- Client Administration
- System Information

---

## OAuth 2.1 Authorization

### Authorization Endpoint

#### `GET /authorize`

Initiates OAuth 2.1 authorization code flow with PKCE support.

**Description:** Displays authorization consent form for user approval of OAuth client access request.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `response_type` | string | ✓ | Must be `code` (OAuth 2.1 only supports authorization code flow) |
| `client_id` | string | ✓ | OAuth client identifier |
| `redirect_uri` | string | ✓ | Client redirect URI (must exactly match registered URI) |
| `scope` | string | | Space-separated list of requested scopes |
| `state` | string | ✓ | CSRF protection parameter (client-generated random value) |
| `code_challenge` | string | ✓ | PKCE code challenge (base64url-encoded SHA256 hash) |
| `code_challenge_method` | string | | PKCE method, must be `S256` (OAuth 2.1 requirement) |

**Example Request:**
```http
GET /authorize?response_type=code&client_id=your-client-id&redirect_uri=https%3A%2F%2Fyourapp.com%2Fcallback&scope=read%20write%20profile&state=random-state-value&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256 HTTP/1.1
Host: auth.example.com
```

**Response (200 OK):**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Request</title>
</head>
<body>
    <h2>Your App is requesting access</h2>
    <p>This application would like to:</p>
    <ul>
        <li>Read your profile information</li>
        <li>Access your data</li>
        <li>Write to your account</li>
    </ul>
    <form method="post" action="/authorize">
        <!-- Authorization form -->
    </form>
</body>
</html>
```

**Error Responses:**

| Status Code | Error | Description |
|-------------|--------|-------------|
| 400 | `invalid_request` | Missing or invalid required parameters |
| 400 | `invalid_client` | Client not found or inactive |
| 400 | `invalid_scope` | Requested scope not available for client |
| 400 | `unsupported_response_type` | Only `code` response type supported |

---

#### `POST /authorize`

Processes user consent and generates authorization code.

**Description:** Handles user authentication and consent, then generates authorization code for token exchange.

**Request Body:**
```json
{
  "response_type": "code",
  "client_id": "your-client-id",
  "redirect_uri": "https://yourapp.com/callback",
  "scope": "read write profile",
  "state": "random-state-value",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256",
  "username": "user@example.com",
  "password": "userpassword",
  "approve": "true"
}
```

**Success Response (302 Found):**
```http
HTTP/1.1 302 Found
Location: https://yourapp.com/callback?code=authorization_code_here&state=random-state-value
```

**Error Response (400 Bad Request):**
```json
{
  "error": "access_denied",
  "error_description": "The resource owner denied the request",
  "state": "random-state-value"
}
```

**Error Codes:**

| Error Code | Description |
|------------|-------------|
| `access_denied` | User denied authorization request |
| `invalid_request` | Invalid or missing parameters |
| `invalid_client` | Client authentication failed |
| `unauthorized_client` | Client not authorized for this grant type |
| `invalid_scope` | Invalid scope parameter |
| `server_error` | Internal server error |

---

### OAuth Discovery Endpoint

#### `GET /.well-known/oauth-authorization-server`

OAuth 2.1 server metadata endpoint (RFC 8414 compliant).

**Description:** Provides OAuth authorization server metadata for client auto-configuration.

**Example Request:**
```http
GET /.well-known/oauth-authorization-server HTTP/1.1
Host: auth.example.com
Accept: application/json
```

**Response (200 OK):**
```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/auth/token",
  "revocation_endpoint": "https://auth.example.com/auth/revoke",
  "scopes_supported": [
    "read",
    "write", 
    "profile",
    "admin"
  ],
  "response_types_supported": [
    "code"
  ],
  "grant_types_supported": [
    "authorization_code",
    "password",
    "refresh_token"
  ],
  "code_challenge_methods_supported": [
    "S256"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ],
  "token_endpoint_auth_signing_alg_values_supported": [
    "HS256"
  ],
  "service_documentation": "https://auth.example.com/docs",
  "ui_locales_supported": [
    "en"
  ]
}
```

---

## Token Management

### Enhanced Token Endpoint

#### `POST /auth/token`

Multi-grant token endpoint supporting password, authorization_code, and refresh_token grants.

**Description:** Issues access and refresh tokens using various OAuth 2.1 grant types with backward compatibility.

**Grant Type: Password (Existing)**

**Request Body:**
```json
{
  "grant_type": "password",
  "username": "user@example.com",
  "password": "userpassword",
  "scope": "read write"
}
```

**Grant Type: Authorization Code (OAuth 2.1)**

**Request Body:**
```json
{
  "grant_type": "authorization_code",
  "code": "authorization_code_from_callback",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "code_verifier": "original_code_verifier_for_pkce",
  "redirect_uri": "https://yourapp.com/callback"
}
```

**Grant Type: Refresh Token**

**Request Body:**
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "existing_refresh_token",
  "scope": "read write"
}
```

**Client Authentication Methods:**

1. **HTTP Basic Authentication:**
```http
Authorization: Basic base64(client_id:client_secret)
```

2. **Client Credentials in Body:**
```json
{
  "grant_type": "authorization_code",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  // ... other parameters
}
```

**Success Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "refresh_token": "refresh_token_here",
  "scope": "read write profile"
}
```

**Error Responses:**

| Status Code | Error | Description |
|-------------|--------|-------------|
| 400 | `invalid_request` | Missing or malformed request parameters |
| 400 | `invalid_client` | Client authentication failed |
| 400 | `invalid_grant` | Invalid authorization code or credentials |
| 400 | `unauthorized_client` | Client not authorized for grant type |
| 400 | `unsupported_grant_type` | Grant type not supported |
| 400 | `invalid_scope` | Requested scope invalid or exceeds granted scope |

**PKCE-Specific Errors:**
```json
{
  "error": "invalid_grant",
  "error_description": "PKCE verification failed - code_verifier does not match code_challenge"
}
```

---

### Token Revocation Endpoint

#### `POST /auth/revoke`

RFC 7009 compliant token revocation endpoint.

**Description:** Revokes access or refresh tokens to immediately invalidate them.

**Authentication:** Requires client authentication (for confidential clients).

**Request Body:**
```json
{
  "token": "token_to_revoke",
  "token_type_hint": "access_token"
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | ✓ | Token to revoke (access or refresh) |
| `token_type_hint` | string | | Hint about token type: `access_token` or `refresh_token` |

**Client Authentication:**
```http
Authorization: Basic base64(client_id:client_secret)
```

**Success Response (200 OK):**
```json
{
  "revoked": true
}
```

**Note:** Per RFC 7009, this endpoint always returns 200 OK to prevent token enumeration attacks, regardless of whether the token was valid.

**Example with cURL:**
```bash
curl -X POST https://auth.example.com/auth/revoke \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'client_id:client_secret' | base64)" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type_hint": "access_token"
  }'
```

---

### Token Validation

#### `GET /auth/validate`

Validates and returns information about a token.

**Description:** Validates token and returns token metadata for resource servers.

**Authentication:** Bearer token required.

**Request Headers:**
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Success Response (200 OK):**
```json
{
  "active": true,
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_id": "your-client-id",
  "scope": "read write profile",
  "token_type": "Bearer",
  "exp": 1640995200,
  "iat": 1640991600,
  "iss": "authly"
}
```

**Invalid Token Response (401 Unauthorized):**
```json
{
  "error": "invalid_token",
  "error_description": "Token is expired, revoked, or invalid"
}
```

---

## User Management

### User Registration

#### `POST /auth/register`

Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "username": "username",
  "password": "SecurePassword123!"
}
```

**Success Response (201 Created):**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "username": "username",
  "is_verified": false,
  "message": "Registration successful. Please check your email for verification."
}
```

**Error Response (400 Bad Request):**
```json
{
  "error": "validation_error",
  "details": {
    "email": ["Email already registered"],
    "password": ["Password must be at least 12 characters"]
  }
}
```

---

### User Profile

#### `GET /api/v1/users/me`

Get current user profile information.

**Authentication:** Bearer token required with `profile` scope.

**Request Headers:**
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Success Response (200 OK):**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "username": "username",
  "is_verified": true,
  "is_admin": false,
  "created_at": "2024-01-01T12:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z"
}
```

**Insufficient Scope Response (403 Forbidden):**
```json
{
  "error": "insufficient_scope",
  "error_description": "Token lacks required scope: profile"
}
```

---

## Client Administration

### OAuth Client Management

#### `POST /admin/oauth/clients`

Create a new OAuth client.

**Authentication:** Bearer token required with `admin` scope.

**Request Body:**
```json
{
  "client_name": "My Application",
  "client_type": "confidential",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/admin/callback"
  ],
  "client_uri": "https://myapp.com",
  "logo_uri": "https://myapp.com/logo.png",
  "scopes": ["read", "write", "profile"],
  "auth_method": "client_secret_basic"
}
```

**Success Response (201 Created):**
```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_name": "My Application",
  "client_type": "confidential",
  "client_secret": "cs_live_abc123def456...",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/admin/callback"
  ],
  "client_uri": "https://myapp.com",
  "logo_uri": "https://myapp.com/logo.png",
  "scopes": ["read", "write", "profile"],
  "auth_method": "client_secret_basic",
  "require_pkce": true,
  "is_active": true,
  "created_at": "2024-01-01T12:00:00Z"
}
```

---

#### `GET /admin/oauth/clients`

List OAuth clients with pagination.

**Authentication:** Bearer token required with `admin` scope.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Number of clients to return (max 100) |
| `offset` | integer | 0 | Number of clients to skip |
| `active` | boolean | true | Filter by active status |

**Example Request:**
```http
GET /admin/oauth/clients?limit=10&offset=0&active=true HTTP/1.1
Authorization: Bearer admin_token_here
```

**Success Response (200 OK):**
```json
{
  "clients": [
    {
      "client_id": "550e8400-e29b-41d4-a716-446655440000",
      "client_name": "My Application",
      "client_type": "confidential",
      "scopes": ["read", "write", "profile"],
      "is_active": true,
      "created_at": "2024-01-01T12:00:00Z"
    }
  ],
  "pagination": {
    "total": 25,
    "limit": 10,
    "offset": 0,
    "has_more": true
  }
}
```

---

#### `GET /admin/oauth/clients/{client_id}`

Get detailed OAuth client information.

**Authentication:** Bearer token required with `admin` scope.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `client_id` | string | OAuth client identifier |

**Success Response (200 OK):**
```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_name": "My Application",
  "client_type": "confidential",
  "redirect_uris": [
    "https://myapp.com/callback"
  ],
  "client_uri": "https://myapp.com",
  "logo_uri": "https://myapp.com/logo.png",
  "scopes": ["read", "write", "profile"],
  "auth_method": "client_secret_basic",
  "require_pkce": true,
  "is_active": true,
  "created_at": "2024-01-01T12:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z",
  "stats": {
    "total_authorizations": 1250,
    "active_tokens": 45,
    "last_used": "2024-01-15T10:30:00Z"
  }
}
```

**Not Found Response (404 Not Found):**
```json
{
  "error": "client_not_found",
  "error_description": "OAuth client not found"
}
```

---

#### `PUT /admin/oauth/clients/{client_id}`

Update OAuth client configuration.

**Authentication:** Bearer token required with `admin` scope.

**Request Body:**
```json
{
  "client_name": "Updated Application Name",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/new-callback"
  ],
  "client_uri": "https://newdomain.com",
  "is_active": true
}
```

**Success Response (200 OK):**
```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_name": "Updated Application Name",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/new-callback"
  ],
  "client_uri": "https://newdomain.com",
  "updated_at": "2024-01-15T14:30:00Z"
}
```

---

#### `POST /admin/oauth/clients/{client_id}/regenerate-secret`

Regenerate OAuth client secret.

**Authentication:** Bearer token required with `admin` scope.

**Request Body:**
```json
{
  "confirm": true
}
```

**Success Response (200 OK):**
```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "cs_live_new_secret_abc123...",
  "regenerated_at": "2024-01-15T14:30:00Z",
  "warning": "Store this secret securely - it will not be shown again"
}
```

---

#### `DELETE /admin/oauth/clients/{client_id}`

Deactivate OAuth client (soft delete).

**Authentication:** Bearer token required with `admin` scope.

**Success Response (200 OK):**
```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "deactivated": true,
  "tokens_revoked": 23,
  "deactivated_at": "2024-01-15T14:30:00Z"
}
```

---

### OAuth Scope Management

#### `POST /admin/oauth/scopes`

Create a new OAuth scope.

**Authentication:** Bearer token required with `admin` scope.

**Request Body:**
```json
{
  "scope_name": "user:profile",
  "description": "Access to detailed user profile information",
  "is_default": false
}
```

**Success Response (201 Created):**
```json
{
  "scope_id": "660f9500-f39c-52e5-b827-557766551111",
  "scope_name": "user:profile",
  "description": "Access to detailed user profile information",
  "is_default": false,
  "is_active": true,
  "created_at": "2024-01-15T14:30:00Z"
}
```

---

#### `GET /admin/oauth/scopes`

List all OAuth scopes.

**Authentication:** Bearer token required with `admin` scope.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `active` | boolean | true | Filter by active status |
| `default` | boolean | | Filter by default status |

**Success Response (200 OK):**
```json
{
  "scopes": [
    {
      "scope_id": "660f9500-f39c-52e5-b827-557766551111",
      "scope_name": "read",
      "description": "Read access to user data",
      "is_default": true,
      "is_active": true,
      "clients_count": 15,
      "created_at": "2024-01-01T12:00:00Z"
    },
    {
      "scope_id": "770fa600-f49d-63f6-c938-668877662222",
      "scope_name": "write",
      "description": "Write access to user data",
      "is_default": false,
      "is_active": true,
      "clients_count": 8,
      "created_at": "2024-01-01T12:00:00Z"
    }
  ]
}
```

---

## System Information

### Health Check

#### `GET /health`

System health check endpoint.

**Description:** Provides application health status for monitoring systems.

**Success Response (200 OK):**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T14:30:00Z",
  "version": "1.0.0",
  "database": {
    "status": "connected",
    "response_time_ms": 2.3
  },
  "oauth": {
    "enabled": true,
    "active_clients": 15,
    "active_scopes": 8
  }
}
```

**Unhealthy Response (503 Service Unavailable):**
```json
{
  "status": "unhealthy",
  "timestamp": "2024-01-15T14:30:00Z",
  "errors": [
    "Database connection failed",
    "High response times detected"
  ]
}
```

---

### System Status

#### `GET /admin/status`

Detailed system status information.

**Authentication:** Bearer token required with `admin` scope.

**Success Response (200 OK):**
```json
{
  "system": {
    "status": "healthy",
    "uptime_seconds": 86400,
    "version": "1.0.0",
    "environment": "production"
  },
  "database": {
    "status": "connected",
    "pool_active": 8,
    "pool_idle": 2,
    "response_time_ms": 2.3
  },
  "oauth": {
    "enabled": true,
    "pkce_required": true,
    "discovery_enabled": true,
    "supported_grants": [
      "authorization_code",
      "password", 
      "refresh_token"
    ]
  },
  "statistics": {
    "total_users": 1247,
    "active_clients": 15,
    "active_scopes": 8,
    "tokens_issued_24h": 2341,
    "authorizations_24h": 156
  },
  "performance": {
    "avg_response_time_ms": 45,
    "requests_per_minute": 850,
    "error_rate_percent": 0.02
  }
}
```

---

## Error Handling

### Standard OAuth Error Format

All OAuth endpoints return errors in RFC-compliant format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable error description",
  "error_uri": "https://auth.example.com/docs/errors#error_code",
  "state": "original_state_parameter"
}
```

### Common OAuth Error Codes

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `invalid_request` | 400 | Missing or malformed request parameter |
| `invalid_client` | 401 | Client authentication failed |
| `invalid_grant` | 400 | Invalid authorization grant |
| `unauthorized_client` | 400 | Client not authorized for grant type |
| `unsupported_grant_type` | 400 | Grant type not supported |
| `invalid_scope` | 400 | Invalid scope parameter |
| `access_denied` | 400 | User denied authorization request |
| `unsupported_response_type` | 400 | Response type not supported |
| `server_error` | 500 | Internal server error |
| `temporarily_unavailable` | 503 | Service temporarily unavailable |

### Application-Specific Errors

```json
{
  "error": "validation_error",
  "details": {
    "field_name": ["Field-specific error message"],
    "another_field": ["Another error message"]
  }
}
```

### Rate Limiting Errors

```json
{
  "error": "rate_limit_exceeded",
  "error_description": "Rate limit exceeded. Try again later.",
  "retry_after": 60,
  "limit": 100,
  "window": 60
}
```

---

## Authentication Methods

### Bearer Token Authentication

Most API endpoints require Bearer token authentication:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### OAuth Client Authentication

For OAuth client endpoints, use HTTP Basic authentication:

```http
Authorization: Basic base64(client_id:client_secret)
```

### Required Scopes

| Endpoint Category | Required Scope |
|------------------|----------------|
| User Profile | `profile` |
| User Data Read | `read` |
| User Data Write | `write` |
| Admin Operations | `admin` |

---

## Rate Limiting

All endpoints implement rate limiting:

| Endpoint Type | Limit | Window |
|---------------|-------|--------|
| Authentication | 10 requests | 1 minute |
| API Endpoints | 100 requests | 1 minute |
| Discovery | 1000 requests | 1 minute |

Rate limit headers are included in responses:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

---

## Response Codes

| Status Code | Description |
|-------------|-------------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 204 | No Content - Request successful, no response body |
| 400 | Bad Request - Invalid request parameters |
| 401 | Unauthorized - Authentication required or failed |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server error |
| 503 | Service Unavailable - Service temporarily unavailable |

This API reference provides comprehensive documentation for all Authly endpoints, ensuring developers can effectively integrate with the OAuth 2.1 authorization server.