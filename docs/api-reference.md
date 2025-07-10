# Authly API Reference

Complete REST API documentation for the Authly OAuth 2.1 + OpenID Connect 1.0 authorization server.

**Base URL**: `http://localhost:8000` (development) or your deployment URL  
**API Version**: v1  
**Standards**: OAuth 2.1, OpenID Connect 1.0, RFC 6749, RFC 7636, RFC 7009, RFC 8414

---

## 🔐 **OAuth 2.1 Authorization Server**

### **Authorization Endpoint**

#### **GET /oauth/authorize**
Initiates OAuth 2.1 authorization flow with consent UI.

**Query Parameters**:
```
response_type    string   required   Must be "code"
client_id        string   required   OAuth client identifier
redirect_uri     string   required   Registered redirect URI
scope           string   optional   Space-separated list of scopes
state           string   recommended CSRF protection parameter
code_challenge   string   required   PKCE code challenge (S256)
code_challenge_method string required Must be "S256"
```

**Example Request**:
```http
GET /oauth/authorize?response_type=code&client_id=your-client&redirect_uri=https://app.com/callback&scope=read%20write&state=xyz&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256
```

**Response**: HTML consent form for user authorization

#### **POST /oauth/authorize**
Processes user consent and generates authorization code.

**Form Data**:
```
username    string   required   User's username
password    string   required   User's password
consent     string   required   Must be "allow"
```

**Success Response**:
```http
HTTP/1.1 302 Found
Location: https://app.com/callback?code=auth_code_here&state=xyz
```

**Error Response**:
```http
HTTP/1.1 302 Found
Location: https://app.com/callback?error=access_denied&error_description=User%20denied%20access&state=xyz
```

---

### **Token Endpoint**

#### **POST /oauth/token**
Exchanges authorization code for access tokens.

**Headers**:
```
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)  // For confidential clients
```

**Form Data**:
```
grant_type      string   required   "authorization_code" or "refresh_token"
code           string   required   Authorization code (for authorization_code grant)
redirect_uri   string   required   Must match authorization request
code_verifier  string   required   PKCE code verifier
client_id      string   required   OAuth client identifier
refresh_token  string   required   Refresh token (for refresh_token grant)
```

**Authorization Code Grant Example**:
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=

grant_type=authorization_code&code=auth_code&redirect_uri=https://app.com/callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&client_id=your-client
```

**Success Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def502004c6c4e...",
  "scope": "read write"
}
```

**Error Response**:
```json
{
  "error": "invalid_grant",
  "error_description": "Invalid authorization code"
}
```

---

### **Token Revocation**

#### **POST /oauth/revoke**
Revokes access or refresh tokens (RFC 7009).

**Headers**:
```
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)
```

**Form Data**:
```
token           string   required   Token to revoke
token_type_hint string   optional   "access_token" or "refresh_token"
```

**Example Request**:
```http
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=

token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...&token_type_hint=access_token
```

**Success Response**:
```http
HTTP/1.1 200 OK
```

---

### **Server Discovery**

#### **GET /.well-known/oauth-authorization-server**
OAuth 2.1 server metadata (RFC 8414).

**Response**:
```json
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/oauth/authorize",
  "token_endpoint": "http://localhost:8000/oauth/token",
  "revocation_endpoint": "http://localhost:8000/oauth/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "password"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "scopes_supported": ["read", "write", "admin"]
}
```

---

## 🆔 **OpenID Connect 1.0**

### **UserInfo Endpoint**

#### **GET /oidc/userinfo**
Returns user claims based on access token scopes.

**Headers**:
```
Authorization: Bearer access_token_here
```

**Example Request**:
```http
GET /oidc/userinfo
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

**Success Response**:
```json
{
  "sub": "user123",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john@example.com",
  "email_verified": true
}
```

**Error Response**:
```json
{
  "error": "invalid_token",
  "error_description": "The access token is invalid"
}
```

---

### **JWKS Endpoint**

#### **GET /.well-known/jwks.json**
JSON Web Key Set for token signature verification.

**Response**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "rsa-key-1",
      "n": "0vx7agoebGcQSzuuiUiUXqjy...",
      "e": "AQAB"
    }
  ]
}
```

---

### **OIDC Discovery**

#### **GET /.well-known/openid_configuration**
OpenID Connect provider configuration.

**Response**:
```json
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/oauth/authorize",
  "token_endpoint": "http://localhost:8000/oauth/token",
  "userinfo_endpoint": "http://localhost:8000/oidc/userinfo",
  "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "HS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "claims_supported": ["sub", "name", "given_name", "family_name", "email", "email_verified"]
}
```

---

## 🔑 **Authentication API**

### **User Authentication**

#### **POST /auth/token**
Authenticate user and obtain tokens.

**Form Data**:
```
grant_type   string   required   "password"
username     string   required   User's username
password     string   required   User's password
scope        string   optional   Requested scopes
```

**Example Request**:
```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=john&password=secret&scope=read%20write
```

**Success Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def502004c6c4e...",
  "scope": "read write"
}
```

---

### **Token Refresh**

#### **POST /auth/refresh**
Refresh access token using refresh token.

**Form Data**:
```
grant_type     string   required   "refresh_token"
refresh_token  string   required   Valid refresh token
```

**Example Request**:
```http
POST /auth/refresh
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=def502004c6c4e...
```

**Success Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "abc123new_refresh...",
  "scope": "read write"
}
```

---

### **Logout**

#### **POST /auth/logout**
Invalidate user tokens and logout.

**Headers**:
```
Authorization: Bearer access_token_here
```

**Example Request**:
```http
POST /auth/logout
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

**Success Response**:
```json
{
  "message": "Successfully logged out"
}
```

---

## 👑 **Admin API**

All admin endpoints require authentication and admin privileges.

### **Admin Authentication**

#### **POST /admin/auth**
Authenticate for admin API access.

**Request Body**:
```json
{
  "username": "admin",
  "password": "admin_password"
}
```

**Success Response**:
```json
{
  "access_token": "admin_jwt_token...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

### **OAuth Client Management**

#### **GET /admin/clients**
List OAuth clients.

**Headers**:
```
Authorization: Bearer admin_token
```

**Query Parameters**:
```
limit    integer   optional   Number of clients to return (default: 20)
offset   integer   optional   Pagination offset (default: 0)
active   boolean   optional   Filter by active status
```

**Success Response**:
```json
{
  "clients": [
    {
      "id": "client-uuid",
      "client_id": "my-app",
      "client_name": "My Application",
      "client_type": "confidential",
      "redirect_uris": ["https://myapp.com/callback"],
      "is_active": true,
      "created_at": "2025-07-10T10:00:00Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

#### **POST /admin/clients**
Create new OAuth client.

**Request Body**:
```json
{
  "client_name": "My Application",
  "client_type": "confidential",
  "redirect_uris": ["https://myapp.com/callback"],
  "scopes": ["read", "write"]
}
```

**Success Response**:
```json
{
  "id": "client-uuid",
  "client_id": "generated-client-id",
  "client_secret": "generated-secret",
  "client_name": "My Application",
  "client_type": "confidential",
  "redirect_uris": ["https://myapp.com/callback"],
  "scopes": ["read", "write"],
  "is_active": true,
  "created_at": "2025-07-10T10:00:00Z"
}
```

#### **GET /admin/clients/{client_id}**
Get specific OAuth client details.

**Success Response**:
```json
{
  "id": "client-uuid",
  "client_id": "my-app",
  "client_name": "My Application",
  "client_type": "confidential",
  "redirect_uris": ["https://myapp.com/callback"],
  "scopes": ["read", "write"],
  "is_active": true,
  "created_at": "2025-07-10T10:00:00Z"
}
```

#### **PUT /admin/clients/{client_id}**
Update OAuth client.

**Request Body**:
```json
{
  "client_name": "Updated Application Name",
  "redirect_uris": ["https://myapp.com/callback", "https://myapp.com/callback2"],
  "is_active": true
}
```

#### **POST /admin/clients/{client_id}/regenerate-secret**
Regenerate client secret (confidential clients only).

**Success Response**:
```json
{
  "client_secret": "new-generated-secret"
}
```

#### **DELETE /admin/clients/{client_id}**
Deactivate OAuth client.

**Success Response**:
```http
HTTP/1.1 204 No Content
```

---

### **OAuth Scope Management**

#### **GET /admin/scopes**
List OAuth scopes.

**Success Response**:
```json
{
  "scopes": [
    {
      "id": "scope-uuid",
      "scope_name": "read",
      "description": "Read access to user data",
      "is_default": false,
      "is_active": true,
      "created_at": "2025-07-10T10:00:00Z"
    }
  ]
}
```

#### **POST /admin/scopes**
Create new OAuth scope.

**Request Body**:
```json
{
  "scope_name": "read",
  "description": "Read access to user data",
  "is_default": false
}
```

#### **GET /admin/scopes/{scope_name}**
Get specific scope details.

#### **PUT /admin/scopes/{scope_name}**
Update OAuth scope.

#### **DELETE /admin/scopes/{scope_name}**
Deactivate OAuth scope.

---

### **User Management**

#### **GET /admin/users**
List users (admin only).

**Query Parameters**:
```
limit    integer   optional   Number of users to return
offset   integer   optional   Pagination offset
active   boolean   optional   Filter by active status
admin    boolean   optional   Filter by admin status
```

**Success Response**:
```json
{
  "users": [
    {
      "id": "user-uuid",
      "username": "john",
      "email": "john@example.com",
      "is_active": true,
      "is_admin": false,
      "is_verified": true,
      "created_at": "2025-07-10T10:00:00Z",
      "last_login": "2025-07-10T12:00:00Z"
    }
  ],
  "total": 1
}
```

---

### **System Status**

#### **GET /admin/status**
Get system status and configuration.

**Success Response**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": {
    "status": "connected",
    "pool_size": 10,
    "active_connections": 2
  },
  "oauth": {
    "clients_count": 5,
    "scopes_count": 8,
    "active_tokens": 12
  },
  "uptime": "2 days, 5 hours"
}
```

---

## 🏥 **Health & Monitoring**

### **Health Check**

#### **GET /health**
Basic application health check.

**Success Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-07-10T10:00:00Z"
}
```

#### **GET /health/ready**
Kubernetes readiness probe.

**Success Response**:
```json
{
  "status": "ready",
  "database": "connected",
  "timestamp": "2025-07-10T10:00:00Z"
}
```

#### **GET /health/live**
Kubernetes liveness probe.

**Success Response**:
```json
{
  "status": "alive",
  "timestamp": "2025-07-10T10:00:00Z"
}
```

---

## ⚠️ **Error Handling**

### **Standard Error Format**

All API errors follow this format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable error description",
  "error_uri": "https://docs.authly.com/errors/error_code"
}
```

### **HTTP Status Codes**

- `200` - Success
- `201` - Created
- `204` - No Content
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `422` - Unprocessable Entity
- `429` - Too Many Requests
- `500` - Internal Server Error

### **OAuth Error Codes**

- `invalid_request` - The request is missing a required parameter
- `invalid_client` - Client authentication failed
- `invalid_grant` - The provided authorization grant is invalid
- `unauthorized_client` - The client is not authorized to request a token
- `unsupported_grant_type` - The authorization grant type is not supported
- `invalid_scope` - The requested scope is invalid or unknown
- `access_denied` - The resource owner or authorization server denied the request

---

## 🔒 **Authentication Methods**

### **Bearer Token Authentication**

Most endpoints require Bearer token authentication:

```http
Authorization: Bearer your_access_token_here
```

### **Basic Authentication**

OAuth client authentication uses HTTP Basic:

```http
Authorization: Basic base64(client_id:client_secret)
```

### **Admin Authentication**

Admin endpoints require admin JWT tokens obtained via `/admin/auth`.

---

## 🚦 **Rate Limiting**

- **Default Limit**: 100 requests per minute per IP
- **Admin Endpoints**: 60 requests per minute per authenticated user
- **Token Endpoint**: 20 requests per minute per client

**Rate limit headers**:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1625097600
```

**Rate limit exceeded response**:
```json
{
  "error": "rate_limit_exceeded",
  "error_description": "Too many requests. Please retry later.",
  "retry_after": 60
}
```

---

This API reference covers all endpoints in the Authly OAuth 2.1 + OpenID Connect 1.0 authorization server. For integration examples and advanced usage, see the [OAuth Guide](oauth-guide.md) and [OIDC Guide](oidc-guide.md).