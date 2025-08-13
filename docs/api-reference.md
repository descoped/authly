# Authly API Reference

Complete REST API documentation for the Authly OAuth 2.1 + OpenID Connect 1.0 authorization server.

**Base URL**: `http://localhost:8000` (development) or your deployment URL  
**API Version**: v1  
**Standards**: OAuth 2.1, OpenID Connect Core 1.0, RFC 6749, RFC 7636 (PKCE), RFC 7009 (Revocation), RFC 8414 (Discovery)  
**OIDC Conformance**: 100% compliant with OpenID Connect Core 1.0 certification tests

---

## 🔐 OAuth 2.1 Authorization Server

### Authorization Endpoint

#### **GET /api/v1/oauth/authorize**
Initiates OAuth 2.1 authorization flow with OpenID Connect support and consent UI.

**Query Parameters**:
```
response_type    string   required   Must be "code"
client_id        string   required   OAuth client identifier
redirect_uri     string   required   Registered redirect URI
scope           string   optional   Space-separated list of scopes (include "openid" for OIDC)
state           string   recommended CSRF protection parameter
code_challenge   string   required   PKCE code challenge (base64url, 43-128 chars)
code_challenge_method string required Must be "S256"

# OpenID Connect Parameters
nonce           string   optional   Nonce for ID token binding
response_mode   string   optional   How to return response (query, fragment, form_post)
display         string   optional   UI display mode (page, popup, touch, wap)
prompt          string   optional   Re-authentication/consent (none, login, consent, select_account)
max_age         integer  optional   Maximum authentication age in seconds
ui_locales      string   optional   Preferred UI languages (space-separated)
id_token_hint   string   optional   ID token hint for logout or re-authentication
login_hint      string   optional   Hint to identify the user
acr_values      string   optional   Authentication Context Class Reference values
```

**Example Request**:
```http
GET /api/v1/oauth/authorize?
  response_type=code&
  client_id=your-client&
  redirect_uri=https://app.com/callback&
  scope=openid%20profile%20email&
  state=xyz&
  nonce=abc123&
  code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&
  code_challenge_method=S256
```

**Response**: HTML consent form for user authorization

#### **POST /api/v1/oauth/authorize**
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

### Token Endpoint

#### **POST /api/v1/oauth/token**
OAuth 2.1 Token Endpoint supporting authorization code, refresh token, and client credentials grants.

**Headers**:
```
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)  // For confidential clients
```

**Supported Grant Types**:
- `authorization_code` - OAuth 2.1 authorization code flow with PKCE
- `refresh_token` - Refresh an access token
- `client_credentials` - Machine-to-machine authentication (no user context)

##### Authorization Code Grant

**Form Data**:
```
grant_type      string   required   "authorization_code"
code           string   required   Authorization code
redirect_uri   string   required   Must match authorization request
code_verifier  string   required   PKCE code verifier
client_id      string   required   OAuth client identifier
```

**Example**:
```http
POST /api/v1/oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=

grant_type=authorization_code&
code=auth_code&
redirect_uri=https://app.com/callback&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&
client_id=your-client
```

##### Refresh Token Grant

**Form Data**:
```
grant_type      string   required   "refresh_token"
refresh_token   string   required   Refresh token
```

**Example**:
```http
POST /api/v1/oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=

grant_type=refresh_token&
refresh_token=def502004c6c4e02834...
```

##### Client Credentials Grant

**Form Data**:
```
grant_type   string   required   "client_credentials"
scope       string   optional   Requested scopes (space-separated)
```

**Example**:
```http
POST /api/v1/oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=

grant_type=client_credentials&
scope=api:read api:write
```

**Success Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def502004c6c4e02834...",  // Not included for client_credentials
  "scope": "read write",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."  // Only for OIDC requests
}
```

---

### Token Introspection Endpoint

#### **POST /api/v1/oauth/introspect**
RFC 7662 compliant token introspection for resource servers.

**Headers**:
```
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)
```

**Form Data**:
```
token            string   required   Token to introspect
token_type_hint  string   optional   "access_token" or "refresh_token"
```

**Success Response**:
```json
{
  "active": true,
  "scope": "read write",
  "client_id": "your-client",
  "username": "john.doe",
  "token_type": "Bearer",
  "exp": 1625097600,
  "iat": 1625094000,
  "sub": "user-uuid",
  "aud": "your-client",
  "iss": "http://localhost:8000",
  "jti": "token-unique-id"
}
```

---

### Token Revocation Endpoint

#### **POST /api/v1/oauth/revoke**
RFC 7009 compliant token revocation.

**Headers**:
```
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)
```

**Form Data**:
```
token            string   required   Token to revoke
token_type_hint  string   optional   "access_token" or "refresh_token"
```

**Response**: HTTP 200 (always succeeds per RFC 7009)

---

### Refresh Token Endpoint (Deprecated - Use /oauth/token)

#### **POST /api/v1/oauth/refresh**
Legacy refresh endpoint. Use `/api/v1/oauth/token` with `grant_type=refresh_token` instead.

---

## 🆔 OpenID Connect 1.0

### Discovery Endpoint

#### **GET /.well-known/openid-configuration**
OpenID Connect Discovery metadata endpoint.

**Response**:
```json
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/api/v1/oauth/authorize",
  "token_endpoint": "http://localhost:8000/api/v1/oauth/token",
  "userinfo_endpoint": "http://localhost:8000/oidc/userinfo",
  "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "id_token_signing_alg_values_supported": ["RS256", "HS256"],
  "subject_types_supported": ["public"],
  "scopes_supported": ["openid", "profile", "email", "phone", "address"],
  "claims_supported": [
    "sub", "name", "given_name", "family_name", "middle_name",
    "nickname", "preferred_username", "profile", "picture", "website",
    "email", "email_verified", "gender", "birthdate", "zoneinfo",
    "locale", "phone_number", "phone_number_verified", "address", "updated_at"
  ],
  "code_challenge_methods_supported": ["S256"],
  "require_pkce": true
}
```

---

### JWKS Endpoint

#### **GET /.well-known/jwks.json**
JSON Web Key Set for ID token signature verification.

**Response**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "rsa-key-1",
      "alg": "RS256",
      "n": "...",  // RSA modulus
      "e": "AQAB"  // RSA exponent
    }
  ]
}
```

---

### UserInfo Endpoint

#### **GET /oidc/userinfo**
Returns user claims based on access token and granted scopes.

**Headers**:
```
Authorization: Bearer {access_token}
```

**Response**:
```json
{
  "sub": "user-uuid",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john.doe@example.com",
  "email_verified": true,
  "picture": "https://example.com/photo.jpg"
}
```

#### **PUT /oidc/userinfo**
Update user profile information (OIDC standard claims only).

**Headers**:
```
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request Body**:
```json
{
  "given_name": "Jonathan",
  "family_name": "Smith",
  "picture": "https://example.com/new-photo.jpg"
}
```

**Note**: Only OIDC standard claims allowed by granted scopes can be updated.

---

### OIDC Logout Endpoint

#### **GET /oidc/logout**
OpenID Connect end session endpoint.

**Query Parameters**:
```
id_token_hint             string   optional   ID token for session identification
post_logout_redirect_uri  string   optional   Registered logout redirect URI
state                    string   optional   State parameter for redirect
```

---

### Session Management Endpoints

#### **GET /oidc/session/iframe**
Returns HTML iframe for OIDC session management.

#### **GET /oidc/session/check**
Check OIDC session status.

#### **GET /oidc/frontchannel/logout**
OIDC front-channel logout endpoint.

---

## 🔒 Authentication Endpoints

### Login Page

#### **GET /auth/login**
Display login page for web-based authentication.

**Query Parameters**:
```
redirect_to  string   optional   URL to redirect after login
error       string   optional   Error message to display
message     string   optional   Info message to display
```

---

### Logout Endpoints

#### **GET /auth/logout**
Web-based logout endpoint.

#### **POST /api/v1/auth/logout**
API logout endpoint.

**Headers**:
```
Authorization: Bearer {access_token}
```

**Response**: HTTP 204 No Content

---

### Password Management

#### **POST /api/v1/auth/change-password**
Change user password (requires authentication).

**Headers**:
```
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request Body**:
```json
{
  "current_password": "old_password",
  "new_password": "new_secure_password"
}
```

#### **GET /api/v1/auth/password-status**
Check password status and requirements.

**Headers**:
```
Authorization: Bearer {access_token}
```

---

### Session Management

#### **GET /auth/session**
Get current session information.

#### **GET /auth/session/validate**
Validate current session status.

---

## 👥 User Management API

### Create User

#### **POST /api/v1/users/**
Create a new user account.

**Request Body**:
```json
{
  "username": "john.doe",
  "email": "john@example.com",
  "password": "secure_password"
}
```

### Get User

#### **GET /api/v1/users/{user_id}**
Get user information (admin only).

### Update User

#### **PUT /api/v1/users/{user_id}**
Update user information (admin only).

### Delete User

#### **DELETE /api/v1/users/{user_id}**
Delete user account (admin only).

### Verify User

#### **PUT /api/v1/users/{user_id}/verify**
Verify user account (admin only).

---

## 🛠️ Admin API

### Client Management

#### **GET /admin/clients**
List OAuth clients.

#### **POST /admin/clients**
Create new OAuth client.

#### **GET /admin/clients/{client_id}**
Get client details.

#### **PUT /admin/clients/{client_id}**
Update client configuration.

#### **DELETE /admin/clients/{client_id}**
Delete OAuth client.

#### **POST /admin/clients/{client_id}/regenerate-secret**
Generate new client secret.

#### **GET /admin/clients/{client_id}/oidc**
Get client OIDC settings.

#### **PUT /admin/clients/{client_id}/oidc**
Update client OIDC settings.

---

### Scope Management

#### **GET /admin/scopes**
List all scopes.

#### **POST /admin/scopes**
Create new scope.

#### **GET /admin/scopes/{scope_name}**
Get scope details.

#### **PUT /admin/scopes/{scope_name}**
Update scope.

#### **DELETE /admin/scopes/{scope_name}**
Delete scope.

#### **GET /admin/scopes/defaults**
Get default scopes.

---

### User Management

#### **GET /admin/users**
List all users.

#### **GET /admin/users/{user_id}**
Get user details.

#### **PUT /admin/users/{user_id}**
Update user.

#### **DELETE /admin/users/{user_id}**
Delete user.

#### **POST /admin/users/{user_id}/reset-password**
Reset user password.

#### **GET /admin/users/{user_id}/sessions**
Get user sessions.

#### **DELETE /admin/users/{user_id}/sessions/{session_id}**
Terminate specific session.

---

### System Status

#### **GET /admin/status**
Get system status.

#### **GET /admin/health**
Health check endpoint.

#### **GET /admin/dashboard/stats**
Get dashboard statistics.

---

## 🔍 Discovery Endpoints

### OAuth 2.1 Discovery

#### **GET /.well-known/oauth-authorization-server**
OAuth 2.1 Authorization Server metadata.

**Response**:
```json
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/api/v1/oauth/authorize",
  "token_endpoint": "http://localhost:8000/api/v1/oauth/token",
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "revocation_endpoint": "http://localhost:8000/api/v1/oauth/revoke",
  "introspection_endpoint": "http://localhost:8000/api/v1/oauth/introspect",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["read", "write", "openid", "profile", "email"]
}
```

---

## 📊 Monitoring

### Health Check

#### **GET /health**
Basic health check endpoint.

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Metrics

#### **GET /metrics**
Prometheus-compatible metrics endpoint.

---

## 🔒 Security Headers

All API responses include security headers:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

---

## ⚠️ Error Responses

### OAuth 2.1 Errors
```json
{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid"
}
```

### API Errors
```json
{
  "detail": "Authentication required",
  "status": 401
}
```

### Validation Errors
```json
{
  "detail": [
    {
      "loc": ["body", "username"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

---

## 📝 Notes

- **PKCE Required**: All authorization code flows require PKCE (OAuth 2.1)
- **No Password Grant**: Password grant has been removed per OAuth 2.1 specification
- **No Implicit Grant**: Implicit grant has been removed per OAuth 2.1 specification
- **Client Credentials**: Available for machine-to-machine authentication only
- **Token Rotation**: Refresh tokens are automatically rotated on use
- **Session Management**: Supports both cookie-based and token-based sessions

---

This API reference reflects the current implementation of Authly's OAuth 2.1 and OpenID Connect 1.0 authorization server.