# OAuth 2.1 + OpenID Connect Flow Research

**Date:** 2025-07-13  
**Status:** Research Documentation  
**Category:** Implementation Research  
**Implementation Status:** Research Complete - Implementation Complete

## Overview
Research findings for implementing end-to-end OAuth 2.1 and OpenID Connect flow testing in the Authly authorization server.

## Discovery Endpoints Analysis

### OAuth 2.1 Authorization Server Metadata (RFC 8414)
**Endpoint:** `/.well-known/oauth-authorization-server`

**Key Findings:**
- **Authorization Endpoint:** `/api/v1/oauth/authorize`
- **Token Endpoint:** `/api/v1/auth/token`
- **Revocation Endpoint:** `/api/v1/auth/revoke`
- **PKCE Required:** `true` (S256 method)
- **Supported Grant Types:** `authorization_code`, `refresh_token`
- **Response Types:** `code` only (authorization code flow)
- **Auth Methods:** `client_secret_basic`, `client_secret_post`, `none`

### OpenID Connect Discovery Metadata
**Endpoint:** `/.well-known/openid_configuration`

**Additional OIDC Features:**
- **UserInfo Endpoint:** `/oidc/userinfo`
- **End Session Endpoint:** `/api/v1/oidc/logout`
- **Session Iframe:** `/api/v1/oidc/session/iframe`
- **JWKS URI:** `/.well-known/jwks.json`
- **Supported Scopes:** `openid`, `profile`, `email`, `address`, `phone`, `read`, `write`, `admin`
- **ID Token Algorithms:** `RS256`, `HS256`
- **Claims Supported:** Comprehensive list including standard OIDC claims
- **Session Management:** Front-channel logout supported

## Core OAuth Flow Endpoints

### 1. Authorization Endpoint
**URL:** `/api/v1/oauth/authorize`
**Methods:** GET, POST

**Required Parameters:**
- `response_type=code`
- `client_id` (registered client)
- `redirect_uri` (must match client registration)
- `code_challenge` (PKCE challenge, base64url, 43-128 chars)

**Optional Parameters:**
- `scope` (space-separated)
- `state` (CSRF protection)
- `code_challenge_method=S256`
- `nonce` (OIDC)
- `response_mode`, `display`, `prompt`, `max_age`, etc.

**Authentication Required:** Yes (user must be logged in)

### 2. Token Endpoint
**URL:** `/api/v1/auth/token`
**Method:** POST

**Supported Grant Types:**

#### Authorization Code Grant
```json
{
  "grant_type": "authorization_code",
  "code": "authorization_code_value",
  "redirect_uri": "client_redirect_uri",
  "client_id": "client_identifier",
  "code_verifier": "pkce_code_verifier",
  "client_secret": "client_secret_if_confidential"
}
```

#### Password Grant (for user authentication)
```json
{
  "grant_type": "password",
  "username": "user_username",
  "password": "user_password",
  "scope": "openid profile email"
}
```

#### Refresh Token Grant
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "refresh_token_value",
  "scope": "optional_scope_restriction"
}
```

### 3. UserInfo Endpoint
**URL:** `/oidc/userinfo`
**Method:** GET
**Authentication:** Bearer token with `openid` scope required

**Returns user claims based on granted scopes:**
- `openid`: `sub` claim
- `profile`: name, given_name, family_name, etc.
- `email`: email, email_verified
- `phone`: phone_number, phone_number_verified
- `address`: address claim

### 4. Revocation Endpoint
**URL:** `/api/v1/auth/revoke`
**Method:** POST
**Purpose:** Revoke access or refresh tokens

## User Management

### User Registration
**URL:** `/api/v1/users/`
**Method:** POST

```json
{
  "username": "string (1-50 chars)",
  "email": "string",
  "password": "string (min 8 chars)"
}
```

**Returns:** User object with `is_verified: false`

### User Verification
**URL:** `/api/v1/users/{user_id}/verify`
**Method:** PUT
**Authentication Required:** Yes (admin or self)

**Issue Identified:** Users need to be verified before they can authenticate

## Testing Strategy Requirements

### 1. User Authentication Flow
- **Create test user** via `/api/v1/users/`
- **Verify user** (need to solve authentication requirement)
- **Test password grant** for user token
- **Test userinfo endpoint** with user token

### 2. Authorization Code Flow (Complete PKCE Flow)
- **Generate PKCE challenge/verifier pair**
- **Create OAuth client** via Admin API
- **Initiate authorization** at `/api/v1/oauth/authorize`
- **Handle user authentication** (redirect to login)
- **Process authorization grant** (user consent)
- **Exchange code for tokens** at `/api/v1/auth/token`
- **Test access token** with UserInfo endpoint
- **Validate ID token** (JWT signature, claims)
- **Test refresh token flow**

### 3. Session Management
- **Test session check** via `/oidc/session/check`
- **Test logout** via `/oidc/logout`
- **Test front-channel logout** coordination

## Implementation Challenges

### 1. User Verification Challenge
**Problem:** Created users have `is_verified: false` and cannot authenticate
**Solutions to Investigate:**
- Admin API for user verification
- Verification token/code flow
- Dev mode bypass
- Bootstrap user creation

### 2. Browser-Based Testing
**Problem:** Authorization endpoint requires user login (HTML forms)
**Solutions:**
- Headless browser automation (Selenium/Playwright)
- Mock authentication for testing
- Direct session/cookie management
- Admin API user impersonation

### 3. PKCE Implementation
**Requirement:** Generate cryptographically secure code verifier and challenge
**Implementation:** Base64URL encoding of SHA256 hash

## Next Steps

### Immediate (High Priority)
1. **Solve user verification** - find admin method or dev bypass
2. **Test complete password grant flow** with verified user
3. **Implement PKCE generation** utilities
4. **Design authorization code flow test** strategy

### Medium Priority
1. **Research browser automation** for authorization endpoint
2. **Implement session management** testing
3. **Add ID token validation** (JWT verification)
4. **Test refresh token flows**

### Advanced
1. **Multi-client session testing**
2. **Front-channel logout coordination**
3. **OIDC compliance validation**
4. **Security vulnerability testing**

## Technical Notes

### PKCE Implementation
```bash
# Generate code verifier (43-128 characters, base64url)
code_verifier=$(openssl rand -base64 96 | tr -d '\n' | tr '/+' '_-' | tr -d '=')

# Generate code challenge (SHA256 hash, base64url encoded)
code_challenge=$(echo -n "$code_verifier" | openssl dgst -sha256 -binary | openssl base64 | tr -d '\n' | tr '/+' '_-' | tr -d '=')
```

### JWT Token Validation
- Validate signature using JWKS from `/.well-known/jwks.json`
- Verify issuer, audience, expiration claims
- Check nonce for OIDC flows

### Client Configuration for Testing
- **Public clients:** Use `token_endpoint_auth_method: "none"`
- **Confidential clients:** Use `token_endpoint_auth_method: "client_secret_post"`
- **PKCE:** Always required (set `require_pkce: true`)

## Security Considerations

1. **PKCE mandatory** - prevents authorization code interception
2. **State parameter** - CSRF protection for authorization flow
3. **Nonce parameter** - ID token binding for OIDC
4. **Secure redirect URI validation** - prevent open redirects
5. **Token revocation** - proper cleanup on logout
6. **Session management** - coordinated logout across clients

---

**Status:** Research Phase Complete
**Next Action:** Implement user verification solution and basic OAuth flow testing