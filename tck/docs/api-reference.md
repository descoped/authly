# API Reference

## OIDC/OAuth Endpoints

This document provides detailed specifications for the OIDC and OAuth endpoints tested by the TCK.

## Discovery Endpoints

### `/.well-known/openid-configuration`
**Purpose**: OIDC Discovery Document  
**Method**: GET  
**Response**: JSON document with issuer metadata

Required fields:
- `issuer` - Must match server configuration
- `authorization_endpoint` - OAuth authorization URL
- `token_endpoint` - Token exchange URL
- `userinfo_endpoint` - User information URL
- `jwks_uri` - JSON Web Key Set URL
- `response_types_supported` - Supported response types
- `subject_types_supported` - Subject identifier types
- `id_token_signing_alg_values_supported` - Signing algorithms

### `/.well-known/jwks.json`
**Purpose**: JSON Web Key Set  
**Method**: GET  
**Response**: Public keys for token verification

Required fields per key:
- `kty` - Key type (RSA, EC)
- `use` - Key use (sig, enc)
- `kid` - Key identifier
- `alg` - Algorithm (RS256)
- For RSA: `n` (modulus), `e` (exponent)

## OAuth 2.1 Endpoints

### `/api/v1/oauth/authorize`
**Purpose**: Authorization endpoint  
**Methods**: GET, POST  
**Parameters**:
- `response_type` - Must be "code" for authorization code flow
- `client_id` - OAuth client identifier
- `redirect_uri` - Callback URL (must match registered)
- `scope` - Requested permissions
- `state` - CSRF protection token
- `code_challenge` - PKCE challenge (required)
- `code_challenge_method` - Must be "S256"

**Response**: Redirect to callback with authorization code or error

### `/api/v1/oauth/token`
**Purpose**: Token exchange  
**Method**: POST  
**Content-Type**: `application/x-www-form-urlencoded`

**Parameters**:
- `grant_type` - "authorization_code" or "refresh_token"
- `code` - Authorization code (for authorization_code grant)
- `redirect_uri` - Must match authorize request
- `client_id` - Client identifier
- `client_secret` - Client secret (for confidential clients)
- `code_verifier` - PKCE verifier (required)
- `refresh_token` - For refresh grant

**Response**:
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "id_token": "...",
  "scope": "openid profile email"
}
```

### `/api/v1/oauth/revoke`
**Purpose**: Token revocation  
**Method**: POST  
**Authentication**: Client credentials

**Parameters**:
- `token` - Token to revoke
- `token_type_hint` - "access_token" or "refresh_token"

### `/api/v1/oauth/introspect`
**Purpose**: Token introspection  
**Method**: POST  
**Authentication**: Client credentials

**Parameters**:
- `token` - Token to introspect
- `token_type_hint` - Token type hint

**Response**:
```json
{
  "active": true,
  "scope": "openid profile",
  "client_id": "...",
  "username": "...",
  "exp": 1234567890
}
```

## OIDC Endpoints

### `/oidc/userinfo`
**Purpose**: User information  
**Methods**: GET, POST  
**Authentication**: Bearer token

**Response** (based on scopes):
```json
{
  "sub": "user-id",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john@example.com",
  "email_verified": true,
  "picture": "https://example.com/photo.jpg"
}
```

### `/oidc/logout`
**Purpose**: End session  
**Method**: GET  
**Parameters**:
- `id_token_hint` - ID token for session
- `post_logout_redirect_uri` - Where to redirect after logout
- `state` - State parameter

## Error Responses

All endpoints must return proper error responses:

### Authorization Errors
Returned as query parameters in redirect:
- `error` - Error code (invalid_request, unauthorized_client, etc.)
- `error_description` - Human-readable description
- `state` - Original state parameter

### Token Endpoint Errors
HTTP 400 with JSON body:
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code is invalid or expired"
}
```

## Security Requirements

### PKCE (OAuth 2.1)
- **Required** for all authorization code flows
- Only `S256` method supported
- `plain` method must be rejected

### Token Security
- Bearer tokens in `Authorization` header
- Tokens must expire
- Refresh tokens should rotate

### HTTPS Requirement
- Production deployments must use HTTPS
- Issuer URL must be HTTPS (except localhost)

## Scope Definitions

Standard OIDC scopes and their claims:

| Scope | Claims |
|-------|--------|
| `openid` | Required for OIDC, returns `sub` |
| `profile` | `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `address` | `address` (structured claim) |
| `phone` | `phone_number`, `phone_number_verified` |

## Testing Endpoints

For TCK validation, these endpoints are tested for:
1. **Availability** - Returns appropriate status codes
2. **Format compliance** - Correct content types and structures
3. **Security** - Proper authentication and authorization
4. **Error handling** - Specification-compliant error responses