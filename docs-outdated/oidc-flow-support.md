# OpenID Connect Flow Support

## Overview

This document describes the OpenID Connect (OIDC) flows supported by Authly and the security rationale behind the implementation choices.

## Supported Flows

### ✅ Authorization Code Flow (Fully Supported)

**Response Type**: `code`
**Status**: **Fully Implemented and Recommended**

The Authorization Code Flow is the most secure OIDC flow and is fully supported by Authly with the following features:

- **PKCE Required**: All authorization code flows require PKCE (Proof Key for Code Exchange) with S256 challenge method
- **ID Token Generation**: ID tokens are generated at the token endpoint when `openid` scope is requested
- **OIDC Parameters**: Full support for OIDC parameters including `nonce`, `max_age`, `display`, `prompt`, etc.
- **Scope-based Claims**: Claims in ID tokens are filtered based on granted scopes
- **Refresh Token Support**: ID tokens are included in refresh token responses for OIDC flows

**Example Flow**:
```
1. Authorization Request: GET /oauth/authorize?response_type=code&client_id=...&scope=openid profile email&nonce=...
2. User Authentication and Consent
3. Authorization Code Response: https://client.example.com/callback?code=...&state=...
4. Token Exchange: POST /auth/token with authorization_code grant
5. Token Response: {"access_token": "...", "id_token": "...", "refresh_token": "..."}
```

## Unsupported Flows

### ❌ Implicit Flow (Not Supported)

**Response Types**: `id_token`, `id_token token`
**Status**: **Not Implemented**

**Reasons for Non-Support**:
1. **OAuth 2.1 Deprecation**: Implicit flow is deprecated in OAuth 2.1 specification
2. **Security Concerns**: Tokens exposed in URL fragments are vulnerable to interception
3. **Modern Alternatives**: Authorization Code Flow with PKCE provides better security for all client types

### ❌ Hybrid Flow (Not Supported)

**Response Types**: `code id_token`, `code token`, `code id_token token`
**Status**: **Not Implemented**

**Reasons for Non-Support**:
1. **Complexity**: Hybrid flows add significant implementation complexity
2. **Limited Benefit**: Authorization Code Flow with PKCE addresses the same use cases more securely
3. **Maintenance Overhead**: Additional security considerations and edge cases

## Security Rationale

### OAuth 2.1 Compliance

Authly follows OAuth 2.1 security best practices:

1. **PKCE Mandatory**: All authorization code flows require PKCE
2. **Secure Flows Only**: Only the most secure flow (Authorization Code) is supported
3. **No Implicit Flow**: Avoids token exposure in URL fragments

### OIDC Security Features

1. **Nonce Validation**: Proper nonce handling prevents replay attacks
2. **JWT Security**: ID tokens are signed with RS256 (default) or configurable algorithms
3. **Scope-based Privacy**: Claims are filtered based on granted scopes
4. **Token Binding**: ID tokens are bound to specific clients and users

## Discovery Endpoint Compliance

The OIDC discovery endpoint (`/.well-known/openid_configuration`) accurately advertises only supported capabilities:

```json
{
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "HS256"],
  "scopes_supported": ["openid", "profile", "email", "address", "phone", ...],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email", ...]
}
```

## Client Integration

### JavaScript (Single Page Application)

```javascript
// Use Authorization Code Flow with PKCE
const authUrl = new URL('/oauth/authorize', 'https://auth.example.com');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('redirect_uri', 'https://yourapp.com/callback');
authUrl.searchParams.set('state', generateRandomState());
authUrl.searchParams.set('nonce', generateRandomNonce());
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

// Redirect to authorization endpoint
window.location.href = authUrl.toString();
```

### Python (Server-side Application)

```python
import requests
from authlib.integrations.requests_client import OAuth2Session

# Configure OAuth2 session
client = OAuth2Session(
    client_id='your-client-id',
    client_secret='your-client-secret',
    scope='openid profile email',
    redirect_uri='https://yourapp.com/callback'
)

# Get authorization URL
authorization_url, state = client.create_authorization_url(
    'https://auth.example.com/oauth/authorize',
    nonce='random-nonce',
    code_challenge='...',
    code_challenge_method='S256'
)

# After receiving authorization code, exchange for tokens
token = client.fetch_token(
    'https://auth.example.com/auth/token',
    code=authorization_code,
    code_verifier='...'
)

# token contains: access_token, id_token, refresh_token
```

## Migration from Other Flows

### From Implicit Flow

If you're currently using implicit flow:

1. **Update Response Type**: Change from `id_token` to `code`
2. **Add PKCE**: Implement PKCE code challenge/verifier
3. **Add Token Exchange**: Implement server-side token exchange
4. **Update Redirect Handling**: Handle authorization codes instead of tokens

### From Hybrid Flow

If you're currently using hybrid flow:

1. **Simplify to Authorization Code**: Use only `response_type=code`
2. **Token Exchange**: Get all tokens from token endpoint
3. **Remove Fragment Handling**: Use query parameters only

## Standards Compliance

- **OpenID Connect Core 1.0**: Compliant for supported flows
- **OAuth 2.1**: Fully compliant with security best practices
- **RFC 7636**: PKCE implementation
- **RFC 7517**: JSON Web Key Set (JWKS) support

## Testing

The implementation includes comprehensive tests for:

- Authorization Code Flow with OIDC parameters
- ID token generation and validation
- Discovery endpoint accuracy
- JWKS endpoint functionality
- UserInfo endpoint with scope-based claims
- Refresh token flow with ID token preservation

## Conclusion

By supporting only the Authorization Code Flow with PKCE, Authly provides a secure, standards-compliant OIDC implementation that meets the needs of modern applications while maintaining the highest security standards as recommended by OAuth 2.1.