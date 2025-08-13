# OAuth 2.1 Implementation Guide

Guide to using Authly's OAuth 2.1 authorization server implementation.

**Standards**: OAuth 2.1, RFC 6749, RFC 7636 (PKCE), RFC 7009 (Revocation), RFC 8414 (Discovery)  
**Security**: Mandatory PKCE, OAuth 2.1 security best practices  
**Compliance**: Full OAuth 2.1 compliance with mandatory PKCE  
**Status**: Production-ready OAuth 2.1 implementation

---

## 🎯 OAuth 2.1 Overview

Authly implements a fully compliant OAuth 2.1 authorization server with mandatory security features. OAuth 2.1 consolidates security best practices and removes deprecated grant types.

### Key Features
- ✅ **Authorization Code + PKCE** - Mandatory PKCE for all authorization code flows
- ✅ **Client Credentials** - Machine-to-machine authentication support
- ✅ **Refresh Token** - Token renewal with automatic rotation
- ✅ **Token Revocation** - RFC 7009 compliant token revocation
- ✅ **Discovery** - Automatic configuration via discovery endpoints
- ✅ **JWT Tokens** - Secure token management with JTI tracking

### OAuth 2.1 Changes from OAuth 2.0
- ❌ **Removed**: Password grant (security risk)
- ❌ **Removed**: Implicit grant (tokens exposed in URLs)
- ✅ **Mandatory**: PKCE for authorization code flow
- ✅ **Retained**: Authorization code, refresh token, client credentials

---

## 🚀 Quick Start

### 1. Register Your Application

```bash
# Using Authly CLI
python -m authly admin login
python -m authly admin client create \
  --name "My Application" \
  --type confidential \
  --redirect-uri "https://myapp.com/oauth/callback"

# Note the returned client_id and client_secret
```

### 2. Authorization Code Flow with PKCE

```javascript
// Step 1: Generate PKCE challenge
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Step 2: Redirect to authorization
const authUrl = new URL('http://localhost:8000/api/v1/oauth/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://myapp.com/oauth/callback');
authUrl.searchParams.set('scope', 'read write');
authUrl.searchParams.set('state', generateState());
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

window.location.href = authUrl.toString();

// Step 3: Exchange code for tokens
const tokenResponse = await fetch('http://localhost:8000/api/v1/oauth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': `Basic ${btoa(clientId + ':' + clientSecret)}`
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: 'https://myapp.com/oauth/callback',
    code_verifier: codeVerifier,
    client_id: clientId
  })
});
```

---

## 🔑 Grant Types

### Authorization Code with PKCE (User Authentication)

**Use for**: Web apps, mobile apps, SPAs - any application with user interaction

```http
POST /api/v1/oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code&
code=auth_code_here&
redirect_uri=https://myapp.com/callback&
code_verifier=your_code_verifier&
client_id=your-client-id
```

**Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def502004c6c4e02834...",
  "scope": "read write"
}
```

### Client Credentials (Machine-to-Machine)

**Use for**: Service-to-service authentication, backend APIs, automated processes

```http
POST /api/v1/oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=client_credentials&
scope=api:read api:write
```

**Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read api:write"
}
```

**Note**: No refresh token is issued for client credentials per OAuth 2.1 specification.

### Refresh Token

**Use for**: Renewing expired access tokens without user interaction

```http
POST /api/v1/oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token&
refresh_token=def502004c6c4e02834...
```

**Response**: New access and refresh tokens (automatic rotation)

---

## 🔐 PKCE Implementation

PKCE is **mandatory** for all authorization code flows in OAuth 2.1.

### Generate PKCE Values

```javascript
// JavaScript/TypeScript
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(digest));
}

function base64URLEncode(buffer) {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

```python
# Python
import secrets
import hashlib
import base64

def generate_code_verifier():
    return base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')

def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
```

---

## 🎭 Scope Management

### Built-in Scopes
- `read` - Read access to resources
- `write` - Write access to resources
- `openid` - OpenID Connect authentication
- `profile` - User profile information
- `email` - Email address access

### Create Custom Scopes

```bash
python -m authly admin scope create \
  --name "orders:read" \
  --description "Read access to orders"

python -m authly admin scope create \
  --name "admin" \
  --description "Administrative access"
```

### Using Scopes

```javascript
// Request specific scopes
authUrl.searchParams.set('scope', 'read write orders:read');

// Validate token scopes
const payload = jwt.decode(accessToken);
if (!payload.scope?.includes('orders:read')) {
  throw new Error('Insufficient scope');
}
```

---

## 🔧 Token Management

### JWT Token Structure

```json
{
  "sub": "user123",              // Subject (user ID or client ID)
  "jti": "unique-token-id",      // JWT ID for revocation
  "scope": "read write",         // Granted scopes
  "exp": 1625097600,            // Expiration time
  "iat": 1625094000,            // Issued at
  "client_id": "your-client-id", // OAuth client
  "token_use": "access"          // Token type indicator
}
```

### Token Revocation

```javascript
// Revoke a token (RFC 7009)
await fetch('http://localhost:8000/api/v1/oauth/revoke', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': `Basic ${btoa(clientId + ':' + clientSecret)}`
  },
  body: new URLSearchParams({
    token: accessToken,
    token_type_hint: 'access_token'
  })
});
```

---

## 🔍 Discovery Endpoints

### OAuth 2.1 Server Metadata

```javascript
// Fetch OAuth metadata
const response = await fetch('http://localhost:8000/.well-known/oauth-authorization-server');
const metadata = await response.json();

/* Response:
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/api/v1/oauth/authorize",
  "token_endpoint": "http://localhost:8000/api/v1/oauth/token",
  "revocation_endpoint": "http://localhost:8000/api/v1/oauth/revoke",
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "response_types_supported": ["code"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "scopes_supported": ["read", "write", "openid", "profile", "email"]
}
*/
```

---

## ⚠️ Error Handling

OAuth errors follow RFC 6749 specifications:

### Authorization Errors
```
https://myapp.com/callback?
  error=access_denied&
  error_description=User%20denied%20access&
  state=xyz123
```

### Token Endpoint Errors
```json
{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid"
}
```

### Common Error Codes
- `invalid_request` - Missing or invalid parameters
- `invalid_client` - Client authentication failed
- `invalid_grant` - Invalid authorization grant
- `unauthorized_client` - Client not authorized for grant type
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Requested scope is invalid

---

## 🛡️ Security Best Practices

### Required Security Measures
- ✅ Always use HTTPS in production
- ✅ Implement PKCE for all authorization code flows
- ✅ Use exact redirect URI matching
- ✅ Validate state parameter for CSRF protection
- ✅ Store tokens securely (never in URLs or localStorage for sensitive data)
- ✅ Implement token rotation for refresh tokens
- ✅ Set appropriate token expiration times

### Client Authentication
- **Confidential Clients**: Use client_secret_basic (HTTP Basic Auth)
- **Public Clients**: PKCE is mandatory, no client secret

---

## 📱 Integration Examples

### React SPA with PKCE

```jsx
import { useEffect, useState } from 'react';

function OAuthLogin() {
  const [codeVerifier, setCodeVerifier] = useState('');

  const initiateLogin = async () => {
    // Generate and store PKCE values
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    
    sessionStorage.setItem('code_verifier', verifier);
    sessionStorage.setItem('state', generateState());
    
    // Redirect to authorization
    const authUrl = new URL('http://localhost:8000/api/v1/oauth/authorize');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', process.env.REACT_APP_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', window.location.origin + '/callback');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', sessionStorage.getItem('state'));
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    
    window.location.href = authUrl.toString();
  };

  return <button onClick={initiateLogin}>Login with OAuth</button>;
}
```

### Express.js Resource Server

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

// Token validation middleware
const validateToken = (requiredScopes = []) => {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing authorization' });
    }

    const token = authHeader.substring(7);
    
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      
      // Check required scopes
      const tokenScopes = payload.scope?.split(' ') || [];
      const hasScopes = requiredScopes.every(s => tokenScopes.includes(s));
      
      if (!hasScopes) {
        return res.status(403).json({ 
          error: 'insufficient_scope',
          required: requiredScopes 
        });
      }
      
      req.user = payload;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
};

// Protected endpoints
app.get('/api/orders', validateToken(['orders:read']), (req, res) => {
  // Return orders for req.user.sub
});
```

---

This guide provides complete OAuth 2.1 integration with Authly. For OpenID Connect features, see the [OIDC Guide](oidc-guide.md).