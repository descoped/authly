# OpenID Connect (OIDC) Guide

Guide to using Authly's OpenID Connect 1.0 implementation.

**Standards**: OpenID Connect Core 1.0, OpenID Connect Discovery 1.0  
**Foundation**: Built on OAuth 2.1 with mandatory PKCE  
**Signing**: RS256 (RSA) and HS256 (HMAC) algorithms  
**Status**: Production-ready with 100% conformance test coverage

---

## 🆔 OpenID Connect Overview

OpenID Connect (OIDC) is an identity layer on top of OAuth 2.1 that enables secure user authentication and identity verification. Authly provides a complete OIDC implementation with ID tokens, UserInfo endpoint, and discovery.

### Key Features
- ✅ **ID Tokens** - JWT-based identity tokens with user claims
- ✅ **UserInfo Endpoint** - GET and PUT operations for user profile
- ✅ **Discovery** - Automatic configuration via `/.well-known/openid-configuration`
- ✅ **JWKS Endpoint** - Public keys for ID token verification
- ✅ **Standard Claims** - Full OIDC claim support
- ✅ **Multiple Algorithms** - RS256 and HS256 signing

### OIDC vs OAuth 2.1
- **OAuth 2.1**: Authorization for accessing resources
- **OIDC**: Authentication and identity verification
- **ID Token**: Contains user identity claims (OIDC-specific)
- **Access Token**: Grants resource access (OAuth)

---

## 🚀 Quick Start

### 1. OIDC Authentication Flow

```javascript
// Include 'openid' scope to enable OIDC
const authUrl = new URL('http://localhost:8000/api/v1/oauth/authorize');
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);
const nonce = generateNonce(); // For ID token validation

authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://myapp.com/callback');
authUrl.searchParams.set('scope', 'openid profile email'); // Must include 'openid'
authUrl.searchParams.set('state', generateState());
authUrl.searchParams.set('nonce', nonce); // Store for validation
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

window.location.href = authUrl.toString();
```

### 2. Token Exchange (Receives ID Token)

```javascript
const tokenResponse = await fetch('http://localhost:8000/api/v1/oauth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': `Basic ${btoa(clientId + ':' + clientSecret)}`
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: 'https://myapp.com/callback',
    code_verifier: codeVerifier,
    client_id: clientId
  })
});

const tokens = await tokenResponse.json();
// Response includes:
// - access_token: For API access
// - id_token: Contains user identity claims (OIDC)
// - refresh_token: For token renewal
```

---

## 🔑 ID Token

### ID Token Structure

```json
{
  "header": {
    "typ": "JWT",
    "alg": "RS256",
    "kid": "rsa-key-1"
  },
  "payload": {
    "iss": "http://localhost:8000",      // Issuer
    "sub": "user-uuid",                   // Subject (user ID)
    "aud": "your-client-id",              // Audience
    "exp": 1625097600,                    // Expiration
    "iat": 1625094000,                    // Issued at
    "auth_time": 1625094000,              // Authentication time
    "nonce": "random-nonce",              // Nonce for validation
    
    // Profile claims (with 'profile' scope)
    "name": "John Doe",
    "given_name": "John",
    "family_name": "Doe",
    "picture": "https://example.com/photo.jpg",
    
    // Email claims (with 'email' scope)
    "email": "john@example.com",
    "email_verified": true
  }
}
```

### ID Token Validation

```javascript
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// Create JWKS client
const client = jwksClient({
  jwksUri: 'http://localhost:8000/.well-known/jwks.json'
});

// Get signing key
function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// Validate ID token
function validateIdToken(idToken, clientId, nonce) {
  return new Promise((resolve, reject) => {
    jwt.verify(idToken, getKey, {
      algorithms: ['RS256'],
      audience: clientId,
      issuer: 'http://localhost:8000'
    }, (err, decoded) => {
      if (err) return reject(err);
      
      // Validate nonce
      if (decoded.nonce !== nonce) {
        return reject(new Error('Invalid nonce'));
      }
      
      resolve(decoded);
    });
  });
}
```

---

## 👤 UserInfo Endpoint

### Get User Information

```javascript
// GET /oidc/userinfo
const userInfoResponse = await fetch('http://localhost:8000/oidc/userinfo', {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});

const userInfo = await userInfoResponse.json();
/* Response based on granted scopes:
{
  "sub": "user-uuid",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john@example.com",
  "email_verified": true,
  "picture": "https://example.com/photo.jpg"
}
*/
```

### Update User Profile

```javascript
// PUT /oidc/userinfo - Update profile information
const updateResponse = await fetch('http://localhost:8000/oidc/userinfo', {
  method: 'PUT',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    given_name: "Jonathan",
    family_name: "Smith",
    picture: "https://example.com/new-photo.jpg"
  })
});

const updatedInfo = await updateResponse.json();
```

**Note**: Only OIDC standard claims allowed by granted scopes can be updated. Email and verification status cannot be changed via this endpoint.

---

## 🔐 OIDC Scopes and Claims

### Standard OIDC Scopes

| Scope | Claims Provided |
|-------|----------------|
| `openid` | `sub` (required for OIDC) |
| `profile` | `name`, `given_name`, `family_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `phone` | `phone_number`, `phone_number_verified` |
| `address` | `address` (structured claim) |

### Requesting Specific Scopes

```javascript
// Request profile and email information
authUrl.searchParams.set('scope', 'openid profile email');

// Minimal OIDC request (only sub claim)
authUrl.searchParams.set('scope', 'openid');

// Full user profile
authUrl.searchParams.set('scope', 'openid profile email phone address');
```

---

## 🔍 Discovery and JWKS

### OpenID Configuration Discovery

```javascript
// Fetch OIDC configuration
const configResponse = await fetch('http://localhost:8000/.well-known/openid-configuration');
const config = await configResponse.json();

/* Response:
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/api/v1/oauth/authorize",
  "token_endpoint": "http://localhost:8000/api/v1/oauth/token",
  "userinfo_endpoint": "http://localhost:8000/oidc/userinfo",
  "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "id_token_signing_alg_values_supported": ["RS256", "HS256"],
  "subject_types_supported": ["public"],
  "scopes_supported": ["openid", "profile", "email", "phone", "address"],
  "claims_supported": ["sub", "name", "email", "email_verified", ...],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "code_challenge_methods_supported": ["S256"]
}
*/
```

### JWKS Endpoint

```javascript
// Fetch public keys for ID token verification
const jwksResponse = await fetch('http://localhost:8000/.well-known/jwks.json');
const jwks = await jwksResponse.json();

/* Response:
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "rsa-key-1",
      "alg": "RS256",
      "n": "...", // RSA modulus
      "e": "AQAB" // RSA exponent
    }
  ]
}
*/
```

---

## 🎯 OIDC Parameters

### Authorization Request Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `scope` | Yes | Must include "openid" |
| `nonce` | Recommended | Random value for ID token validation |
| `display` | No | UI display type (page, popup, touch, wap) |
| `prompt` | No | User interaction (none, login, consent, select_account) |
| `max_age` | No | Maximum authentication age in seconds |
| `ui_locales` | No | Preferred UI languages |
| `id_token_hint` | No | Previously issued ID token |
| `login_hint` | No | Hint about user's identifier |
| `acr_values` | No | Authentication Context Class Reference |

### Example with Optional Parameters

```javascript
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('nonce', generateNonce());
authUrl.searchParams.set('display', 'popup');
authUrl.searchParams.set('prompt', 'consent');
authUrl.searchParams.set('max_age', '3600');
authUrl.searchParams.set('ui_locales', 'en-US');
authUrl.searchParams.set('login_hint', 'user@example.com');
```

---

## 📱 Integration Examples

### React OIDC Authentication

```jsx
import { useEffect, useState } from 'react';

function OIDCAuth() {
  const [user, setUser] = useState(null);

  const login = async () => {
    const nonce = generateNonce();
    sessionStorage.setItem('nonce', nonce);
    
    const authUrl = new URL('http://localhost:8000/api/v1/oauth/authorize');
    // ... set OIDC parameters including nonce
    
    window.location.href = authUrl.toString();
  };

  const handleCallback = async (code) => {
    // Exchange code for tokens
    const tokens = await exchangeCodeForTokens(code);
    
    // Validate ID token
    const nonce = sessionStorage.getItem('nonce');
    const idClaims = await validateIdToken(tokens.id_token, CLIENT_ID, nonce);
    
    // Fetch additional user info if needed
    const userInfo = await fetch('http://localhost:8000/oidc/userinfo', {
      headers: { 'Authorization': `Bearer ${tokens.access_token}` }
    }).then(r => r.json());
    
    setUser({ ...idClaims, ...userInfo });
  };

  return (
    <div>
      {user ? (
        <div>Welcome, {user.name}!</div>
      ) : (
        <button onClick={login}>Login with OIDC</button>
      )}
    </div>
  );
}
```

### Node.js ID Token Validation

```javascript
const { JWK, JWT } = require('jose');
const axios = require('axios');

class OIDCValidator {
  constructor(issuer) {
    this.issuer = issuer;
    this.jwks = null;
  }

  async loadJWKS() {
    const response = await axios.get(`${this.issuer}/.well-known/jwks.json`);
    this.jwks = response.data.keys.map(key => JWK.asKey(key));
  }

  async validateIdToken(idToken, clientId, nonce) {
    if (!this.jwks) await this.loadJWKS();
    
    // Find the right key
    const decoded = JWT.decode(idToken, { complete: true });
    const key = this.jwks.find(k => k.kid === decoded.header.kid);
    
    if (!key) throw new Error('Key not found');
    
    // Verify token
    const verified = JWT.verify(idToken, key, {
      audience: clientId,
      issuer: this.issuer,
      algorithms: ['RS256']
    });
    
    // Validate nonce
    if (verified.nonce !== nonce) {
      throw new Error('Invalid nonce');
    }
    
    return verified;
  }
}

// Usage
const validator = new OIDCValidator('http://localhost:8000');
const claims = await validator.validateIdToken(idToken, clientId, nonce);
```

---

## 🛡️ Security Best Practices

### Required Security Measures
- ✅ Always validate ID token signature using JWKS
- ✅ Verify issuer (iss) matches expected value
- ✅ Verify audience (aud) contains your client_id
- ✅ Check expiration (exp) hasn't passed
- ✅ Validate nonce to prevent replay attacks
- ✅ Use HTTPS in production
- ✅ Store tokens securely

### ID Token vs Access Token
- **ID Token**: Contains user identity, validate on client
- **Access Token**: For API access, validate on resource server
- Never use ID token as an access token
- ID tokens should not be sent to APIs

---

## ⚠️ Common Issues

### Missing ID Token
- **Cause**: `openid` scope not included
- **Solution**: Always include `openid` in scope parameter

### Invalid Nonce
- **Cause**: Nonce mismatch or missing
- **Solution**: Generate and store nonce before authorization

### UserInfo Access Denied
- **Cause**: Missing `openid` scope in access token
- **Solution**: Ensure token was obtained with `openid` scope

### Profile Updates Rejected
- **Cause**: Attempting to update claims not in granted scopes
- **Solution**: Request appropriate scopes during authorization

---

This guide covers OIDC authentication with Authly. For OAuth 2.1 authorization flows, see the [OAuth Guide](oauth-guide.md).