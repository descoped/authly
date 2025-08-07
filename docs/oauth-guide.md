# OAuth 2.1 Implementation Guide

Guide to using Authly's OAuth 2.1 authorization server implementation.

**Standards**: OAuth 2.1, RFC 6749, RFC 7636 (PKCE), RFC 7009 (Revocation), RFC 8414 (Discovery)  
**Security**: Mandatory PKCE, OAuth 2.1 security best practices  
**Compliance**: Full OAuth 2.1 compliance with mandatory PKCE for all flows  
**Status**: Production-ready OAuth 2.1 implementation

---

## 🎯 **OAuth 2.1 Overview**

Authly implements a fully compliant OAuth 2.1 authorization server with all security best practices. OAuth 2.1 consolidates the latest security improvements and makes PKCE mandatory for all flows.

### **Key Features**
- ✅ **Mandatory PKCE** - Proof Key for Code Exchange required for all authorization flows
- ✅ **Multiple Grant Types** - Authorization code, password, refresh token, client credentials
- ✅ **Client Management** - Support for confidential and public clients
- ✅ **Scope System** - Granular permission control with custom scopes
- ✅ **Token Security** - JWT tokens with rotation, revocation, and blacklisting
- ✅ **Discovery** - Automatic client configuration via discovery endpoints

### **Security Improvements Over OAuth 2.0**
- **Mandatory PKCE** prevents authorization code interception attacks
- **Restricted redirect URIs** prevent open redirect vulnerabilities
- **Enhanced client authentication** with multiple supported methods
- **Improved token handling** with automatic rotation and secure storage

---

## 🔧 **Quick Start Integration**

### **1. Register Your Application**

First, register your application as an OAuth client:

```bash
# Using Authly CLI
python -m authly admin login
python -m authly admin client create \
  --name "My Application" \
  --type confidential \
  --redirect-uri "https://myapp.com/oauth/callback"

# Note the returned client_id and client_secret
```

### **2. Basic Authorization Flow**

```javascript
// Frontend: Initiate authorization
const authUrl = new URL('http://localhost:8000/api/v1/oauth/authorize');
const codeVerifier = generateCodeVerifier(); // Store securely
const codeChallenge = await generateCodeChallenge(codeVerifier);

authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://myapp.com/oauth/callback');
authUrl.searchParams.set('scope', 'read write');
authUrl.searchParams.set('state', generateState()); // CSRF protection
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

// Redirect user to authorization URL
window.location.href = authUrl.toString();
```

### **3. Exchange Authorization Code for Tokens**

```javascript
// Backend: Handle callback and exchange code
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
    code_verifier: codeVerifier, // From step 2
    client_id: clientId
  })
});

const tokens = await tokenResponse.json();
// tokens.access_token, tokens.refresh_token, tokens.expires_in
```

---

## 🏗️ **OAuth 2.1 Flows**

### **Authorization Code Flow (Recommended)**

The primary OAuth 2.1 flow with mandatory PKCE for maximum security.

#### **Step 1: Authorization Request**

```http
GET /oauth/authorize?
  response_type=code&
  client_id=your-client-id&
  redirect_uri=https://myapp.com/callback&
  scope=read%20write&
  state=xyz123&
  code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&
  code_challenge_method=S256
```

**Parameters**:
- `response_type`: Must be "code"
- `client_id`: Your registered client identifier
- `redirect_uri`: Exact match to registered URI
- `scope`: Space-separated list of requested permissions
- `state`: Random value for CSRF protection (recommended)
- `code_challenge`: Base64URL-encoded SHA256 hash of code_verifier
- `code_challenge_method`: Must be "S256"

#### **Step 2: User Authorization**

User sees consent screen and approves or denies the request. On approval:

```http
HTTP/1.1 302 Found
Location: https://myapp.com/callback?code=auth_code_here&state=xyz123
```

On denial:
```http
HTTP/1.1 302 Found
Location: https://myapp.com/callback?error=access_denied&error_description=User%20denied%20access&state=xyz123
```

#### **Step 3: Token Exchange**

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code&
code=auth_code_here&
redirect_uri=https://myapp.com/callback&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&
client_id=your-client-id
```

**Success Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def502004c6c4e02834...",
  "scope": "read write"
}
```

---

### **Password Grant Flow**

Direct username/password authentication for trusted first-party applications.

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&
username=user@example.com&
password=user_password&
scope=read%20write
```

**Use Cases**:
- First-party mobile applications
- Command-line tools
- Internal administrative interfaces
- Migration from legacy authentication systems

**Security Considerations**:
- Only use for applications you fully control
- Implement secure credential storage
- Consider using authorization code flow when possible

---

### **Refresh Token Flow**

Obtain new access tokens without user interaction.

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token&
refresh_token=def502004c6c4e02834...
```

**Response**:
```json
{
  "access_token": "new_access_token...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "new_refresh_token...",
  "scope": "read write"
}
```

**Important Notes**:
- Refresh tokens are automatically rotated (old token invalidated)
- Store new refresh token securely
- Implement proper refresh token storage and rotation

---

### **Client Credentials Flow**

Service-to-service authentication without user context.

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=client_credentials&
scope=api:read%20api:write
```

**Use Cases**:
- Backend service communication
- API integrations
- Automated processes
- Server-to-server authentication

---

## 🔐 **PKCE Implementation**

Proof Key for Code Exchange (PKCE) is mandatory in Authly's OAuth 2.1 implementation.

### **PKCE Flow Overview**

1. **Generate Code Verifier**: Random 43-128 character string
2. **Create Code Challenge**: Base64URL(SHA256(code_verifier))
3. **Authorization Request**: Include code_challenge and method
4. **Token Exchange**: Provide original code_verifier for verification

### **Code Generation Examples**

#### **JavaScript Implementation**
```javascript
// Generate code verifier (43-128 characters)
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

// Generate code challenge
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

#### **Python Implementation**
```python
import secrets
import hashlib
import base64

def generate_code_verifier():
    """Generate PKCE code verifier"""
    return base64.urlsafe_b64encode(secrets.randbits(256).to_bytes(32, 'big')).decode('utf-8').rstrip('=')

def generate_code_challenge(verifier):
    """Generate PKCE code challenge"""
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

# Usage
verifier = generate_code_verifier()
challenge = generate_code_challenge(verifier)
```

#### **Java Implementation**
```java
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Base64;

public class PKCEHelper {
    public static String generateCodeVerifier() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    public static String generateCodeChallenge(String verifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(verifier.getBytes("UTF-8"));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
```

---

## 👥 **Client Types & Authentication**

### **Confidential Clients**

Applications that can securely store credentials.

**Characteristics**:
- Server-side applications
- Mobile apps with secure backend
- Applications with protected client_secret

**Authentication Methods**:
- `client_secret_basic` - HTTP Basic authentication (recommended)
- `client_secret_post` - Client credentials in request body

**Example Registration**:
```bash
python -m authly admin client create \
  --name "Web Application" \
  --type confidential \
  --redirect-uri "https://webapp.com/oauth/callback" \
  --redirect-uri "https://webapp.com/admin/callback"
```

### **Public Clients**

Applications that cannot securely store credentials.

**Characteristics**:
- Single-page applications (SPAs)
- Mobile applications
- Desktop applications
- Applications without secure backend storage

**Security Requirements**:
- Mandatory PKCE for all flows
- Exact redirect URI matching
- No client secret required

**Example Registration**:
```bash
python -m authly admin client create \
  --name "Mobile App" \
  --type public \
  --redirect-uri "myapp://oauth/callback" \
  --redirect-uri "http://localhost:3000/callback"
```

---

## 🎭 **Scope Management**

Scopes provide granular access control for OAuth clients.

### **Built-in Scopes**

Authly provides several built-in scopes:

- `read` - Read access to user data
- `write` - Write access to user data  
- `profile` - Access to user profile information
- `email` - Access to user email address
- `openid` - OpenID Connect authentication (see OIDC guide)

### **Custom Scopes**

Create application-specific scopes:

```bash
# Create custom scopes
python -m authly admin scope create \
  --name "orders:read" \
  --description "Read access to user orders"

python -m authly admin scope create \
  --name "orders:write" \
  --description "Create and update user orders"

python -m authly admin scope create \
  --name "admin" \
  --description "Administrative access" \
  --default
```

### **Scope Usage in Applications**

#### **Request Specific Scopes**
```javascript
// Request specific permissions
const authUrl = new URL('http://localhost:8000/api/v1/oauth/authorize');
authUrl.searchParams.set('scope', 'read write orders:read');
```

#### **Validate Token Scopes**
```javascript
// Check if token has required scope
function hasScope(token, requiredScope) {
  const decoded = jwt.decode(token);
  const scopes = decoded.scopes || [];
  return scopes.includes(requiredScope);
}

// Protect API endpoints
app.get('/api/orders', (req, res) => {
  if (!hasScope(req.token, 'orders:read')) {
    return res.status(403).json({ error: 'insufficient_scope' });
  }
  // Return orders
});
```

---

## 🔧 **Token Management**

### **JWT Token Structure**

Authly uses JWT tokens with the following structure:

```json
{
  "header": {
    "typ": "JWT",
    "alg": "HS256"
  },
  "payload": {
    "sub": "user123",
    "aud": "your-client-id",
    "iss": "http://localhost:8000",
    "exp": 1625097600,
    "iat": 1625094000,
    "jti": "token-unique-id",
    "scopes": ["read", "write"],
    "client_id": "your-client-id"
  }
}
```

### **Token Validation**

#### **Python Token Validation**
```python
import jwt
from jwt.exceptions import InvalidTokenError

def validate_token(token, secret_key):
    try:
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=['HS256'],
            audience='your-client-id',
            issuer='http://localhost:8000'
        )
        return payload
    except InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")

# Usage
try:
    payload = validate_token(access_token, jwt_secret)
    user_id = payload['sub']
    scopes = payload['scopes']
except ValueError as e:
    # Handle invalid token
    pass
```

#### **JavaScript Token Validation**
```javascript
const jwt = require('jsonwebtoken');

function validateToken(token, secretKey) {
  try {
    const payload = jwt.verify(token, secretKey, {
      algorithms: ['HS256'],
      audience: 'your-client-id',
      issuer: 'http://localhost:8000'
    });
    return payload;
  } catch (error) {
    throw new Error(`Invalid token: ${error.message}`);
  }
}
```

### **Token Revocation**

Revoke tokens when they're no longer needed:

```javascript
// Revoke access token
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

## 🔍 **Discovery & Metadata**

OAuth 2.1 discovery enables automatic client configuration.

### **Server Discovery**

```javascript
// Fetch OAuth server metadata
const discoveryResponse = await fetch('http://localhost:8000/.well-known/oauth-authorization-server');
const metadata = await discoveryResponse.json();

// Use discovered endpoints
const authEndpoint = metadata.authorization_endpoint;
const tokenEndpoint = metadata.token_endpoint;
const supportedScopes = metadata.scopes_supported;
```

### **Discovery Response Example**

```json
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/api/v1/oauth/authorize",
  "token_endpoint": "http://localhost:8000/api/v1/oauth/token",
  "revocation_endpoint": "http://localhost:8000/api/v1/oauth/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "password", "client_credentials"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "scopes_supported": ["read", "write", "profile", "email", "openid"],
  "response_modes_supported": ["query"],
  "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
}
```

---

## ⚠️ **Error Handling**

### **OAuth Error Responses**

OAuth errors follow RFC 6749 specifications:

#### **Authorization Errors**
Redirected to redirect_uri with error parameters:
```
https://myapp.com/callback?error=access_denied&error_description=User%20denied%20access&state=xyz123
```

#### **Token Endpoint Errors**
JSON error responses:
```json
{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
}
```

### **Common Error Codes**

- `invalid_request` - Missing or invalid request parameters
- `invalid_client` - Client authentication failed
- `invalid_grant` - Authorization grant is invalid
- `unauthorized_client` - Client not authorized for this grant type
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Requested scope is invalid
- `access_denied` - User denied authorization
- `server_error` - Internal server error

### **Error Handling Best Practices**

```javascript
// Handle authorization callback errors
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.has('error')) {
  const error = urlParams.get('error');
  const description = urlParams.get('error_description');
  
  switch (error) {
    case 'access_denied':
      // User denied access - show appropriate message
      break;
    case 'invalid_request':
      // Invalid parameters - check implementation
      break;
    default:
      // Handle other errors
      break;
  }
}

// Handle token endpoint errors
try {
  const response = await fetch('/oauth/token', { /* ... */ });
  if (!response.ok) {
    const error = await response.json();
    console.error('Token error:', error.error, error.error_description);
  }
} catch (err) {
  console.error('Network error:', err);
}
```

---

## 🛡️ **Security Best Practices**

### **Client Security**
- Store client secrets securely (environment variables, key vaults)
- Use HTTPS for all OAuth communications
- Validate state parameter to prevent CSRF attacks
- Implement proper PKCE for public clients
- Use exact redirect URI matching

### **Token Security**
- Store tokens securely (HttpOnly cookies, secure storage)
- Implement automatic token refresh
- Set appropriate token expiration times
- Revoke tokens on logout
- Never expose tokens in URLs or logs

### **Application Security**
- Validate all tokens before using
- Check token scopes for authorization
- Implement rate limiting for token requests
- Monitor for suspicious OAuth activity
- Use secure random generators for PKCE

### **Production Considerations**
- Use load balancers with session affinity if needed
- Implement proper logging and monitoring
- Set up alerting for OAuth errors
- Regular security audits and penetration testing
- Keep OAuth library dependencies updated

---

## 📱 **Integration Examples**

### **React SPA Integration**

```jsx
import { useEffect, useState } from 'react';

const OAuthCallback = () => {
  const [tokens, setTokens] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const handleCallback = async () => {
      const urlParams = new URLSearchParams(window.location.search);
      
      if (urlParams.has('error')) {
        setError(urlParams.get('error_description'));
        return;
      }

      const code = urlParams.get('code');
      const state = urlParams.get('state');
      
      // Retrieve stored code_verifier and state
      const storedState = localStorage.getItem('oauth_state');
      const codeVerifier = localStorage.getItem('code_verifier');
      
      if (state !== storedState) {
        setError('Invalid state parameter');
        return;
      }

      try {
        const response = await fetch('/api/oauth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            code,
            code_verifier: codeVerifier,
            redirect_uri: window.location.origin + '/oauth/callback'
          })
        });

        const tokens = await response.json();
        setTokens(tokens);
        
        // Store tokens securely
        localStorage.setItem('access_token', tokens.access_token);
        localStorage.setItem('refresh_token', tokens.refresh_token);
        
      } catch (err) {
        setError('Failed to exchange authorization code');
      }
    };

    handleCallback();
  }, []);

  if (error) {
    return <div>Error: {error}</div>;
  }

  if (tokens) {
    return <div>Successfully authenticated!</div>;
  }

  return <div>Processing authentication...</div>;
};
```

### **Express.js Backend Integration**

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

// OAuth token validation middleware
const validateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  const token = authHeader.substring(7);
  
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: process.env.OAUTH_ISSUER
    });
    
    req.user = {
      id: payload.sub,
      scopes: payload.scopes || [],
      clientId: payload.client_id
    };
    
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Scope validation middleware
const requireScope = (requiredScope) => {
  return (req, res, next) => {
    if (!req.user.scopes.includes(requiredScope)) {
      return res.status(403).json({ 
        error: 'insufficient_scope',
        error_description: `Required scope: ${requiredScope}`
      });
    }
    next();
  };
};

// Protected routes
app.get('/api/profile', validateToken, requireScope('profile'), (req, res) => {
  res.json({ userId: req.user.id });
});

app.get('/api/orders', validateToken, requireScope('orders:read'), (req, res) => {
  // Return user orders
  res.json({ orders: [] });
});
```

---

This comprehensive OAuth 2.1 guide provides everything you need to integrate with Authly's authorization server. For OpenID Connect features, see the [OIDC Guide](oidc-guide.md). For detailed API reference, see the [API Reference](api-reference.md).