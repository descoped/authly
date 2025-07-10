# OpenID Connect 1.0 Implementation Guide

Comprehensive guide to using Authly's OpenID Connect 1.0 implementation built on the OAuth 2.1 foundation for secure identity authentication.

**Standards**: OpenID Connect Core 1.0, OpenID Connect Discovery 1.0  
**Foundation**: OAuth 2.1 with mandatory PKCE  
**Signing**: RS256 (RSA) and HS256 (HMAC) ID token signing

---

## 🆔 **OpenID Connect Overview**

OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.1 that enables clients to verify user identity and obtain basic profile information. Authly's OIDC implementation provides secure, standards-compliant identity authentication.

### **Key Features**
- ✅ **ID Token Generation** - JWT-based identity tokens with standard claims
- ✅ **UserInfo Endpoint** - Retrieve user information with scope-based filtering
- ✅ **JWKS Support** - RSA key publishing for token signature verification
- ✅ **OIDC Discovery** - Automatic client configuration via discovery metadata
- ✅ **Multiple Signing Algorithms** - RS256 (RSA) and HS256 (HMAC) support
- ✅ **OAuth 2.1 Integration** - Seamless integration with OAuth authorization flows

### **OIDC vs OAuth 2.1**
- **OAuth 2.1**: Authorization framework for accessing protected resources
- **OIDC**: Identity layer that adds user authentication on top of OAuth 2.1
- **ID Tokens**: OIDC adds ID tokens containing user identity information
- **UserInfo**: Standardized endpoint for retrieving user profile data

---

## 🚀 **Quick Start Integration**

### **1. Register OIDC Client**

```bash
# Register client with OIDC scopes
python -m authly admin login
python -m authly admin client create \
  --name "OIDC Application" \
  --type confidential \
  --redirect-uri "https://myapp.com/oidc/callback"

# Create OIDC scopes
python -m authly admin scope create \
  --name "openid" \
  --description "OpenID Connect authentication"

python -m authly admin scope create \
  --name "profile" \
  --description "Access to user profile information"

python -m authly admin scope create \
  --name "email" \
  --description "Access to user email address"
```

### **2. OIDC Authorization Flow**

```javascript
// Initiate OIDC authentication (includes 'openid' scope)
const authUrl = new URL('http://localhost:8000/oauth/authorize');
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);
const nonce = generateNonce(); // For ID token validation

authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://myapp.com/oidc/callback');
authUrl.searchParams.set('scope', 'openid profile email'); // Must include 'openid'
authUrl.searchParams.set('state', generateState());
authUrl.searchParams.set('nonce', nonce); // Store for later validation
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

// Redirect user for authentication
window.location.href = authUrl.toString();
```

### **3. Exchange Code for Tokens (Including ID Token)**

```javascript
// Exchange authorization code for tokens
const tokenResponse = await fetch('http://localhost:8000/oauth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': `Basic ${btoa(clientId + ':' + clientSecret)}`
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: 'https://myapp.com/oidc/callback',
    code_verifier: codeVerifier,
    client_id: clientId
  })
});

const tokens = await tokenResponse.json();
/*
Response includes:
{
  "access_token": "...",
  "refresh_token": "...",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...", // ID token for OIDC
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
*/
```

---

## 🔑 **ID Token Structure**

ID tokens are JWT tokens containing user identity information.

### **ID Token Header**
```json
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "rsa-key-1"
}
```

### **ID Token Payload**
```json
{
  "iss": "http://localhost:8000",
  "sub": "user123",
  "aud": "your-client-id",
  "exp": 1625097600,
  "iat": 1625094000,
  "auth_time": 1625094000,
  "nonce": "random-nonce-value",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john@example.com",
  "email_verified": true
}
```

### **Standard Claims**
- `iss` - Issuer identifier (Authly server URL)
- `sub` - Subject identifier (unique user ID)
- `aud` - Audience (client ID)
- `exp` - Expiration time (Unix timestamp)
- `iat` - Issued at time (Unix timestamp)
- `auth_time` - Authentication time (Unix timestamp)
- `nonce` - Value used to associate client session with ID token

### **Profile Claims** (when 'profile' scope requested)
- `name` - Full name
- `given_name` - First name
- `family_name` - Last name
- `middle_name` - Middle name
- `nickname` - Casual name
- `preferred_username` - Shorthand name
- `profile` - Profile page URL
- `picture` - Profile picture URL
- `website` - Web page or blog URL
- `gender` - Gender
- `birthdate` - Birthday
- `zoneinfo` - Time zone
- `locale` - Locale
- `updated_at` - Profile update time

### **Email Claims** (when 'email' scope requested)
- `email` - Email address
- `email_verified` - Email verification status

---

## 🔍 **ID Token Validation**

Proper ID token validation is crucial for security.

### **JavaScript ID Token Validation**

```javascript
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// Create JWKS client for RSA signature verification
const client = jwksClient({
  jwksUri: 'http://localhost:8000/.well-known/jwks.json',
  cache: true,
  cacheMaxAge: 3600000 // 1 hour
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
    } else {
      const signingKey = key.publicKey || key.rsaPublicKey;
      callback(null, signingKey);
    }
  });
}

function validateIdToken(idToken, clientId, nonce) {
  return new Promise((resolve, reject) => {
    jwt.verify(idToken, getKey, {
      algorithms: ['RS256'],
      audience: clientId,
      issuer: 'http://localhost:8000',
      clockTolerance: 60 // Allow 60 seconds clock skew
    }, (err, decoded) => {
      if (err) {
        reject(new Error(`ID token validation failed: ${err.message}`));
        return;
      }

      // Validate nonce
      if (decoded.nonce !== nonce) {
        reject(new Error('Invalid nonce in ID token'));
        return;
      }

      // Validate auth_time if max_age was used
      const now = Math.floor(Date.now() / 1000);
      if (decoded.auth_time && (now - decoded.auth_time) > maxAge) {
        reject(new Error('Authentication too old'));
        return;
      }

      resolve(decoded);
    });
  });
}

// Usage
try {
  const claims = await validateIdToken(idToken, clientId, storedNonce);
  const userId = claims.sub;
  const userName = claims.name;
  const userEmail = claims.email;
} catch (error) {
  console.error('ID token validation failed:', error.message);
}
```

### **Python ID Token Validation**

```python
import jwt
from jwt.exceptions import InvalidTokenError
import requests
from cryptography.hazmat.primitives import serialization

def get_jwks():
    """Fetch JWKS from Authly"""
    response = requests.get('http://localhost:8000/.well-known/jwks.json')
    return response.json()

def get_rsa_key(kid, jwks):
    """Extract RSA public key from JWKS"""
    for key in jwks['keys']:
        if key['kid'] == kid:
            # Construct RSA public key from n and e
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            import base64
            
            n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '=='), 'big')
            e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '=='), 'big')
            
            public_numbers = RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key()
            
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    
    raise ValueError(f"Key ID {kid} not found in JWKS")

def validate_id_token(id_token, client_id, nonce):
    """Validate OIDC ID token"""
    try:
        # Decode header to get key ID
        header = jwt.get_unverified_header(id_token)
        kid = header.get('kid')
        
        if not kid:
            raise ValueError("No key ID in token header")
        
        # Get JWKS and extract public key
        jwks = get_jwks()
        public_key = get_rsa_key(kid, jwks)
        
        # Validate token
        payload = jwt.decode(
            id_token,
            public_key,
            algorithms=['RS256'],
            audience=client_id,
            issuer='http://localhost:8000',
            leeway=60  # Allow 60 seconds clock skew
        )
        
        # Validate nonce
        if payload.get('nonce') != nonce:
            raise ValueError("Invalid nonce in ID token")
        
        return payload
        
    except InvalidTokenError as e:
        raise ValueError(f"ID token validation failed: {e}")

# Usage
try:
    claims = validate_id_token(id_token, client_id, stored_nonce)
    user_id = claims['sub']
    user_name = claims.get('name')
    user_email = claims.get('email')
except ValueError as e:
    print(f"ID token validation failed: {e}")
```

---

## 👤 **UserInfo Endpoint**

The UserInfo endpoint provides user information based on the access token's scopes.

### **UserInfo Request**

```http
GET /oidc/userinfo
Authorization: Bearer access_token_here
```

### **UserInfo Response**

```json
{
  "sub": "user123",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john@example.com",
  "email_verified": true,
  "picture": "https://example.com/avatar.jpg",
  "updated_at": 1625094000
}
```

### **UserInfo Integration Examples**

#### **JavaScript UserInfo Fetch**
```javascript
async function getUserInfo(accessToken) {
  try {
    const response = await fetch('http://localhost:8000/oidc/userinfo', {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user info');
    }

    const userInfo = await response.json();
    return userInfo;
  } catch (error) {
    console.error('UserInfo request failed:', error);
    throw error;
  }
}

// Usage
try {
  const userInfo = await getUserInfo(accessToken);
  console.log('User ID:', userInfo.sub);
  console.log('User Name:', userInfo.name);
  console.log('User Email:', userInfo.email);
} catch (error) {
  // Handle error
}
```

#### **Python UserInfo Request**
```python
import requests

def get_user_info(access_token):
    """Fetch user information from UserInfo endpoint"""
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.get(
            'http://localhost:8000/oidc/userinfo',
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise ValueError(f"UserInfo request failed: {e}")

# Usage
try:
    user_info = get_user_info(access_token)
    user_id = user_info['sub']
    user_name = user_info.get('name')
    user_email = user_info.get('email')
except ValueError as e:
    print(f"Failed to get user info: {e}")
```

---

## 🔐 **JWKS and Key Management**

JSON Web Key Set (JWKS) provides public keys for ID token signature verification.

### **JWKS Endpoint**

```http
GET /.well-known/jwks.json
```

### **JWKS Response**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "rsa-key-1",
      "alg": "RS256",
      "n": "0vx7agoebGcQSzuuiUiUXqjy...",
      "e": "AQAB"
    }
  ]
}
```

### **Key Rotation**

Authly supports automatic key rotation:

- New keys are added to JWKS before use
- Old keys remain available for signature verification
- Clients should cache JWKS with appropriate TTL
- Failed verification should trigger JWKS refresh

### **JWKS Client Implementation**

```javascript
class JWKSClient {
  constructor(jwksUri) {
    this.jwksUri = jwksUri;
    this.cache = new Map();
    this.cacheMaxAge = 3600000; // 1 hour
  }

  async getSigningKey(kid) {
    // Check cache first
    const cached = this.cache.get(kid);
    if (cached && (Date.now() - cached.timestamp) < this.cacheMaxAge) {
      return cached.key;
    }

    // Fetch JWKS
    const response = await fetch(this.jwksUri);
    const jwks = await response.json();

    // Find and cache key
    const key = jwks.keys.find(k => k.kid === kid);
    if (!key) {
      throw new Error(`Key ID ${kid} not found in JWKS`);
    }

    this.cache.set(kid, {
      key: this.jwkToKey(key),
      timestamp: Date.now()
    });

    return this.cache.get(kid).key;
  }

  jwkToKey(jwk) {
    // Convert JWK to PEM format for jwt library
    // Implementation depends on your JWT library
    return convertJWKToPEM(jwk);
  }
}
```

---

## 🔍 **OIDC Discovery**

OIDC Discovery provides automatic client configuration.

### **Discovery Endpoint**

```http
GET /.well-known/openid_configuration
```

### **Discovery Response**

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
  "claims_supported": [
    "sub", "name", "given_name", "family_name",
    "email", "email_verified", "picture", "updated_at"
  ],
  "code_challenge_methods_supported": ["S256"],
  "grant_types_supported": ["authorization_code", "refresh_token"]
}
```

### **Discovery Client Implementation**

```javascript
class OIDCClient {
  constructor(issuer, clientId, clientSecret) {
    this.issuer = issuer;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.config = null;
  }

  async discover() {
    const discoveryUrl = `${this.issuer}/.well-known/openid_configuration`;
    const response = await fetch(discoveryUrl);
    this.config = await response.json();
    return this.config;
  }

  getAuthorizationUrl(redirectUri, scopes, state, nonce) {
    if (!this.config) {
      throw new Error('Must call discover() first');
    }

    const url = new URL(this.config.authorization_endpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', scopes.join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    
    return url.toString();
  }

  async exchangeCode(code, redirectUri, codeVerifier) {
    const response = await fetch(this.config.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${btoa(this.clientId + ':' + this.clientSecret)}`
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
        client_id: this.clientId
      })
    });

    return response.json();
  }
}

// Usage
const client = new OIDCClient(
  'http://localhost:8000',
  'your-client-id',
  'your-client-secret'
);

await client.discover();
const authUrl = client.getAuthorizationUrl(
  'https://myapp.com/callback',
  ['openid', 'profile', 'email'],
  'state123',
  'nonce456'
);
```

---

## 🔄 **Token Refresh with ID Tokens**

When refreshing tokens in OIDC, new ID tokens are issued if the original request included 'openid' scope.

### **Refresh Token Request**

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token&
refresh_token=your_refresh_token
```

### **Refresh Token Response**

```json
{
  "access_token": "new_access_token...",
  "refresh_token": "new_refresh_token...",
  "id_token": "new_id_token...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

### **Refresh Implementation**

```javascript
async function refreshTokens(refreshToken, clientId, clientSecret) {
  const response = await fetch('http://localhost:8000/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${btoa(clientId + ':' + clientSecret)}`
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    })
  });

  const tokens = await response.json();
  
  // Validate new ID token if present
  if (tokens.id_token) {
    const claims = await validateIdToken(tokens.id_token, clientId, null); // No nonce for refresh
    console.log('Refreshed tokens for user:', claims.sub);
  }

  return tokens;
}
```

---

## 🎨 **Advanced OIDC Features**

### **Custom Claims**

Add custom claims to ID tokens based on application needs:

```python
# Example: Custom claims processor (server-side)
def get_custom_claims(user, scopes):
    claims = {}
    
    if 'profile' in scopes:
        claims.update({
            'department': user.department,
            'employee_id': user.employee_id,
            'roles': user.roles
        })
    
    if 'subscription' in scopes:
        claims.update({
            'subscription_type': user.subscription.type,
            'subscription_expires': user.subscription.expires_at
        })
    
    return claims
```

### **Logout Support**

Implement OIDC logout (end session):

```javascript
function logout(idTokenHint, postLogoutRedirectUri) {
  // Construct logout URL
  const logoutUrl = new URL('http://localhost:8000/oidc/logout');
  if (idTokenHint) {
    logoutUrl.searchParams.set('id_token_hint', idTokenHint);
  }
  if (postLogoutRedirectUri) {
    logoutUrl.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);
  }
  
  // Clear local tokens
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('id_token');
  
  // Redirect to logout endpoint
  window.location.href = logoutUrl.toString();
}
```

### **Session Management**

Monitor authentication session status:

```javascript
// Check session iframe for session changes
function setupSessionManagement() {
  const iframe = document.createElement('iframe');
  iframe.src = 'http://localhost:8000/oidc/check_session';
  iframe.style.display = 'none';
  document.body.appendChild(iframe);
  
  // Listen for session changes
  window.addEventListener('message', (event) => {
    if (event.origin !== 'http://localhost:8000') return;
    
    if (event.data === 'changed') {
      // Session changed - user may have logged out
      console.log('Session changed, checking authentication status...');
      checkAuthStatus();
    }
  });
  
  // Periodically check session
  setInterval(() => {
    iframe.contentWindow.postMessage('check', 'http://localhost:8000');
  }, 5000);
}
```

---

## 📱 **Framework Integration Examples**

### **React OIDC Integration**

```jsx
import { createContext, useContext, useEffect, useState } from 'react';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for existing tokens
    const idToken = localStorage.getItem('id_token');
    if (idToken) {
      try {
        const claims = parseJWT(idToken);
        if (claims.exp > Date.now() / 1000) {
          setUser(claims);
        }
      } catch (err) {
        console.error('Invalid stored ID token');
      }
    }
    setLoading(false);
  }, []);

  const login = () => {
    const client = new OIDCClient('http://localhost:8000', 'client-id', 'client-secret');
    const authUrl = client.getAuthorizationUrl(
      window.location.origin + '/callback',
      ['openid', 'profile', 'email'],
      generateState(),
      generateNonce()
    );
    window.location.href = authUrl;
  };

  const logout = () => {
    const idToken = localStorage.getItem('id_token');
    localStorage.clear();
    setUser(null);
    
    // Redirect to OIDC logout
    const logoutUrl = new URL('http://localhost:8000/oidc/logout');
    logoutUrl.searchParams.set('id_token_hint', idToken);
    logoutUrl.searchParams.set('post_logout_redirect_uri', window.location.origin);
    window.location.href = logoutUrl.toString();
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

// Usage in components
const Profile = () => {
  const { user, logout } = useAuth();
  
  if (!user) {
    return <div>Please log in</div>;
  }

  return (
    <div>
      <h1>Welcome, {user.name}</h1>
      <p>Email: {user.email}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
};
```

### **Express.js OIDC Middleware**

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();

// JWKS client for RSA verification
const client = jwksClient({
  jwksUri: 'http://localhost:8000/.well-known/jwks.json',
  cache: true,
  cacheMaxAge: 3600000
});

// OIDC authentication middleware
const authenticateOIDC = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization header' });
  }

  const token = authHeader.substring(7);
  
  try {
    // For access tokens, verify with HMAC
    const accessTokenPayload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256']
    });
    
    req.user = {
      id: accessTokenPayload.sub,
      scopes: accessTokenPayload.scopes || []
    };
    
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// OIDC ID token validation (for logout, etc.)
const validateIdToken = async (idToken) => {
  const header = jwt.decode(idToken, { complete: true }).header;
  
  return new Promise((resolve, reject) => {
    client.getSigningKey(header.kid, (err, key) => {
      if (err) {
        reject(err);
        return;
      }

      const signingKey = key.publicKey || key.rsaPublicKey;
      
      try {
        const payload = jwt.verify(idToken, signingKey, {
          algorithms: ['RS256'],
          issuer: 'http://localhost:8000'
        });
        resolve(payload);
      } catch (verifyErr) {
        reject(verifyErr);
      }
    });
  });
};

// Protected routes
app.get('/api/profile', authenticateOIDC, async (req, res) => {
  // Get user info from UserInfo endpoint
  const userInfoResponse = await fetch('http://localhost:8000/oidc/userinfo', {
    headers: {
      'Authorization': req.headers.authorization
    }
  });
  
  const userInfo = await userInfoResponse.json();
  res.json(userInfo);
});

app.post('/api/logout', async (req, res) => {
  const { id_token } = req.body;
  
  try {
    // Validate ID token
    const claims = await validateIdToken(id_token);
    
    // Perform logout operations
    console.log(`User ${claims.sub} logged out`);
    
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(400).json({ error: 'Invalid ID token' });
  }
});
```

---

## ⚠️ **Security Considerations**

### **ID Token Security**
- Always validate ID token signatures using JWKS
- Verify issuer, audience, and expiration claims
- Check nonce to prevent replay attacks
- Use HTTPS for all OIDC communications
- Store ID tokens securely (avoid localStorage for sensitive data)

### **UserInfo Security**
- UserInfo endpoint requires valid access token
- Scope-based filtering protects user privacy
- Implement rate limiting for UserInfo requests
- Monitor UserInfo access patterns

### **JWKS Security**
- Cache JWKS appropriately (recommended: 1 hour TTL)
- Implement fallback for key rotation
- Validate key algorithm and usage parameters
- Monitor key rotation events

### **Session Security**
- Implement proper session timeout
- Use secure session storage mechanisms
- Monitor for session hijacking attempts
- Implement logout confirmation

---

## 🔧 **Troubleshooting**

### **Common Issues**

#### **ID Token Validation Fails**
```javascript
// Check common validation issues
const troubleshootIdToken = (idToken, clientId, nonce) => {
  try {
    // Decode without verification to inspect claims
    const decoded = jwt.decode(idToken, { complete: true });
    
    console.log('Header:', decoded.header);
    console.log('Payload:', decoded.payload);
    
    // Check common issues
    if (decoded.payload.aud !== clientId) {
      console.error('Audience mismatch:', decoded.payload.aud, 'vs', clientId);
    }
    
    if (decoded.payload.nonce !== nonce) {
      console.error('Nonce mismatch:', decoded.payload.nonce, 'vs', nonce);
    }
    
    if (decoded.payload.exp < Date.now() / 1000) {
      console.error('Token expired:', new Date(decoded.payload.exp * 1000));
    }
    
  } catch (err) {
    console.error('Failed to decode token:', err.message);
  }
};
```

#### **UserInfo Request Fails**
- Verify access token is valid and not expired
- Check that required scopes are included in token
- Ensure UserInfo endpoint URL is correct
- Verify network connectivity and CORS settings

#### **JWKS Key Not Found**
- Check if key ID (kid) exists in JWKS response
- Verify JWKS endpoint is accessible
- Check for key rotation timing issues
- Clear JWKS cache and retry

### **Debug Mode**

Enable debug logging for OIDC operations:

```javascript
// Debug OIDC flow
const debugOIDC = {
  logTokens: (tokens) => {
    console.log('Received tokens:', {
      access_token: tokens.access_token ? 'present' : 'missing',
      refresh_token: tokens.refresh_token ? 'present' : 'missing',
      id_token: tokens.id_token ? 'present' : 'missing',
      scope: tokens.scope
    });
    
    if (tokens.id_token) {
      const decoded = jwt.decode(tokens.id_token);
      console.log('ID token claims:', decoded);
    }
  },
  
  logUserInfo: (userInfo) => {
    console.log('UserInfo response:', userInfo);
  },
  
  logJWKS: (jwks) => {
    console.log('JWKS keys:', jwks.keys.map(k => ({
      kid: k.kid,
      alg: k.alg,
      use: k.use
    })));
  }
};
```

---

This comprehensive OIDC guide provides everything needed to integrate with Authly's OpenID Connect 1.0 implementation. For OAuth 2.1 features, see the [OAuth Guide](oauth-guide.md). For detailed API reference, see the [API Reference](api-reference.md).