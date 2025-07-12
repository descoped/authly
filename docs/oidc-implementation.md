# OpenID Connect (OIDC) Implementation Guide

**Document Version**: 1.0  
**Authly Version**: Production-ready OAuth 2.1 + OIDC 1.0  
**Last Updated**: 2025-07-12  
**Status**: ✅ **Complete OIDC Core 1.0 + Session Management 1.0 Compliance**

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [OIDC Endpoints](#oidc-endpoints)
4. [Supported Scopes and Claims](#supported-scopes-and-claims)
5. [Client Integration Examples](#client-integration-examples)
6. [Session Management](#session-management)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)
9. [Specification Compliance](#specification-compliance)

---

## 🎯 Overview

Authly provides **complete OpenID Connect (OIDC) Core 1.0 specification compliance** with additional Session Management 1.0 support. OIDC extends OAuth 2.1 to provide identity information about authenticated users through standardized ID tokens and claims.

### **Key Features**

- ✅ **Full OIDC Core 1.0 compliance** - All required features implemented
- ✅ **Session Management 1.0** - Complete session monitoring and logout coordination
- ✅ **Standard claims support** - Profile, email, phone, and address scopes
- ✅ **Multiple signature algorithms** - RS256 and HS256 ID token signing
- ✅ **Production security** - Enterprise-grade security practices
- ✅ **Comprehensive testing** - 45+ OIDC-specific tests ensuring reliability

### **What is OpenID Connect?**

OpenID Connect is an identity layer built on top of OAuth 2.1 that allows clients to:
- **Verify user identity** through ID tokens
- **Obtain user information** via standardized claims
- **Manage user sessions** across multiple applications
- **Implement secure logout** with session coordination

---

## 🚀 Quick Start

### **1. Discovery Endpoint**

Start by discovering Authly's OIDC capabilities:

```bash
curl https://your-authly-server/.well-known/openid_configuration
```

**Response includes**:
- Authorization and token endpoints
- Supported scopes, claims, and algorithms
- Session management endpoints
- JWKS URI for token verification

### **2. Basic OIDC Flow**

The standard OIDC authorization code flow:

```
1. Redirect user to authorization endpoint with `openid` scope
2. User authenticates and grants consent
3. Receive authorization code
4. Exchange code for access token + ID token
5. Verify ID token and extract user claims
6. Optionally call UserInfo endpoint for additional claims
```

### **3. Minimal Client Configuration**

```javascript
const oidcConfig = {
  issuer: 'https://your-authly-server',
  client_id: 'your-client-id',
  client_secret: 'your-client-secret',
  redirect_uris: ['https://your-app.com/callback'],
  response_types: ['code'],
  scopes: ['openid', 'profile', 'email']
};
```

---

## 🛡️ OIDC Endpoints

### **Discovery Endpoint**
```
GET /.well-known/openid_configuration
```
**Purpose**: Provides server metadata and capabilities  
**Authentication**: None required  
**Response**: Complete OIDC server configuration

### **Authorization Endpoint**
```
GET /api/v1/oauth/authorize
```
**Purpose**: Initiates OIDC authentication flow  
**Required Parameters**: 
- `response_type=code`
- `client_id`
- `redirect_uri`
- `scope` (must include `openid`)
- `code_challenge` (PKCE required)

**OIDC Parameters**:
- `nonce` - Prevents replay attacks in ID tokens
- `display` - UI display preference (page, popup, touch, wap)
- `prompt` - Authentication behavior (none, login, consent, select_account)
- `max_age` - Maximum authentication age in seconds
- `ui_locales` - Preferred languages for UI
- `id_token_hint` - Hint about user's current session
- `login_hint` - Hint for user identification
- `acr_values` - Authentication Context Class Reference values

### **Token Endpoint**
```
POST /api/v1/auth/token
```
**Purpose**: Exchange authorization code for tokens  
**Authentication**: Client authentication required  
**Response**: Access token + **ID token** (when `openid` scope granted)

**ID Token Structure**:
```json
{
  "iss": "https://your-authly-server",
  "sub": "user-identifier",
  "aud": "client-id",
  "exp": 1234567890,
  "iat": 1234567890,
  "nonce": "request-nonce",
  "auth_time": 1234567890,
  "name": "John Doe",
  "email": "john.doe@example.com",
  "email_verified": true
}
```

### **UserInfo Endpoint**
```
GET /api/v1/oidc/userinfo
Authorization: Bearer {access_token}
```
**Purpose**: Retrieve user claims based on granted scopes  
**Authentication**: Valid access token with `openid` scope  
**Response**: User claims filtered by granted scopes

### **JWKS Endpoint**
```
GET /.well-known/jwks.json
```
**Purpose**: Public keys for ID token signature verification  
**Authentication**: None required  
**Caching**: Recommended with Cache-Control headers

### **Session Management Endpoints**

#### **End Session (Logout)**
```
GET /api/v1/oidc/logout
```
**Purpose**: OIDC-compliant user logout  
**Parameters**:
- `id_token_hint` (optional) - ID token for client validation
- `post_logout_redirect_uri` (optional) - Redirect after logout
- `state` (optional) - Client state preservation

#### **Session iframe**
```
GET /api/v1/oidc/session/iframe
```
**Purpose**: iframe for client-side session monitoring  
**Usage**: Embed in client applications for session state tracking

#### **Session Status Check**
```
GET /api/v1/oidc/session/check
```
**Purpose**: Check current session status  
**Parameters**: `client_id` (optional)  
**Response**: Session state information

#### **Front-Channel Logout**
```
GET /api/v1/oidc/frontchannel/logout
```
**Purpose**: Coordinate logout across multiple clients  
**Parameters**:
- `iss` - Issuer identifier for validation
- `sid` - Session identifier

---

## 🏷️ Supported Scopes and Claims

### **Standard OIDC Scopes**

#### **`openid` (Required)**
- **Description**: Required for all OIDC requests
- **Claims**: `sub`, `iss`, `aud`, `exp`, `iat`
- **Usage**: Must be included in all OIDC authorization requests

#### **`profile`**
- **Description**: User profile information
- **Claims**: `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at`
- **Example**: Name, profile picture, personal website

#### **`email`**
- **Description**: Email address and verification status
- **Claims**: `email`, `email_verified`
- **Usage**: Essential for user communication and account management

#### **`phone`**
- **Description**: Phone number and verification status
- **Claims**: `phone_number`, `phone_number_verified`
- **Usage**: Two-factor authentication, account recovery

#### **`address`**
- **Description**: Physical mailing address
- **Claims**: `address` (structured claim)
- **Format**: JSON object with `street_address`, `locality`, `region`, `postal_code`, `country`

### **Claims Reference**

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string | Subject identifier (unique user ID) |
| `name` | string | Full name |
| `given_name` | string | First name |
| `family_name` | string | Last name |
| `middle_name` | string | Middle name |
| `nickname` | string | Casual name |
| `preferred_username` | string | Preferred username |
| `profile` | string | Profile page URL |
| `picture` | string | Profile picture URL |
| `website` | string | Personal website URL |
| `email` | string | Email address |
| `email_verified` | boolean | Email verification status |
| `gender` | string | Gender |
| `birthdate` | string | Birth date (YYYY-MM-DD) |
| `zoneinfo` | string | Time zone |
| `locale` | string | Locale preference |
| `phone_number` | string | Phone number |
| `phone_number_verified` | boolean | Phone verification status |
| `address` | object | Structured address |
| `updated_at` | number | Profile last update time |

---

## 💻 Client Integration Examples

### **JavaScript (Browser)**

#### **Using oidc-client-js Library**

```javascript
import { UserManager } from 'oidc-client';

// Configuration
const config = {
  authority: 'https://your-authly-server',
  client_id: 'your-spa-client',
  redirect_uri: 'https://your-app.com/callback',
  post_logout_redirect_uri: 'https://your-app.com/logout-callback',
  response_type: 'code',
  scope: 'openid profile email',
  
  // PKCE configuration (automatically handled)
  automaticSilentRenew: true,
  silent_redirect_uri: 'https://your-app.com/silent-callback'
};

const userManager = new UserManager(config);

// Start authentication
async function login() {
  try {
    await userManager.signinRedirect();
  } catch (error) {
    console.error('Login failed:', error);
  }
}

// Handle callback
async function handleCallback() {
  try {
    const user = await userManager.signinRedirectCallback();
    console.log('User authenticated:', user);
    
    // Access ID token claims
    console.log('User ID:', user.profile.sub);
    console.log('Name:', user.profile.name);
    console.log('Email:', user.profile.email);
    
    return user;
  } catch (error) {
    console.error('Callback handling failed:', error);
  }
}

// Get current user
async function getCurrentUser() {
  try {
    const user = await userManager.getUser();
    return user;
  } catch (error) {
    console.error('Failed to get user:', error);
  }
}

// Logout
async function logout() {
  try {
    await userManager.signoutRedirect();
  } catch (error) {
    console.error('Logout failed:', error);
  }
}

// Session monitoring
userManager.events.addUserSignedOut(() => {
  console.log('User signed out');
});

userManager.events.addSilentRenewError((error) => {
  console.error('Silent renew failed:', error);
});
```

#### **Vanilla JavaScript Implementation**

```javascript
class AuthlyOIDCClient {
  constructor(config) {
    this.config = config;
    this.discoveryCache = null;
  }

  // Discover OIDC configuration
  async getDiscoveryDocument() {
    if (this.discoveryCache) {
      return this.discoveryCache;
    }

    const response = await fetch(`${this.config.issuer}/.well-known/openid_configuration`);
    this.discoveryCache = await response.json();
    return this.discoveryCache;
  }

  // Generate PKCE challenge
  generatePKCE() {
    const codeVerifier = this.base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = this.base64URLEncode(
      new Uint8Array(crypto.subtle.digestSync('SHA-256', new TextEncoder().encode(codeVerifier)))
    );
    
    return { codeVerifier, codeChallenge: challenge };
  }

  // Start authorization flow
  async authorize(scopes = ['openid', 'profile', 'email']) {
    const discovery = await this.getDiscoveryDocument();
    const pkce = this.generatePKCE();
    const nonce = this.generateNonce();
    const state = this.generateState();

    // Store for later use
    sessionStorage.setItem('code_verifier', pkce.codeVerifier);
    sessionStorage.setItem('nonce', nonce);
    sessionStorage.setItem('state', state);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.client_id,
      redirect_uri: this.config.redirect_uri,
      scope: scopes.join(' '),
      code_challenge: pkce.codeChallenge,
      code_challenge_method: 'S256',
      nonce: nonce,
      state: state
    });

    window.location.href = `${discovery.authorization_endpoint}?${params}`;
  }

  // Handle authorization callback
  async handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const storedState = sessionStorage.getItem('state');

    if (state !== storedState) {
      throw new Error('Invalid state parameter');
    }

    const codeVerifier = sessionStorage.getItem('code_verifier');
    const nonce = sessionStorage.getItem('nonce');

    // Exchange code for tokens
    const tokens = await this.exchangeCodeForTokens(code, codeVerifier);
    
    // Verify ID token
    const idTokenClaims = await this.verifyIdToken(tokens.id_token, nonce);
    
    // Store tokens securely
    this.storeTokens(tokens);
    
    return { tokens, claims: idTokenClaims };
  }

  // Exchange authorization code for tokens
  async exchangeCodeForTokens(code, codeVerifier) {
    const discovery = await this.getDiscoveryDocument();
    
    const response = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${btoa(`${this.config.client_id}:${this.config.client_secret}`)}`
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: this.config.redirect_uri,
        code_verifier: codeVerifier,
        client_id: this.config.client_id
      })
    });

    if (!response.ok) {
      throw new Error('Token exchange failed');
    }

    return await response.json();
  }

  // Call UserInfo endpoint
  async getUserInfo(accessToken) {
    const discovery = await this.getDiscoveryDocument();
    
    const response = await fetch(discovery.userinfo_endpoint, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    if (!response.ok) {
      throw new Error('UserInfo request failed');
    }

    return await response.json();
  }

  // Logout
  async logout(idToken) {
    const discovery = await this.getDiscoveryDocument();
    
    const params = new URLSearchParams({
      id_token_hint: idToken,
      post_logout_redirect_uri: this.config.post_logout_redirect_uri
    });

    window.location.href = `${discovery.end_session_endpoint}?${params}`;
  }

  // Utility methods
  base64URLEncode(buffer) {
    return btoa(String.fromCharCode(...buffer))
      .replace(/\\+/g, '-')
      .replace(/\\//g, '_')
      .replace(/=/g, '');
  }

  generateNonce() {
    return this.base64URLEncode(crypto.getRandomValues(new Uint8Array(16)));
  }

  generateState() {
    return this.base64URLEncode(crypto.getRandomValues(new Uint8Array(16)));
  }

  storeTokens(tokens) {
    // Store securely (consider using secure storage)
    sessionStorage.setItem('access_token', tokens.access_token);
    sessionStorage.setItem('id_token', tokens.id_token);
    if (tokens.refresh_token) {
      sessionStorage.setItem('refresh_token', tokens.refresh_token);
    }
  }
}

// Usage
const client = new AuthlyOIDCClient({
  issuer: 'https://your-authly-server',
  client_id: 'your-client-id',
  client_secret: 'your-client-secret',
  redirect_uri: 'https://your-app.com/callback',
  post_logout_redirect_uri: 'https://your-app.com/'
});

// Start login
document.getElementById('login').onclick = () => {
  client.authorize(['openid', 'profile', 'email', 'phone']);
};

// Handle callback (on callback page)
if (window.location.pathname === '/callback') {
  client.handleCallback()
    .then(result => {
      console.log('Login successful:', result.claims);
      // Redirect to main app
      window.location.href = '/dashboard';
    })
    .catch(error => {
      console.error('Login failed:', error);
    });
}
```

### **Python Client**

#### **Using authlib Library**

```python
from authlib.integrations.requests_client import OAuth2Session
from authlib.oidc.core import CodeIDToken
import requests

class AuthlyOIDCClient:
    def __init__(self, client_id, client_secret, issuer_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.issuer_url = issuer_url
        self.discovery_cache = None
        
    def get_discovery_document(self):
        """Get OIDC discovery document."""
        if self.discovery_cache:
            return self.discovery_cache
            
        response = requests.get(f"{self.issuer_url}/.well-known/openid_configuration")
        response.raise_for_status()
        self.discovery_cache = response.json()
        return self.discovery_cache
    
    def create_authorization_url(self, redirect_uri, scopes=None):
        """Create authorization URL for OIDC flow."""
        if scopes is None:
            scopes = ['openid', 'profile', 'email']
            
        discovery = self.get_discovery_document()
        
        # Create OAuth2 session with PKCE
        session = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=redirect_uri,
            scope=' '.join(scopes),
            code_challenge_method='S256'
        )
        
        # Generate authorization URL
        authorization_url, state = session.create_authorization_url(
            discovery['authorization_endpoint'],
            nonce='random-nonce-value'  # Generate securely in production
        )
        
        return authorization_url, state, session.code_verifier
    
    def exchange_code_for_tokens(self, code, redirect_uri, code_verifier, state):
        """Exchange authorization code for tokens."""
        discovery = self.get_discovery_document()
        
        # Create session with stored code verifier
        session = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier
        )
        
        # Fetch tokens
        tokens = session.fetch_token(
            discovery['token_endpoint'],
            code=code,
            client_secret=self.client_secret
        )
        
        return tokens
    
    def verify_id_token(self, id_token, nonce):
        """Verify and decode ID token."""
        discovery = self.get_discovery_document()
        
        # Get JWKS for verification
        jwks_response = requests.get(discovery['jwks_uri'])
        jwks = jwks_response.json()
        
        # Verify ID token (simplified - use proper JWT library)
        # In production, use authlib's JWT verification
        claims = CodeIDToken.parse(id_token, key=jwks)
        
        # Verify nonce
        if claims.get('nonce') != nonce:
            raise ValueError('Invalid nonce in ID token')
            
        return claims
    
    def get_userinfo(self, access_token):
        """Get user information from UserInfo endpoint."""
        discovery = self.get_discovery_document()
        
        response = requests.get(
            discovery['userinfo_endpoint'],
            headers={'Authorization': f'Bearer {access_token}'}
        )
        response.raise_for_status()
        return response.json()
    
    def logout(self, id_token, post_logout_redirect_uri):
        """Initiate OIDC logout."""
        discovery = self.get_discovery_document()
        
        params = {
            'id_token_hint': id_token,
            'post_logout_redirect_uri': post_logout_redirect_uri
        }
        
        logout_url = f"{discovery['end_session_endpoint']}?" + \
                    "&".join([f"{k}={v}" for k, v in params.items()])
        
        return logout_url

# Usage example
client = AuthlyOIDCClient(
    client_id='your-client-id',
    client_secret='your-client-secret',
    issuer_url='https://your-authly-server'
)

# Step 1: Generate authorization URL
auth_url, state, code_verifier = client.create_authorization_url(
    redirect_uri='https://your-app.com/callback',
    scopes=['openid', 'profile', 'email', 'phone']
)

print(f"Visit: {auth_url}")

# Step 2: After user authorization, exchange code for tokens
# (code received from callback)
tokens = client.exchange_code_for_tokens(
    code='authorization-code-from-callback',
    redirect_uri='https://your-app.com/callback',
    code_verifier=code_verifier,
    state=state
)

# Step 3: Verify ID token
claims = client.verify_id_token(tokens['id_token'], nonce='your-nonce')
print(f"User: {claims}")

# Step 4: Get additional user info
userinfo = client.get_userinfo(tokens['access_token'])
print(f"UserInfo: {userinfo}")

# Step 5: Logout
logout_url = client.logout(
    tokens['id_token'], 
    'https://your-app.com/logout-complete'
)
print(f"Logout at: {logout_url}")
```

### **Node.js/Express Server**

```javascript
const express = require('express');
const session = require('express-session');
const { Issuer, Strategy } = require('openid-client');
const passport = require('passport');

const app = express();

// Session configuration
app.use(session({
  secret: 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

app.use(passport.initialize());
app.use(passport.session());

// Discover OIDC issuer
async function setupOIDC() {
  const issuer = await Issuer.discover('https://your-authly-server');
  
  const client = new issuer.Client({
    client_id: 'your-client-id',
    client_secret: 'your-client-secret',
    redirect_uris: ['https://your-app.com/auth/callback'],
    response_types: ['code'],
  });

  // Configure passport strategy
  passport.use('oidc', new Strategy({
    client,
    params: {
      scope: 'openid profile email phone'
    }
  }, (tokenset, userinfo, done) => {
    // Store user information
    const user = {
      id: userinfo.sub,
      name: userinfo.name,
      email: userinfo.email,
      phone: userinfo.phone_number,
      tokens: tokenset
    };
    
    return done(null, user);
  }));

  return { issuer, client };
}

// Serialize/deserialize user for session
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Routes
app.get('/auth/login', passport.authenticate('oidc'));

app.get('/auth/callback', 
  passport.authenticate('oidc', { 
    successRedirect: '/dashboard', 
    failureRedirect: '/login' 
  })
);

app.get('/auth/logout', async (req, res) => {
  const { issuer } = await setupOIDC();
  
  req.logout(() => {
    const logoutUrl = issuer.end_session_endpoint + '?' + 
      `id_token_hint=${req.user.tokens.id_token}&` +
      `post_logout_redirect_uri=${encodeURIComponent('https://your-app.com/')}`;
    
    res.redirect(logoutUrl);
  });
});

app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/auth/login');
  }
  
  res.json({
    message: 'Welcome to dashboard',
    user: req.user
  });
});

app.get('/profile', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/auth/login');
  }
  
  // Get fresh user info
  const { client } = await setupOIDC();
  const userinfo = await client.userinfo(req.user.tokens.access_token);
  
  res.json(userinfo);
});

// Initialize OIDC and start server
setupOIDC().then(() => {
  app.listen(3000, () => {
    console.log('App running on http://localhost:3000');
  });
}).catch(console.error);
```

---

## 🔧 Session Management

Authly provides complete OIDC Session Management 1.0 specification support for coordinated session handling across multiple applications.

### **Session Monitoring**

#### **Session iframe Integration**

```javascript
// Embed session monitoring iframe
const iframe = document.createElement('iframe');
iframe.src = 'https://your-authly-server/api/v1/oidc/session/iframe';
iframe.style.display = 'none';
document.body.appendChild(iframe);

// Listen for session changes
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://your-authly-server') return;
  
  if (event.data === 'changed') {
    console.log('Session changed - may need re-authentication');
    // Handle session change (e.g., prompt for re-login)
  }
});

// Periodically check session status
setInterval(() => {
  iframe.contentWindow.postMessage(
    `oidc-session-check ${clientId} ${currentSessionState}`,
    'https://your-authly-server'
  );
}, 3000);
```

#### **Session Status Check API**

```javascript
// Check current session status
async function checkSessionStatus(clientId) {
  const response = await fetch(
    `https://your-authly-server/api/v1/oidc/session/check?client_id=${clientId}`
  );
  
  const status = await response.json();
  
  return {
    authenticated: status.authenticated,
    sessionState: status.session_state,
    checkTime: status.check_time
  };
}

// Usage
const sessionStatus = await checkSessionStatus('your-client-id');
console.log('Session status:', sessionStatus);
```

### **Coordinated Logout**

#### **Single Logout**

```javascript
// Logout from current application only
function singleLogout(idToken) {
  const logoutUrl = `https://your-authly-server/api/v1/oidc/logout?` +
    `id_token_hint=${idToken}&` +
    `post_logout_redirect_uri=${encodeURIComponent('https://your-app.com/logout-complete')}`;
  
  window.location.href = logoutUrl;
}
```

#### **Front-Channel Logout (Cross-Application)**

Front-channel logout enables coordinated logout across multiple applications. When one application initiates logout, all participating applications are notified.

**Application Setup**:
```javascript
// Register front-channel logout handler
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://your-authly-server') return;
  
  if (event.data.type === 'frontchannel-logout') {
    // Clear local session
    localStorage.removeItem('tokens');
    sessionStorage.clear();
    
    // Redirect to logout page
    window.location.href = '/logged-out';
  }
});

// Include logout iframe in each application
const logoutFrame = document.createElement('iframe');
logoutFrame.src = `https://your-authly-server/api/v1/oidc/frontchannel/logout?` +
  `iss=${encodeURIComponent('https://your-authly-server')}&` +
  `sid=${sessionId}`;
logoutFrame.style.display = 'none';
document.body.appendChild(logoutFrame);
```

---

## 🔒 Security Considerations

### **ID Token Verification**

Always verify ID tokens before trusting their contents:

```javascript
async function verifyIdToken(idToken) {
  // 1. Get JWKS from Authly
  const jwksResponse = await fetch('https://your-authly-server/.well-known/jwks.json');
  const jwks = await jwksResponse.json();
  
  // 2. Verify signature (use JWT library)
  const decoded = jwt.verify(idToken, jwks, {
    issuer: 'https://your-authly-server',
    audience: 'your-client-id'
  });
  
  // 3. Verify nonce (if used)
  if (decoded.nonce && decoded.nonce !== expectedNonce) {
    throw new Error('Invalid nonce');
  }
  
  // 4. Check expiration
  if (decoded.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expired');
  }
  
  return decoded;
}
```

### **PKCE Implementation**

Authly requires PKCE for all clients (OAuth 2.1 compliance):

```javascript
// Generate PKCE challenge
function generatePKCE() {
  const codeVerifier = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
  const codeChallenge = base64URLEncode(
    crypto.subtle.digestSync('SHA-256', new TextEncoder().encode(codeVerifier))
  );
  
  return { codeVerifier, codeChallenge };
}

// Use in authorization request
const pkce = generatePKCE();
const authUrl = `https://your-authly-server/api/v1/oauth/authorize?` +
  `response_type=code&` +
  `client_id=${clientId}&` +
  `redirect_uri=${redirectUri}&` +
  `scope=openid profile email&` +
  `code_challenge=${pkce.codeChallenge}&` +
  `code_challenge_method=S256&` +
  `nonce=${nonce}&` +
  `state=${state}`;
```

### **Token Storage**

**Secure Token Storage Guidelines**:

1. **Browser Applications**: Use secure, httpOnly cookies or sessionStorage
2. **Mobile Applications**: Use platform keychain/keystore
3. **Server Applications**: Store in secure session storage with encryption
4. **Never store in localStorage** - vulnerable to XSS attacks

```javascript
// Secure token storage example
class SecureTokenStorage {
  static store(tokens) {
    // Use httpOnly cookies for maximum security
    document.cookie = `access_token=${tokens.access_token}; Secure; HttpOnly; SameSite=Strict`;
    document.cookie = `id_token=${tokens.id_token}; Secure; HttpOnly; SameSite=Strict`;
    
    // Store refresh token separately with shorter expiry
    if (tokens.refresh_token) {
      document.cookie = `refresh_token=${tokens.refresh_token}; Secure; HttpOnly; SameSite=Strict; Max-Age=604800`;
    }
  }
  
  static clear() {
    document.cookie = 'access_token=; Max-Age=0';
    document.cookie = 'id_token=; Max-Age=0';
    document.cookie = 'refresh_token=; Max-Age=0';
  }
}
```

### **Session Security**

```javascript
// Implement session timeout
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
let sessionTimer;

function resetSessionTimer() {
  clearTimeout(sessionTimer);
  sessionTimer = setTimeout(() => {
    alert('Session expired. Please log in again.');
    logout();
  }, SESSION_TIMEOUT);
}

// Reset timer on user activity
document.addEventListener('click', resetSessionTimer);
document.addEventListener('keypress', resetSessionTimer);
```

### **Rate Limiting Awareness**

Authly implements rate limiting on all endpoints:

```javascript
// Implement retry logic with exponential backoff
async function retryRequest(requestFn, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await requestFn();
    } catch (error) {
      if (error.status === 429 && i < maxRetries - 1) {
        const delay = Math.pow(2, i) * 1000; // Exponential backoff
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
}

// Usage
const userInfo = await retryRequest(() => 
  fetch('/api/v1/oidc/userinfo', {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  })
);
```

---

## 🔍 Troubleshooting

### **Common Issues**

#### **1. "invalid_scope" Error**
**Problem**: Authorization request fails with invalid scope error  
**Solution**: Ensure `openid` scope is included in all OIDC requests
```javascript
// ❌ Wrong
scope: 'profile email'

// ✅ Correct
scope: 'openid profile email'
```

#### **2. ID Token Verification Failures**
**Problem**: ID token signature verification fails  
**Solution**: Check issuer, audience, and JWKS endpoint
```javascript
// Verify token parameters
const decoded = jwt.decode(idToken, { complete: true });
console.log('Issuer:', decoded.payload.iss);  // Should match your Authly server
console.log('Audience:', decoded.payload.aud); // Should match your client_id
console.log('Algorithm:', decoded.header.alg); // Should be RS256 or HS256
```

#### **3. PKCE Validation Errors**
**Problem**: Token exchange fails with PKCE validation error  
**Solution**: Ensure code_verifier matches the original code_challenge
```javascript
// Store code_verifier securely during authorization
sessionStorage.setItem('code_verifier', codeVerifier);

// Use the same verifier in token exchange
const storedVerifier = sessionStorage.getItem('code_verifier');
```

#### **4. Nonce Mismatch**
**Problem**: ID token contains invalid nonce  
**Solution**: Ensure nonce in ID token matches the original request
```javascript
// Generate and store nonce
const nonce = generateRandomString();
sessionStorage.setItem('nonce', nonce);

// Verify nonce in ID token
const decodedToken = jwt.decode(idToken);
const storedNonce = sessionStorage.getItem('nonce');
if (decodedToken.nonce !== storedNonce) {
  throw new Error('Nonce mismatch');
}
```

#### **5. Session Management Issues**
**Problem**: Session iframe not responding to messages  
**Solution**: Check origin validation and message format
```javascript
// Ensure correct message format
iframe.contentWindow.postMessage(
  `oidc-session-check ${clientId} ${sessionState}`,
  'https://your-authly-server' // Must match iframe origin
);

// Handle responses properly
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://your-authly-server') return;
  
  if (event.data === 'changed') {
    // Handle session change
  }
});
```

### **Debugging Tools**

#### **Discovery Document Validation**
```bash
# Check OIDC discovery document
curl -s https://your-authly-server/.well-known/openid_configuration | jq

# Verify required endpoints exist
curl -s https://your-authly-server/.well-known/openid_configuration | jq '.authorization_endpoint, .token_endpoint, .userinfo_endpoint, .end_session_endpoint'
```

#### **JWKS Verification**
```bash
# Check JWKS endpoint
curl -s https://your-authly-server/.well-known/jwks.json | jq

# Verify key algorithms
curl -s https://your-authly-server/.well-known/jwks.json | jq '.keys[].alg'
```

#### **Token Introspection**
```javascript
// Decode ID token for debugging (without verification)
function debugIdToken(idToken) {
  const [header, payload, signature] = idToken.split('.');
  
  return {
    header: JSON.parse(atob(header)),
    payload: JSON.parse(atob(payload)),
    signature: signature
  };
}

const tokenInfo = debugIdToken(idToken);
console.log('Token info:', tokenInfo);
```

#### **Network Debugging**
```javascript
// Log all OIDC-related requests
const originalFetch = window.fetch;
window.fetch = function(...args) {
  const [url, options] = args;
  
  if (url.includes('your-authly-server')) {
    console.log('OIDC Request:', {
      url,
      method: options?.method || 'GET',
      headers: options?.headers,
      body: options?.body
    });
  }
  
  return originalFetch.apply(this, args).then(response => {
    if (url.includes('your-authly-server')) {
      console.log('OIDC Response:', {
        url,
        status: response.status,
        headers: [...response.headers.entries()]
      });
    }
    return response;
  });
};
```

---

## 📋 Specification Compliance

Authly provides **complete compliance** with the following specifications:

### **✅ OpenID Connect Core 1.0**
- [x] Authorization Code Flow
- [x] ID Token generation and validation
- [x] UserInfo endpoint
- [x] Standard claims support
- [x] Multiple signature algorithms (RS256, HS256)
- [x] Nonce parameter support
- [x] PKCE requirement (OAuth 2.1)

### **✅ OpenID Connect Discovery 1.0**
- [x] Discovery document (`/.well-known/openid_configuration`)
- [x] JWKS endpoint (`/.well-known/jwks.json`)
- [x] Complete server metadata
- [x] Dynamic capability advertisement

### **✅ OpenID Connect Session Management 1.0**
- [x] End Session endpoint
- [x] Session Management iframe
- [x] Front-Channel Logout
- [x] Session status checking
- [x] Cross-application logout coordination

### **✅ OAuth 2.1 Security Best Practices**
- [x] PKCE required for all clients
- [x] Secure redirect URI validation
- [x] Rate limiting and abuse protection
- [x] Secure token storage recommendations
- [x] Comprehensive security headers

### **🔄 Supported Parameters**

| Parameter | Support | Description |
|-----------|---------|-------------|
| `response_type` | ✅ | `code` (Authorization Code Flow) |
| `scope` | ✅ | `openid`, `profile`, `email`, `phone`, `address` |
| `nonce` | ✅ | Replay attack prevention |
| `display` | ✅ | `page`, `popup`, `touch`, `wap` |
| `prompt` | ✅ | `none`, `login`, `consent`, `select_account` |
| `max_age` | ✅ | Maximum authentication age |
| `ui_locales` | ✅ | UI language preferences |
| `id_token_hint` | ✅ | Session context hints |
| `login_hint` | ✅ | User identification hints |
| `acr_values` | ✅ | Authentication context references |

### **🔄 Supported Claims**

All standard OIDC claims are supported according to the specification:

- **Essential Claims**: `sub`, `iss`, `aud`, `exp`, `iat`
- **Profile Claims**: `name`, `given_name`, `family_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at`
- **Email Claims**: `email`, `email_verified`
- **Phone Claims**: `phone_number`, `phone_number_verified`
- **Address Claims**: `address` (structured)

### **✅ Security Features**

- **JWT Signing**: RS256 (default) and HS256
- **Token Validation**: Complete signature and claim verification
- **PKCE**: S256 method required
- **Rate Limiting**: Comprehensive endpoint protection
- **CORS**: Proper cross-origin configuration
- **Security Headers**: Complete set implemented

---

## 📚 Additional Resources

### **Specification References**
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)
- [OAuth 2.1 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

### **Client Libraries**
- **JavaScript**: [oidc-client-js](https://github.com/IdentityModel/oidc-client-js)
- **Python**: [authlib](https://github.com/lepture/authlib)
- **Node.js**: [openid-client](https://github.com/panva/node-openid-client)
- **Java**: [Nimbus OAuth 2.0 SDK](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk)
- **C#**: [IdentityModel](https://github.com/IdentityModel/IdentityModel)

### **Testing Tools**
- [jwt.io](https://jwt.io/) - JWT token debugging
- [OIDC Debugger](https://oidcdebugger.com/) - Flow testing
- [OAuth 2.0 Playground](https://developers.google.com/oauthplayground) - Flow simulation

### **Authly Documentation**
- [API Reference](./api-reference.md)
- [Client Registration Guide](./client-registration.md)
- [Security Guide](./security-guide.md)
- [Deployment Guide](./deployment-guide.md)

---

**Document Information**:
- **Version**: 1.0
- **Last Updated**: 2025-07-12
- **Status**: Production Ready
- **Compliance**: OIDC Core 1.0 + Session Management 1.0

For questions or support, please refer to the [troubleshooting section](#troubleshooting) or consult the Authly community resources.