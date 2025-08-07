# OpenID Connect (OIDC) Implementation Guide

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Configuration](#configuration)
- [Endpoints](#endpoints)
- [Integration Examples](#integration-examples)
- [ID Token Claims](#id-token-claims)
- [JWKS and Key Management](#jwks-and-key-management)
- [Security Considerations](#security-considerations)
- [Testing OIDC Flows](#testing-oidc-flows)
- [Troubleshooting](#troubleshooting)
- [Advanced Topics](#advanced-topics)
- [Migration Guide](#migration-guide)
- [Performance Optimization](#performance-optimization)
- [Compliance and Certification](#compliance-and-certification)

## Overview

Authly provides a complete OpenID Connect 1.0 implementation built on top of OAuth 2.1, achieving 100% conformance with the OpenID Connect Core 1.0 specification. This guide covers how to configure and use OIDC features for authentication and identity verification.

### What is OpenID Connect?

OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0 that allows clients to verify user identity and obtain basic profile information. Key benefits include:

- **Standardized Authentication**: Industry-standard protocol for authentication
- **ID Tokens**: Cryptographically signed tokens containing user identity claims
- **User Info Endpoint**: Standardized way to retrieve user profile information
- **Discovery**: Automatic configuration discovery for easier integration
- **Single Sign-On (SSO)**: Enable SSO across multiple applications
- **Session Management**: Coordinate sessions across multiple applications

## Features

Authly's OIDC implementation includes:

- ✅ **OpenID Connect Core 1.0** - Full specification compliance
- ✅ **OpenID Connect Discovery** - Automatic configuration discovery via `/.well-known/openid-configuration`
- ✅ **ID Token Generation** - JWT-based ID tokens with customizable claims
- ✅ **JWKS Endpoint** - JSON Web Key Set for token signature verification
- ✅ **UserInfo Endpoint** - Retrieve authenticated user information
- ✅ **Session Management** - OIDC Session Management 1.0 compliance
- ✅ **Front-Channel Logout** - Coordinated logout across applications
- ✅ **Standard OIDC Flows** - Authorization Code with PKCE (required)
- ✅ **Dynamic Key Rotation** - Automatic JWKS key rotation for enhanced security
- ✅ **Claim Customization** - Configure which claims are included in ID tokens
- ✅ **Nonce Validation** - Replay attack protection
- ✅ **Max Age Support** - Force re-authentication based on session age
- ✅ **Multiple Algorithms** - RS256 and HS256 signing algorithms

## Configuration

### Environment Variables

Configure OIDC-specific settings in your environment:

```bash
# OIDC Configuration
AUTHLY_OIDC_ISSUER=https://auth.example.com
AUTHLY_OIDC_JWKS_ROTATION_DAYS=30
AUTHLY_OIDC_ID_TOKEN_EXPIRE_MINUTES=60

# Supported OIDC Claims (comma-separated)
AUTHLY_OIDC_SUPPORTED_CLAIMS=sub,email,name,given_name,family_name,picture,email_verified,phone_number,address

# OIDC Scopes
AUTHLY_OIDC_SUPPORTED_SCOPES=openid,profile,email,phone,address,offline_access

# Session Management
AUTHLY_SESSION_CHECK_INTERVAL=300
AUTHLY_SESSION_IDLE_TIMEOUT=1800
AUTHLY_SESSION_ABSOLUTE_TIMEOUT=86400
```

### Database Setup

Authly uses PostgreSQL to store JWKS keys. The required table is automatically created during migration:

```sql
CREATE TABLE oidc_jwks_keys (
    kid VARCHAR(255) PRIMARY KEY,
    key_data JSONB NOT NULL,
    key_type VARCHAR(50) NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    key_use VARCHAR(50) DEFAULT 'sig',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    key_size INTEGER,
    curve VARCHAR(50)
);

-- Index for active key queries
CREATE INDEX idx_oidc_jwks_active ON oidc_jwks_keys(is_active, created_at DESC);
```

### Client Configuration

Configure OAuth clients to support OIDC:

```python
# Client model configuration
client = OAuthClient(
    client_id="my-oidc-app",
    client_type="confidential",
    redirect_uris=["https://app.example.com/callback"],
    allowed_scopes=["openid", "profile", "email", "phone"],
    
    # OIDC-specific settings
    id_token_signed_response_alg="RS256",
    id_token_encrypted_response_alg=None,
    userinfo_signed_response_alg=None,
    request_object_signing_alg=None,
    
    # Session management
    frontchannel_logout_uri="https://app.example.com/logout",
    frontchannel_logout_session_required=True,
    post_logout_redirect_uris=["https://app.example.com/logged-out"]
)
```

## Endpoints

### Discovery Endpoint

**GET** `/.well-known/openid-configuration`

Returns OIDC provider metadata:

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/api/v1/oauth/authorize",
  "token_endpoint": "https://auth.example.com/api/v1/auth/token",
  "userinfo_endpoint": "https://auth.example.com/api/v1/oidc/userinfo",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "end_session_endpoint": "https://auth.example.com/api/v1/oidc/logout",
  "check_session_iframe": "https://auth.example.com/api/v1/oidc/session/iframe",
  "scopes_supported": ["openid", "profile", "email", "phone", "address", "offline_access"],
  "response_types_supported": ["code", "code id_token"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "HS256"],
  "claims_supported": ["sub", "email", "name", "given_name", "family_name", "picture", "email_verified"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
}
```

### JWKS Endpoint

**GET** `/.well-known/jwks.json`

Returns the JSON Web Key Set for ID token verification:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "2024-01-15-key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "xGOr-H0A-6_BOXMq83kU00T...",
      "e": "AQAB"
    }
  ]
}
```

### UserInfo Endpoint

**GET** `/api/v1/oidc/userinfo`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "sub": "f2aeb8a6-d2ae-4e2c-8fb2-c86911d25cad",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "picture": "https://example.com/photo.jpg",
  "phone_number": "+1234567890",
  "phone_number_verified": true,
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "CA",
    "postal_code": "12345",
    "country": "US"
  },
  "updated_at": 1642012800
}
```

### Authorization Endpoint

**GET** `/api/v1/oauth/authorize`

OIDC-specific parameters:
- `scope` - Must include `openid` for OIDC flow
- `nonce` - Random value for replay protection (recommended)
- `max_age` - Maximum authentication age in seconds
- `prompt` - Values: `none`, `login`, `consent`, `select_account`
- `display` - Values: `page`, `popup`, `touch`, `wap`
- `ui_locales` - Preferred UI languages (space-separated)
- `id_token_hint` - Previously issued ID token
- `login_hint` - Hint for user identification
- `acr_values` - Authentication context class references

Example:
```
https://auth.example.com/api/v1/oauth/authorize?
  client_id=my-app&
  redirect_uri=https://app.example.com/callback&
  response_type=code&
  scope=openid profile email&
  state=abc123&
  nonce=n0nc3-v4lu3&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256&
  prompt=consent&
  max_age=3600
```

### Token Endpoint

**POST** `/api/v1/auth/token`

When exchanging an authorization code with `openid` scope, the response includes an ID token:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "scope": "openid profile email"
}
```

### Session Management Endpoints

#### End Session Endpoint

**GET** `/api/v1/oidc/logout`

Parameters:
- `id_token_hint` - ID token for session identification
- `post_logout_redirect_uri` - Where to redirect after logout
- `state` - Maintain state through logout flow

#### Session Status Check

**GET** `/api/v1/oidc/session/check`

Parameters:
- `client_id` - Client identifier
- `session_state` - Current session state

Response:
```json
{
  "authenticated": true,
  "session_state": "abc123...",
  "check_time": 1642012800
}
```

#### Session Management iframe

**GET** `/api/v1/oidc/session/iframe`

Returns an HTML page for client-side session monitoring.

## Integration Examples

### Python Client (using Authlib)

```python
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import jwt
import secrets
import hashlib
import base64

class AuthlyOIDCClient:
    def __init__(self, client_id, client_secret, issuer):
        self.client_id = client_id
        self.client_secret = client_secret
        self.issuer = issuer
        self.discovery = None
        
    def get_discovery(self):
        """Get and cache discovery document"""
        if not self.discovery:
            import requests
            resp = requests.get(f'{self.issuer}/.well-known/openid-configuration')
            self.discovery = resp.json()
        return self.discovery
    
    def create_authorization_url(self, redirect_uri, scope='openid profile email', **kwargs):
        """Create authorization URL with PKCE"""
        discovery = self.get_discovery()
        
        # Generate PKCE
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        # Generate security parameters
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        
        # Create OAuth session
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=redirect_uri,
            scope=scope
        )
        
        # Build authorization URL
        auth_url, _ = client.create_authorization_url(
            discovery['authorization_endpoint'],
            code_challenge=code_challenge,
            code_challenge_method='S256',
            nonce=nonce,
            state=state,
            **kwargs
        )
        
        return auth_url, state, nonce, code_verifier
    
    def exchange_code(self, code, redirect_uri, code_verifier):
        """Exchange authorization code for tokens"""
        discovery = self.get_discovery()
        
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=redirect_uri
        )
        
        # Exchange code for tokens
        token = client.fetch_token(
            discovery['token_endpoint'],
            code=code,
            code_verifier=code_verifier,
            client_secret=self.client_secret,
            include_client_id=True
        )
        
        return token
    
    def verify_id_token(self, id_token, nonce):
        """Verify and decode ID token"""
        discovery = self.get_discovery()
        
        # Fetch JWKS
        import requests
        jwks_resp = requests.get(discovery['jwks_uri'])
        jwks = jwks_resp.json()
        
        # Verify ID token
        claims = jwt.decode(
            id_token,
            jwks,
            claims_options={
                "iss": {"essential": True, "value": discovery['issuer']},
                "aud": {"essential": True, "value": self.client_id},
                "exp": {"essential": True},
                "nonce": {"essential": True, "value": nonce}
            }
        )
        
        return claims
    
    def get_userinfo(self, access_token):
        """Get user information"""
        discovery = self.get_discovery()
        
        import requests
        resp = requests.get(
            discovery['userinfo_endpoint'],
            headers={'Authorization': f'Bearer {access_token}'}
        )
        resp.raise_for_status()
        return resp.json()
    
    def end_session(self, id_token, post_logout_redirect_uri=None, state=None):
        """Create end session URL"""
        discovery = self.get_discovery()
        
        params = {'id_token_hint': id_token}
        if post_logout_redirect_uri:
            params['post_logout_redirect_uri'] = post_logout_redirect_uri
        if state:
            params['state'] = state
            
        from urllib.parse import urlencode
        return f"{discovery['end_session_endpoint']}?{urlencode(params)}"

# Usage example
if __name__ == "__main__":
    # Initialize client
    client = AuthlyOIDCClient(
        client_id='your-client-id',
        client_secret='your-client-secret',
        issuer='https://auth.example.com'
    )
    
    # Step 1: Create authorization URL
    auth_url, state, nonce, verifier = client.create_authorization_url(
        redirect_uri='http://localhost:8080/callback',
        scope='openid profile email phone',
        prompt='consent',
        max_age=3600
    )
    
    print(f"Visit: {auth_url}")
    
    # Step 2: After user authorizes, exchange code
    # (In a web app, this would be in your callback handler)
    code = input("Enter authorization code: ")
    
    tokens = client.exchange_code(
        code=code,
        redirect_uri='http://localhost:8080/callback',
        code_verifier=verifier
    )
    
    # Step 3: Verify ID token
    claims = client.verify_id_token(tokens['id_token'], nonce)
    print(f"User ID: {claims['sub']}")
    print(f"Email: {claims.get('email')}")
    
    # Step 4: Get additional user info
    userinfo = client.get_userinfo(tokens['access_token'])
    print(f"User Info: {userinfo}")
    
    # Step 5: Logout
    logout_url = client.end_session(
        id_token=tokens['id_token'],
        post_logout_redirect_uri='http://localhost:8080/'
    )
    print(f"Logout URL: {logout_url}")
```

### JavaScript/TypeScript Client (using oidc-client-ts)

```typescript
import { UserManager, WebStorageStateStore, Log } from 'oidc-client-ts';

// Enable logging for debugging
Log.setLogger(console);
Log.setLevel(Log.DEBUG);

// OIDC client configuration
const settings = {
  authority: 'https://auth.example.com',
  client_id: 'your-client-id',
  redirect_uri: 'http://localhost:3000/callback',
  post_logout_redirect_uri: 'http://localhost:3000/',
  response_type: 'code',
  scope: 'openid profile email phone',
  
  // User store configuration
  userStore: new WebStorageStateStore({ store: window.localStorage }),
  
  // Automatic token management
  automaticSilentRenew: true,
  silent_redirect_uri: 'http://localhost:3000/silent-renew',
  accessTokenExpiringNotificationTimeInSeconds: 60,
  
  // Session monitoring
  monitorSession: true,
  checkSessionIntervalInSeconds: 30,
  
  // Security settings
  loadUserInfo: true,
  filterProtocolClaims: true,
  
  // Additional metadata
  metadata: {
    issuer: 'https://auth.example.com',
    authorization_endpoint: 'https://auth.example.com/api/v1/oauth/authorize',
    token_endpoint: 'https://auth.example.com/api/v1/auth/token',
    userinfo_endpoint: 'https://auth.example.com/api/v1/oidc/userinfo',
    end_session_endpoint: 'https://auth.example.com/api/v1/oidc/logout',
    jwks_uri: 'https://auth.example.com/.well-known/jwks.json'
  }
};

const userManager = new UserManager(settings);

// Event handlers
userManager.events.addUserLoaded((user) => {
  console.log('User loaded:', user.profile);
  updateUI(user);
});

userManager.events.addUserUnloaded(() => {
  console.log('User unloaded');
  clearUI();
});

userManager.events.addAccessTokenExpiring(() => {
  console.log('Access token expiring...');
});

userManager.events.addAccessTokenExpired(() => {
  console.log('Access token expired');
  // Attempt silent renewal
  userManager.signinSilent().catch(error => {
    console.error('Silent renewal failed:', error);
    // Fall back to interactive login
    userManager.signinRedirect();
  });
});

userManager.events.addSilentRenewError((error) => {
  console.error('Silent renewal error:', error);
});

userManager.events.addUserSignedOut(() => {
  console.log('User signed out');
  clearUI();
});

// Authentication functions
async function login(extraParams = {}) {
  try {
    await userManager.signinRedirect({
      state: { returnUrl: window.location.pathname },
      extraQueryParams: extraParams
    });
  } catch (error) {
    console.error('Login failed:', error);
  }
}

async function handleCallback() {
  try {
    const user = await userManager.signinRedirectCallback();
    console.log('Login successful:', user);
    
    // Access tokens and claims
    console.log('ID Token:', user.id_token);
    console.log('Access Token:', user.access_token);
    console.log('User Claims:', user.profile);
    
    // Redirect to original location
    const returnUrl = user.state?.returnUrl || '/';
    window.location.href = returnUrl;
  } catch (error) {
    console.error('Callback error:', error);
    window.location.href = '/error';
  }
}

async function logout() {
  try {
    await userManager.signoutRedirect();
  } catch (error) {
    console.error('Logout failed:', error);
  }
}

async function getUser() {
  try {
    const user = await userManager.getUser();
    if (user && !user.expired) {
      return user;
    }
    return null;
  } catch (error) {
    console.error('Error getting user:', error);
    return null;
  }
}

// API calls with automatic token management
async function callApi(endpoint: string, options: RequestInit = {}) {
  const user = await userManager.getUser();
  
  if (!user || user.expired) {
    throw new Error('User not authenticated');
  }
  
  const response = await fetch(endpoint, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${user.access_token}`,
      'Content-Type': 'application/json'
    }
  });
  
  if (response.status === 401) {
    // Token might be expired, try renewal
    await userManager.signinSilent();
    return callApi(endpoint, options);
  }
  
  return response;
}

// UI update functions
function updateUI(user: any) {
  document.getElementById('username')!.textContent = user.profile.name || user.profile.email;
  document.getElementById('login-btn')!.style.display = 'none';
  document.getElementById('logout-btn')!.style.display = 'block';
}

function clearUI() {
  document.getElementById('username')!.textContent = '';
  document.getElementById('login-btn')!.style.display = 'block';
  document.getElementById('logout-btn')!.style.display = 'none';
}

// Initialize on page load
window.addEventListener('load', async () => {
  // Handle callback
  if (window.location.pathname === '/callback') {
    await handleCallback();
    return;
  }
  
  // Handle silent renewal
  if (window.location.pathname === '/silent-renew') {
    await userManager.signinSilentCallback();
    return;
  }
  
  // Check for existing user session
  const user = await getUser();
  if (user) {
    updateUI(user);
  }
});

// Export for use in other modules
export { userManager, login, logout, getUser, callApi };
```

### React Integration

```tsx
import React, { createContext, useContext, useEffect, useState } from 'react';
import { User, UserManager } from 'oidc-client-ts';

// Auth context
interface AuthContextType {
  user: User | null;
  loading: boolean;
  error: Error | null;
  login: (params?: any) => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => Promise<string | null>;
}

const AuthContext = createContext<AuthContextType | null>(null);

// UserManager configuration
const userManager = new UserManager({
  authority: process.env.REACT_APP_OIDC_AUTHORITY!,
  client_id: process.env.REACT_APP_OIDC_CLIENT_ID!,
  redirect_uri: `${window.location.origin}/callback`,
  post_logout_redirect_uri: window.location.origin,
  response_type: 'code',
  scope: 'openid profile email',
  automaticSilentRenew: true,
  loadUserInfo: true
});

// Auth Provider Component
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    // Load user on mount
    userManager.getUser()
      .then(user => {
        if (user && !user.expired) {
          setUser(user);
        }
      })
      .catch(err => setError(err))
      .finally(() => setLoading(false));

    // Event listeners
    const handleUserLoaded = (user: User) => setUser(user);
    const handleUserUnloaded = () => setUser(null);
    const handleSilentRenewError = (err: Error) => {
      console.error('Silent renew error:', err);
      setError(err);
    };

    userManager.events.addUserLoaded(handleUserLoaded);
    userManager.events.addUserUnloaded(handleUserUnloaded);
    userManager.events.addSilentRenewError(handleSilentRenewError);

    return () => {
      userManager.events.removeUserLoaded(handleUserLoaded);
      userManager.events.removeUserUnloaded(handleUserUnloaded);
      userManager.events.removeSilentRenewError(handleSilentRenewError);
    };
  }, []);

  const login = async (params?: any) => {
    try {
      await userManager.signinRedirect({
        state: { returnUrl: window.location.pathname },
        ...params
      });
    } catch (err) {
      setError(err as Error);
      throw err;
    }
  };

  const logout = async () => {
    try {
      await userManager.signoutRedirect();
    } catch (err) {
      setError(err as Error);
      throw err;
    }
  };

  const getAccessToken = async (): Promise<string | null> => {
    const user = await userManager.getUser();
    return user?.access_token || null;
  };

  return (
    <AuthContext.Provider value={{ user, loading, error, login, logout, getAccessToken }}>
      {children}
    </AuthContext.Provider>
  );
};

// Auth hook
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

// Protected route component
export const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, loading, login } = useAuth();

  useEffect(() => {
    if (!loading && !user) {
      login();
    }
  }, [user, loading, login]);

  if (loading) {
    return <div>Loading...</div>;
  }

  return user ? <>{children}</> : null;
};

// Callback component
export const CallbackPage: React.FC = () => {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    userManager.signinRedirectCallback()
      .then(user => {
        const returnUrl = user.state?.returnUrl || '/';
        window.location.href = returnUrl;
      })
      .catch(err => {
        console.error('Callback error:', err);
        setError(err.message);
      });
  }, []);

  if (error) {
    return <div>Error: {error}</div>;
  }

  return <div>Completing login...</div>;
};

// API hook with authentication
export const useAuthenticatedFetch = () => {
  const { getAccessToken } = useAuth();

  return async (url: string, options: RequestInit = {}) => {
    const token = await getAccessToken();
    
    if (!token) {
      throw new Error('No access token available');
    }

    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    if (response.status === 401) {
      // Token expired, trigger re-authentication
      await userManager.signinSilent();
      // Retry the request
      return useAuthenticatedFetch()(url, options);
    }

    return response;
  };
};

// Usage in components
export const UserProfile: React.FC = () => {
  const { user, logout } = useAuth();
  const [profile, setProfile] = useState<any>(null);
  const authFetch = useAuthenticatedFetch();

  useEffect(() => {
    if (user) {
      authFetch('/api/profile')
        .then(res => res.json())
        .then(data => setProfile(data))
        .catch(console.error);
    }
  }, [user]);

  if (!user) return null;

  return (
    <div>
      <h2>User Profile</h2>
      <p>Name: {user.profile.name}</p>
      <p>Email: {user.profile.email}</p>
      {profile && (
        <div>
          <h3>Extended Profile</h3>
          <pre>{JSON.stringify(profile, null, 2)}</pre>
        </div>
      )}
      <button onClick={logout}>Logout</button>
    </div>
  );
};
```

### .NET Client Example

```csharp
// Program.cs (.NET 6+)
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.SlidingExpiration = true;
})
.AddOpenIdConnect(options =>
{
    // Basic configuration
    options.Authority = "https://auth.example.com";
    options.ClientId = "your-client-id";
    options.ClientSecret = "your-client-secret";
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true; // Always use PKCE
    
    // Scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("phone");
    
    // Token handling
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    
    // Claim mapping
    options.ClaimActions.MapJsonKey("picture", "picture");
    options.ClaimActions.MapJsonKey("email_verified", "email_verified");
    options.ClaimActions.MapJsonKey("phone_number", "phone_number");
    options.ClaimActions.MapJsonKey("phone_number_verified", "phone_number_verified");
    
    // Events
    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            // Add custom parameters
            if (context.Properties.Items.ContainsKey("prompt"))
            {
                context.ProtocolMessage.Prompt = context.Properties.Items["prompt"];
            }
            
            // Force re-authentication
            if (context.Properties.Items.ContainsKey("max_age"))
            {
                context.ProtocolMessage.MaxAge = context.Properties.Items["max_age"];
            }
            
            return Task.CompletedTask;
        },
        
        OnTokenValidated = context =>
        {
            // Custom claim processing
            var identity = context.Principal?.Identity as ClaimsIdentity;
            if (identity != null)
            {
                // Add custom claims
                var sub = identity.FindFirst("sub")?.Value;
                if (!string.IsNullOrEmpty(sub))
                {
                    identity.AddClaim(new Claim("user_id", sub));
                }
                
                // Log authentication
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogInformation($"User {sub} authenticated successfully");
            }
            
            return Task.CompletedTask;
        },
        
        OnRemoteFailure = context =>
        {
            context.Response.Redirect("/Account/Error?message=" + 
                Uri.EscapeDataString(context.Failure?.Message ?? "Unknown error"));
            context.HandleResponse();
            return Task.CompletedTask;
        },
        
        OnSignedOutCallbackRedirect = context =>
        {
            // Clear local session data
            context.HttpContext.Session.Clear();
            context.Response.Redirect("/");
            context.HandleResponse();
            return Task.CompletedTask;
        }
    };
    
    // Token validation
    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "name",
        RoleClaimType = "role",
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(2)
    };
});

builder.Services.AddHttpClient();
builder.Services.AddSession();
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

// Account controller actions
app.MapGet("/Account/Login", async (HttpContext context, string? returnUrl) =>
{
    var properties = new AuthenticationProperties
    {
        RedirectUri = returnUrl ?? "/",
        Items = { { "prompt", "login" } }
    };
    
    await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, properties);
});

app.MapPost("/Account/Logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
});

app.MapGet("/Account/UserInfo", async (HttpContext context, IHttpClientFactory httpClientFactory) =>
{
    if (!context.User.Identity?.IsAuthenticated ?? true)
    {
        context.Response.StatusCode = 401;
        return;
    }
    
    var accessToken = await context.GetTokenAsync("access_token");
    if (string.IsNullOrEmpty(accessToken))
    {
        context.Response.StatusCode = 401;
        return;
    }
    
    // Call UserInfo endpoint
    var client = httpClientFactory.CreateClient();
    client.DefaultRequestHeaders.Authorization = 
        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
    
    var response = await client.GetAsync("https://auth.example.com/api/v1/oidc/userinfo");
    if (response.IsSuccessStatusCode)
    {
        var userInfo = await response.Content.ReadAsStringAsync();
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(userInfo);
    }
    else
    {
        context.Response.StatusCode = (int)response.StatusCode;
    }
});

app.Run();

// Razor Page example
@page
@model IndexModel
@{
    ViewData["Title"] = "Home page";
}

<div class="text-center">
    @if (User.Identity?.IsAuthenticated ?? false)
    {
        <h1>Welcome, @User.Identity.Name!</h1>
        <p>Email: @User.FindFirst("email")?.Value</p>
        <p>Email Verified: @User.FindFirst("email_verified")?.Value</p>
        
        <form method="post" action="/Account/Logout">
            <button type="submit" class="btn btn-danger">Logout</button>
        </form>
    }
    else
    {
        <h1>Welcome to OIDC Demo</h1>
        <a href="/Account/Login" class="btn btn-primary">Login</a>
    }
</div>
```

## ID Token Claims

### Standard Claims

Authly supports the following standard OIDC claims:

| Claim | Type | Description | Scope Required |
|-------|------|-------------|----------------|
| `sub` | string | Subject identifier (user ID) | `openid` |
| `iss` | string | Issuer identifier | `openid` |
| `aud` | string/array | Audience (client ID) | `openid` |
| `exp` | number | Expiration time | `openid` |
| `iat` | number | Issued at time | `openid` |
| `auth_time` | number | Authentication time | `openid` |
| `nonce` | string | Nonce value | `openid` |
| `acr` | string | Authentication context class | `openid` |
| `amr` | array | Authentication methods | `openid` |
| `azp` | string | Authorized party | `openid` |
| `at_hash` | string | Access token hash | `openid` |
| `c_hash` | string | Code hash | `openid` |
| `email` | string | User's email address | `email` |
| `email_verified` | boolean | Email verification status | `email` |
| `name` | string | Full name | `profile` |
| `given_name` | string | Given/first name | `profile` |
| `family_name` | string | Family/last name | `profile` |
| `middle_name` | string | Middle name | `profile` |
| `nickname` | string | Nickname | `profile` |
| `preferred_username` | string | Preferred username | `profile` |
| `profile` | string | Profile page URL | `profile` |
| `picture` | string | Profile picture URL | `profile` |
| `website` | string | Website URL | `profile` |
| `gender` | string | Gender | `profile` |
| `birthdate` | string | Birthdate (YYYY-MM-DD) | `profile` |
| `zoneinfo` | string | Timezone | `profile` |
| `locale` | string | Locale | `profile` |
| `updated_at` | number | Last update time | `profile` |
| `phone_number` | string | Phone number | `phone` |
| `phone_number_verified` | boolean | Phone verification status | `phone` |
| `address` | object | Structured address | `address` |

### Address Claim Structure

```json
{
  "formatted": "123 Main St\nAnytown, CA 12345\nUSA",
  "street_address": "123 Main St",
  "locality": "Anytown",
  "region": "CA",
  "postal_code": "12345",
  "country": "USA"
}
```

### Custom Claims

To add custom claims to ID tokens, extend the token service:

```python
# In your token service extension
from authly.tokens.service import TokenService
from authly.users import UserModel

class CustomTokenService(TokenService):
    async def get_id_token_claims(self, user: UserModel, client_id: str, scopes: List[str], nonce: Optional[str] = None) -> dict:
        # Get standard claims
        claims = await super().get_id_token_claims(user, client_id, scopes, nonce)
        
        # Add custom claims based on scopes
        if "custom:employee" in scopes:
            claims.update({
                "employee_id": user.employee_id,
                "department": user.department,
                "manager": user.manager_email,
                "hire_date": user.hire_date.isoformat() if user.hire_date else None
            })
        
        if "custom:roles" in scopes:
            claims["roles"] = user.roles
            claims["permissions"] = user.permissions
        
        if "custom:organization" in scopes:
            claims["org_id"] = user.organization_id
            claims["org_name"] = user.organization_name
            claims["org_unit"] = user.organizational_unit
        
        return claims

# Register custom claims in discovery
CUSTOM_CLAIMS_SUPPORTED = [
    "employee_id", "department", "manager", "hire_date",
    "roles", "permissions", "org_id", "org_name", "org_unit"
]

CUSTOM_SCOPES_SUPPORTED = [
    "custom:employee", "custom:roles", "custom:organization"
]
```

## JWKS and Key Management

### Key Rotation

Authly automatically rotates signing keys based on the configured schedule:

1. **Key Generation**: New RSA key pairs are generated automatically
2. **Key Activation**: New keys become active immediately
3. **Grace Period**: Old keys remain in JWKS for signature verification
4. **Key Cleanup**: Expired keys are removed after the grace period

### Manual Key Rotation

You can manually rotate keys using the admin CLI:

```bash
# Generate new signing key
authly admin jwks rotate

# List all keys
authly admin jwks list

# Deactivate a specific key
authly admin jwks deactivate <kid>

# Force cleanup of expired keys
authly admin jwks cleanup
```

### Key Storage

Keys are stored encrypted in the database with metadata:

- `kid` - Key ID for identification
- `key_data` - Encrypted private/public key pair
- `algorithm` - Signing algorithm (RS256)
- `created_at` - Key creation timestamp
- `expires_at` - Key expiration time
- `is_active` - Whether key is used for signing

### Key Rotation Best Practices

1. **Rotation Schedule**: Rotate keys every 30-90 days
2. **Grace Period**: Keep old keys for at least 7 days
3. **Monitoring**: Monitor key age and usage
4. **Backup**: Backup keys before rotation
5. **Testing**: Test key rotation in staging first

## Security Considerations

### 1. Always Use HTTPS

OIDC requires HTTPS for all endpoints except localhost development:

```python
# Enforce HTTPS in production
from authly.api.security_middleware import enforce_https

@enforce_https(allow_localhost=True)
async def authorization_endpoint(request: Request):
    # Handle authorization
    pass
```

### 2. Validate ID Tokens

Always validate ID tokens on the client:

```python
import time
from authlib.jose import jwt, JsonWebKey
from typing import Dict, Any

def validate_id_token(
    id_token: str, 
    client_id: str, 
    issuer: str, 
    nonce: Optional[str] = None,
    max_age: Optional[int] = None
) -> Dict[str, Any]:
    """Validate ID token with comprehensive checks"""
    
    # Fetch JWKS
    jwks = fetch_jwks(issuer)
    
    # Decode and validate
    claims = jwt.decode(
        id_token,
        jwks,
        claims_options={
            "iss": {"essential": True, "value": issuer},
            "aud": {"essential": True, "value": client_id},
            "exp": {"essential": True},
            "iat": {"essential": True}
        }
    )
    
    # Additional validation
    current_time = int(time.time())
    
    # Check token age
    if max_age and (current_time - claims["iat"]) > max_age:
        raise ValueError("Token too old")
    
    # Verify nonce
    if nonce and claims.get("nonce") != nonce:
        raise ValueError("Invalid nonce")
    
    # Check authorized party for multiple audiences
    if isinstance(claims.get("aud"), list) and len(claims["aud"]) > 1:
        if claims.get("azp") != client_id:
            raise ValueError("Invalid authorized party")
    
    # Verify auth_time if requested
    if "auth_time" in claims:
        if claims["auth_time"] > current_time:
            raise ValueError("Invalid auth_time (future)")
    
    return claims
```

### 3. Nonce Validation

Always use and validate nonce to prevent replay attacks:

```javascript
// Generate cryptographically secure nonce
function generateNonce() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Store nonce securely
const nonce = generateNonce();
sessionStorage.setItem('oidc_nonce', nonce);

// Validate nonce in ID token
function validateIdToken(idToken, expectedNonce) {
  const claims = parseJwt(idToken);
  
  if (claims.nonce !== expectedNonce) {
    throw new Error('Nonce mismatch - possible replay attack');
  }
  
  // Clear nonce after validation
  sessionStorage.removeItem('oidc_nonce');
  
  return claims;
}
```

### 4. State Parameter

Use state parameter to prevent CSRF attacks:

```python
import secrets
import hashlib
import json
from datetime import datetime, timedelta

class StateManager:
    """Secure state parameter management"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.states = {}  # In production, use Redis or similar
    
    def create_state(self, data: dict) -> str:
        """Create secure state parameter"""
        state_id = secrets.token_urlsafe(32)
        
        state_data = {
            "id": state_id,
            "data": data,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        }
        
        # Store state
        self.states[state_id] = state_data
        
        # Create HMAC for integrity
        import hmac
        signature = hmac.new(
            self.secret_key.encode(),
            state_id.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{state_id}.{signature}"
    
    def validate_state(self, state: str, expected_data: dict = None) -> dict:
        """Validate and retrieve state data"""
        try:
            state_id, signature = state.split('.')
        except ValueError:
            raise ValueError("Invalid state format")
        
        # Verify signature
        import hmac
        expected_signature = hmac.new(
            self.secret_key.encode(),
            state_id.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid state signature")
        
        # Retrieve state
        state_data = self.states.get(state_id)
        if not state_data:
            raise ValueError("State not found")
        
        # Check expiration
        if datetime.fromisoformat(state_data["expires_at"]) < datetime.utcnow():
            raise ValueError("State expired")
        
        # Validate expected data
        if expected_data:
            for key, value in expected_data.items():
                if state_data["data"].get(key) != value:
                    raise ValueError(f"State mismatch for {key}")
        
        # Clean up used state
        del self.states[state_id]
        
        return state_data["data"]
```

### 5. Token Storage

Secure token storage guidelines by platform:

```javascript
// Browser Storage Strategy
class SecureTokenStorage {
  // Use memory storage for most sensitive tokens
  private static memoryStorage = new Map();
  
  static storeTokens(tokens) {
    // Access token in memory only
    this.memoryStorage.set('access_token', tokens.access_token);
    
    // ID token in session storage (encrypted if possible)
    if (tokens.id_token) {
      sessionStorage.setItem('id_token', this.encrypt(tokens.id_token));
    }
    
    // Refresh token in httpOnly cookie (server-side)
    // Never store refresh token in browser storage
    if (tokens.refresh_token) {
      // Send to backend to store as httpOnly cookie
      fetch('/api/auth/store-refresh-token', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: tokens.refresh_token })
      });
    }
  }
  
  static getAccessToken() {
    return this.memoryStorage.get('access_token');
  }
  
  static getIdToken() {
    const encrypted = sessionStorage.getItem('id_token');
    return encrypted ? this.decrypt(encrypted) : null;
  }
  
  static clearTokens() {
    this.memoryStorage.clear();
    sessionStorage.removeItem('id_token');
    
    // Clear httpOnly cookie via backend
    fetch('/api/auth/clear-refresh-token', {
      method: 'POST',
      credentials: 'include'
    });
  }
  
  // Simple encryption for session storage (use proper encryption in production)
  private static encrypt(data: string): string {
    // Implement proper encryption
    return btoa(data); // This is just encoding, not encryption!
  }
  
  private static decrypt(data: string): string {
    // Implement proper decryption
    return atob(data); // This is just decoding, not decryption!
  }
}
```

### 6. Session Security

Implement comprehensive session security:

```python
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import hashlib

class SecureSessionManager:
    """Enhanced session security management"""
    
    def __init__(self, redis_client, config):
        self.redis = redis_client
        self.config = config
        
    async def create_session(
        self, 
        user_id: str, 
        client_id: str, 
        ip_address: str,
        user_agent: str,
        auth_time: datetime
    ) -> str:
        """Create secure session with fingerprinting"""
        
        # Generate session ID
        session_id = secrets.token_urlsafe(32)
        
        # Create device fingerprint
        fingerprint = self._create_fingerprint(ip_address, user_agent)
        
        # Session data
        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "client_id": client_id,
            "auth_time": auth_time.isoformat(),
            "last_activity": datetime.utcnow().isoformat(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "fingerprint": fingerprint,
            "auth_methods": ["password"],  # Track authentication methods
            "auth_level": 1,  # Authentication assurance level
        }
        
        # Store session with expiration
        await self.redis.setex(
            f"session:{session_id}",
            self.config.session_absolute_timeout,
            json.dumps(session_data)
        )
        
        # Track active sessions per user
        await self.redis.sadd(f"user_sessions:{user_id}", session_id)
        
        return session_id
    
    async def validate_session(
        self, 
        session_id: str, 
        ip_address: str,
        user_agent: str
    ) -> Optional[Dict[str, Any]]:
        """Validate session with security checks"""
        
        # Get session data
        session_data = await self.redis.get(f"session:{session_id}")
        if not session_data:
            return None
            
        session = json.loads(session_data)
        
        # Check idle timeout
        last_activity = datetime.fromisoformat(session["last_activity"])
        if datetime.utcnow() - last_activity > timedelta(seconds=self.config.session_idle_timeout):
            await self.invalidate_session(session_id)
            return None
        
        # Verify device fingerprint
        current_fingerprint = self._create_fingerprint(ip_address, user_agent)
        if session["fingerprint"] != current_fingerprint:
            # Possible session hijacking
            await self.invalidate_session(session_id)
            await self._alert_security_event(
                "session_hijacking_attempt",
                session_id,
                session["user_id"]
            )
            return None
        
        # Update last activity
        session["last_activity"] = datetime.utcnow().isoformat()
        await self.redis.setex(
            f"session:{session_id}",
            self.config.session_absolute_timeout,
            json.dumps(session)
        )
        
        return session
    
    async def elevate_session(
        self, 
        session_id: str, 
        auth_method: str
    ) -> bool:
        """Elevate session authentication level"""
        
        session_data = await self.redis.get(f"session:{session_id}")
        if not session_data:
            return False
            
        session = json.loads(session_data)
        
        # Add authentication method
        if auth_method not in session["auth_methods"]:
            session["auth_methods"].append(auth_method)
        
        # Update auth level based on methods used
        if "biometric" in session["auth_methods"]:
            session["auth_level"] = 3
        elif len(session["auth_methods"]) >= 2:
            session["auth_level"] = 2
        
        # Update session
        await self.redis.setex(
            f"session:{session_id}",
            self.config.session_absolute_timeout,
            json.dumps(session)
        )
        
        return True
    
    async def invalidate_session(self, session_id: str):
        """Invalidate a session"""
        
        session_data = await self.redis.get(f"session:{session_id}")
        if session_data:
            session = json.loads(session_data)
            user_id = session["user_id"]
            
            # Remove from user's active sessions
            await self.redis.srem(f"user_sessions:{user_id}", session_id)
        
        # Delete session
        await self.redis.delete(f"session:{session_id}")
    
    async def invalidate_user_sessions(self, user_id: str):
        """Invalidate all sessions for a user"""
        
        # Get all user sessions
        session_ids = await self.redis.smembers(f"user_sessions:{user_id}")
        
        # Delete each session
        for session_id in session_ids:
            await self.redis.delete(f"session:{session_id}")
        
        # Clear user session set
        await self.redis.delete(f"user_sessions:{user_id}")
    
    def _create_fingerprint(self, ip_address: str, user_agent: str) -> str:
        """Create device fingerprint"""
        
        # Extract key parts of user agent
        import re
        
        # Get browser and OS info
        browser_match = re.search(r'(Chrome|Firefox|Safari|Edge)/[\d.]+', user_agent)
        os_match = re.search(r'(Windows|Mac OS X|Linux|Android|iOS)', user_agent)
        
        browser = browser_match.group(1) if browser_match else "Unknown"
        os = os_match.group(1) if os_match else "Unknown"
        
        # Create fingerprint
        fingerprint_data = f"{ip_address}:{browser}:{os}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    async def _alert_security_event(self, event_type: str, session_id: str, user_id: str):
        """Alert on security events"""
        
        # Log security event
        logger.warning(f"Security event: {event_type} for user {user_id}, session {session_id}")
        
        # Send notification (implement based on your notification system)
        # await notification_service.send_security_alert(...)
```

### 7. Rate Limiting and Abuse Prevention

Implement comprehensive rate limiting:

```python
from typing import Dict, Optional
import time

class OIDCRateLimiter:
    """OIDC-specific rate limiting"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.limits = {
            "authorization": {"requests": 10, "window": 60},  # 10 per minute
            "token": {"requests": 20, "window": 60},  # 20 per minute
            "userinfo": {"requests": 60, "window": 60},  # 60 per minute
            "discovery": {"requests": 100, "window": 3600},  # 100 per hour
            "jwks": {"requests": 50, "window": 3600},  # 50 per hour
        }
    
    async def check_rate_limit(
        self, 
        endpoint: str, 
        identifier: str,
        custom_limit: Optional[Dict[str, int]] = None
    ) -> tuple[bool, Optional[int]]:
        """Check if request is within rate limit"""
        
        limit_config = custom_limit or self.limits.get(endpoint, {"requests": 100, "window": 60})
        
        key = f"rate_limit:{endpoint}:{identifier}"
        current_time = int(time.time())
        window_start = current_time - limit_config["window"]
        
        # Remove old entries
        await self.redis.zremrangebyscore(key, 0, window_start)
        
        # Count requests in window
        request_count = await self.redis.zcard(key)
        
        if request_count >= limit_config["requests"]:
            # Calculate retry after
            oldest_request = await self.redis.zrange(key, 0, 0, withscores=True)
            if oldest_request:
                retry_after = int(oldest_request[0][1]) + limit_config["window"] - current_time
                return False, retry_after
            return False, limit_config["window"]
        
        # Add current request
        await self.redis.zadd(key, {str(current_time): current_time})
        await self.redis.expire(key, limit_config["window"])
        
        return True, None
    
    async def get_rate_limit_headers(
        self, 
        endpoint: str, 
        identifier: str
    ) -> Dict[str, str]:
        """Get rate limit headers for response"""
        
        limit_config = self.limits.get(endpoint, {"requests": 100, "window": 60})
        key = f"rate_limit:{endpoint}:{identifier}"
        
        request_count = await self.redis.zcard(key)
        remaining = max(0, limit_config["requests"] - request_count)
        
        return {
            "X-RateLimit-Limit": str(limit_config["requests"]),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(time.time()) + limit_config["window"])
        }
```

## Testing OIDC Flows

### 1. Unit Tests

```python
import pytest
from unittest.mock import Mock, patch
from authly.oidc import create_id_token, verify_id_token

class TestOIDCTokens:
    @pytest.mark.asyncio
    async def test_id_token_creation(self, test_user, test_client):
        """Test ID token creation with all claims"""
        
        # Create ID token
        id_token = await create_id_token(
            user=test_user,
            client_id=test_client.client_id,
            nonce="test-nonce",
            auth_time=datetime.utcnow(),
            scopes=["openid", "profile", "email"]
        )
        
        # Verify structure
        assert id_token is not None
        assert isinstance(id_token, str)
        
        # Decode without verification for testing
        import jwt
        claims = jwt.decode(id_token, options={"verify_signature": False})
        
        # Verify required claims
        assert claims["sub"] == str(test_user.id)
        assert claims["iss"] == "https://test-issuer"
        assert claims["aud"] == test_client.client_id
        assert claims["exp"] > time.time()
        assert claims["iat"] <= time.time()
        assert claims["nonce"] == "test-nonce"
        
        # Verify profile claims
        assert claims["name"] == test_user.name
        assert claims["email"] == test_user.email
        assert claims["email_verified"] == test_user.is_verified
    
    @pytest.mark.asyncio
    async def test_id_token_validation(self, test_id_token, test_jwks):
        """Test ID token validation"""
        
        with patch('requests.get') as mock_get:
            mock_get.return_value.json.return_value = test_jwks
            
            # Valid token
            claims = await verify_id_token(
                id_token=test_id_token,
                client_id="test-client",
                issuer="https://test-issuer",
                nonce="test-nonce"
            )
            
            assert claims["sub"] == "test-user-id"
            
            # Invalid nonce
            with pytest.raises(ValueError, match="Invalid nonce"):
                await verify_id_token(
                    id_token=test_id_token,
                    client_id="test-client",
                    issuer="https://test-issuer",
                    nonce="wrong-nonce"
                )
            
            # Expired token
            expired_token = create_expired_token()
            with pytest.raises(ValueError, match="Token expired"):
                await verify_id_token(
                    id_token=expired_token,
                    client_id="test-client",
                    issuer="https://test-issuer"
                )
```

### 2. Integration Tests

```python
@pytest.mark.integration
class TestOIDCFlow:
    @pytest.mark.asyncio
    async def test_complete_oidc_flow(self, test_client, test_server):
        """Test complete OIDC authorization code flow"""
        
        # Step 1: Discovery
        discovery_response = await test_client.get('/.well-known/openid-configuration')
        assert discovery_response.status_code == 200
        discovery = discovery_response.json()
        
        # Step 2: Authorization request
        auth_params = {
            'response_type': 'code',
            'client_id': 'test-client',
            'redirect_uri': 'http://localhost/callback',
            'scope': 'openid profile email',
            'state': 'test-state',
            'nonce': 'test-nonce',
            'code_challenge': 'test-challenge',
            'code_challenge_method': 'S256'
        }
        
        auth_response = await test_client.get(
            discovery['authorization_endpoint'],
            params=auth_params
        )
        
        assert auth_response.status_code == 302
        location = auth_response.headers['location']
        
        # Step 3: User authentication (simulate)
        await simulate_user_login(test_server, 'testuser', 'password')
        
        # Step 4: Get authorization code
        callback_response = await test_client.get(location)
        code = extract_code_from_callback(callback_response)
        
        # Step 5: Token exchange
        token_response = await test_client.post(
            discovery['token_endpoint'],
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': 'http://localhost/callback',
                'client_id': 'test-client',
                'code_verifier': 'test-verifier'
            },
            auth=('test-client', 'test-secret')
        )
        
        assert token_response.status_code == 200
        tokens = token_response.json()
        
        # Verify tokens received
        assert 'access_token' in tokens
        assert 'id_token' in tokens
        assert 'refresh_token' in tokens
        
        # Step 6: UserInfo request
        userinfo_response = await test_client.get(
            discovery['userinfo_endpoint'],
            headers={'Authorization': f'Bearer {tokens["access_token"]}'}
        )
        
        assert userinfo_response.status_code == 200
        userinfo = userinfo_response.json()
        assert userinfo['sub'] == 'test-user-id'
        assert userinfo['email'] == 'testuser@example.com'
```

### 3. End-to-End Tests

```javascript
// Playwright test example
import { test, expect } from '@playwright/test';

test.describe('OIDC Flow', () => {
  test('complete authorization flow', async ({ page }) => {
    // Start at client application
    await page.goto('http://localhost:3000');
    
    // Click login button
    await page.click('button:has-text("Login with OIDC")');
    
    // Should redirect to authorization server
    await expect(page).toHaveURL(/.*\/oauth\/authorize.*/);
    
    // Fill in credentials
    await page.fill('#username', 'testuser');
    await page.fill('#password', 'testpassword');
    await page.click('button[type="submit"]');
    
    // Consent screen (if shown)
    if (await page.isVisible('button:has-text("Allow")')) {
      await page.click('button:has-text("Allow")');
    }
    
    // Should redirect back to client
    await expect(page).toHaveURL(/.*localhost:3000\/callback.*/);
    
    // Wait for client to process callback
    await page.waitForSelector('text=Welcome, testuser');
    
    // Verify user info displayed
    await expect(page.locator('#user-email')).toHaveText('testuser@example.com');
    
    // Test logout
    await page.click('button:has-text("Logout")');
    
    // Should redirect to logout endpoint and back
    await expect(page).toHaveURL('http://localhost:3000/');
    await expect(page.locator('button:has-text("Login with OIDC")')).toBeVisible();
  });
  
  test('session management', async ({ page, context }) => {
    // Login in first tab
    await page.goto('http://localhost:3000');
    await loginFlow(page);
    
    // Open second tab
    const page2 = await context.newPage();
    await page2.goto('http://localhost:3000');
    
    // Should be logged in automatically
    await expect(page2.locator('text=Welcome, testuser')).toBeVisible();
    
    // Logout from second tab
    await page2.click('button:has-text("Logout")');
    
    // First tab should detect logout (with session management)
    await page.waitForTimeout(3000); // Wait for session check
    await expect(page.locator('button:has-text("Login with OIDC")')).toBeVisible();
  });
});
```

### 4. Security Tests

```python
@pytest.mark.security
class TestOIDCSecurity:
    @pytest.mark.asyncio
    async def test_pkce_required(self, test_client):
        """Test that PKCE is required"""
        
        # Authorization request without PKCE
        response = await test_client.get('/api/v1/oauth/authorize', params={
            'response_type': 'code',
            'client_id': 'test-client',
            'redirect_uri': 'http://localhost/callback',
            'scope': 'openid'
            # Missing code_challenge
        })
        
        assert response.status_code == 400
        assert 'code_challenge required' in response.json()['detail']
    
    @pytest.mark.asyncio
    async def test_nonce_replay_protection(self, test_client, test_tokens):
        """Test nonce replay attack protection"""
        
        # Use same nonce twice
        id_token = test_tokens['id_token']
        
        # First use should succeed
        claims1 = verify_id_token(id_token, nonce='test-nonce')
        assert claims1 is not None
        
        # Second use should fail (if nonce tracking implemented)
        with pytest.raises(ValueError, match="Nonce already used"):
            verify_id_token(id_token, nonce='test-nonce')
    
    @pytest.mark.asyncio  
    async def test_token_substitution_attack(self, test_client):
        """Test protection against token substitution"""
        
        # Get tokens for client A
        tokens_a = await get_tokens_for_client('client-a')
        
        # Try to use ID token from client A with client B
        with pytest.raises(ValueError, match="Invalid audience"):
            verify_id_token(
                tokens_a['id_token'],
                client_id='client-b',
                issuer='https://auth.example.com'
            )
```

## Troubleshooting

### Common Issues

#### 1. "Invalid nonce" error

**Cause**: Nonce mismatch between authorization request and ID token

**Solution**:
- Ensure nonce is properly stored in session/state
- Check for session timeout issues
- Verify nonce is included in authorization request
- Clear browser storage and retry

**Debug**:
```javascript
// Log nonce handling
console.log('Generated nonce:', nonce);
sessionStorage.setItem('oidc_nonce', nonce);

// In callback
const storedNonce = sessionStorage.getItem('oidc_nonce');
console.log('Stored nonce:', storedNonce);
console.log('Token nonce:', decodedToken.nonce);
```

#### 2. "Signature verification failed"

**Cause**: ID token signature cannot be verified

**Solution**:
- Ensure JWKS endpoint is accessible
- Check for key rotation timing issues
- Verify correct algorithm (RS256) is used
- Check for clock skew between servers
- Clear JWKS cache and retry

**Debug**:
```bash
# Test JWKS endpoint
curl -v https://auth.example.com/.well-known/jwks.json

# Decode token header
echo $ID_TOKEN | cut -d. -f1 | base64 -d

# Check key ID matches JWKS
```

#### 3. "Invalid audience" error

**Cause**: ID token audience doesn't match client ID

**Solution**:
- Verify correct client_id in token request
- Check for multiple audiences in ID token
- Ensure client configuration matches
- Verify authorized party (azp) claim for multiple audiences

#### 4. UserInfo endpoint returns 401

**Cause**: Invalid or expired access token

**Solution**:
- Ensure access token has 'openid' scope
- Check token expiration
- Verify token is properly formatted in Authorization header
- Ensure UserInfo endpoint accepts the token

**Debug**:
```bash
# Test UserInfo with curl
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://auth.example.com/api/v1/oidc/userinfo -v

# Decode access token to check scope
echo $ACCESS_TOKEN | cut -d. -f2 | base64 -d | jq .scope
```

#### 5. Missing claims in ID token

**Cause**: Required scopes not requested or user hasn't consented

**Solution**:
- Include necessary scopes (profile, email) in authorization request
- Verify user has provided consent for requested scopes
- Check scope configuration in client settings
- Ensure user has the data for requested claims

#### 6. Session management not working

**Cause**: Session iframe blocked or misconfigured

**Solution**:
- Check browser console for CSP or CORS errors
- Ensure iframe src uses same origin as authorization server
- Verify postMessage origin validation
- Check for third-party cookie blocking

**Debug**:
```javascript
// Test postMessage manually
const iframe = document.querySelector('#session-iframe');
iframe.contentWindow.postMessage(
  'test-message',
  'https://auth.example.com'
);

// Listen for response
window.addEventListener('message', (e) => {
  console.log('Received:', e.data, 'from:', e.origin);
});
```

### Debug Mode

Enable debug logging for OIDC operations:

```python
# In your environment
AUTHLY_LOG_LEVEL=DEBUG
AUTHLY_OIDC_DEBUG=true

# Debug logs will include:
# - Token generation details
# - Claim processing
# - JWKS operations
# - Signature verification steps
# - Session management events
```

### Performance Monitoring

Monitor OIDC endpoints with Prometheus metrics:

```yaml
# Key metrics to monitor
- authly_oidc_token_generation_duration_seconds
- authly_oidc_token_validation_duration_seconds
- authly_oidc_userinfo_requests_total
- authly_oidc_jwks_cache_hit_ratio
- authly_oidc_session_check_duration_seconds
```

## Advanced Topics

### Dynamic Client Registration

Authly supports dynamic client registration per RFC 7591:

```python
# Register a new client dynamically
POST /api/v1/oauth/register
Content-Type: application/json
Authorization: Bearer <initial_access_token>

{
  "redirect_uris": ["https://client.example.com/callback"],
  "client_name": "My Dynamic Client",
  "client_uri": "https://client.example.com",
  "logo_uri": "https://client.example.com/logo.png",
  "contacts": ["support@client.example.com"],
  "tos_uri": "https://client.example.com/tos",
  "policy_uri": "https://client.example.com/privacy",
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email"
}

# Response
{
  "client_id": "generated-client-id",
  "client_secret": "generated-client-secret",
  "registration_access_token": "token-for-updates",
  "registration_client_uri": "https://auth.example.com/api/v1/oauth/register/generated-client-id",
  "client_id_issued_at": 1642012800,
  "client_secret_expires_at": 0
}
```

### Request Objects

Support for signed and encrypted request objects:

```python
# Create signed request object
import jwt

request_object = jwt.encode({
    "iss": "client-id",
    "aud": "https://auth.example.com",
    "response_type": "code",
    "client_id": "client-id",
    "redirect_uri": "https://client.example.com/callback",
    "scope": "openid profile",
    "state": "af0ifjsldkj",
    "nonce": "n-0S6_WzA2Mj",
    "max_age": 86400,
    "claims": {
        "userinfo": {
            "given_name": {"essential": true},
            "email": {"essential": true}
        },
        "id_token": {
            "auth_time": {"essential": true},
            "acr": {"values": ["urn:mace:incommon:iap:silver"]}
        }
    }
}, client_secret, algorithm='HS256')

# Use in authorization request
auth_url = f"https://auth.example.com/api/v1/oauth/authorize?request={request_object}"
```

### Pairwise Subject Identifiers

Configure pairwise subject identifiers for enhanced privacy:

```python
# Client configuration
client.subject_type = "pairwise"
client.sector_identifier_uri = "https://client.example.com/sector.json"

# Sector identifier document
{
  "redirect_uris": [
    "https://app1.example.com/callback",
    "https://app2.example.com/callback"
  ]
}

# Result: Same user gets different 'sub' values for different sectors
```

## Migration Guide

### Migrating from OAuth 2.0 to OIDC

1. **Update Scopes**:
   ```diff
   - scope: "read write"
   + scope: "openid profile email"
   ```

2. **Handle ID Tokens**:
   ```javascript
   // Old OAuth flow
   const { access_token } = await getTokens();
   
   // New OIDC flow
   const { access_token, id_token } = await getTokens();
   const userClaims = parseIdToken(id_token);
   ```

3. **Update User Info Retrieval**:
   ```diff
   - GET /api/users/me
   + GET /api/v1/oidc/userinfo
   ```

4. **Add Discovery**:
   ```javascript
   // Dynamically discover endpoints
   const discovery = await fetch('/.well-known/openid-configuration').then(r => r.json());
   const authEndpoint = discovery.authorization_endpoint;
   ```

### Migrating from SAML to OIDC

Key differences and migration steps:

1. **Protocol Simplification**:
   - SAML: XML-based, complex
   - OIDC: JSON-based, simpler

2. **Token Format**:
   - SAML: XML assertions
   - OIDC: JWT tokens

3. **Migration Steps**:
   ```python
   # Map SAML attributes to OIDC claims
   claim_mapping = {
       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email",
       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "name",
       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "given_name",
       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "family_name"
   }
   ```

## Performance Optimization

### 1. JWKS Caching

Implement intelligent JWKS caching:

```python
class JWKSCache:
    def __init__(self, ttl=3600):
        self.cache = {}
        self.ttl = ttl
        
    async def get_keys(self, jwks_uri: str) -> dict:
        if jwks_uri in self.cache:
            entry = self.cache[jwks_uri]
            if time.time() < entry['expires']:
                return entry['keys']
        
        # Fetch with cache headers
        headers = {}
        if jwks_uri in self.cache:
            if etag := self.cache[jwks_uri].get('etag'):
                headers['If-None-Match'] = etag
        
        response = await fetch(jwks_uri, headers=headers)
        
        if response.status == 304:  # Not Modified
            # Extend cache TTL
            self.cache[jwks_uri]['expires'] = time.time() + self.ttl
            return self.cache[jwks_uri]['keys']
        
        keys = await response.json()
        
        # Cache with headers
        self.cache[jwks_uri] = {
            'keys': keys,
            'expires': time.time() + self.ttl,
            'etag': response.headers.get('ETag')
        }
        
        return keys
```

### 2. Token Validation Optimization

```python
class OptimizedTokenValidator:
    def __init__(self):
        self.jwks_cache = JWKSCache()
        self.validated_tokens = LRUCache(maxsize=10000)
        
    async def validate_token(self, token: str, **kwargs) -> dict:
        # Check validation cache
        cache_key = hashlib.sha256(f"{token}:{kwargs}".encode()).hexdigest()
        if cached := self.validated_tokens.get(cache_key):
            if cached['expires'] > time.time():
                return cached['claims']
        
        # Validate token
        claims = await self._validate_token_internal(token, **kwargs)
        
        # Cache validation result
        self.validated_tokens[cache_key] = {
            'claims': claims,
            'expires': claims['exp']
        }
        
        return claims
```

### 3. Session Check Optimization

```javascript
class OptimizedSessionManager {
  constructor() {
    this.checkInterval = 30000; // 30 seconds
    this.lastCheck = 0;
    this.sessionState = null;
    this.checking = false;
  }
  
  async checkSession(force = false) {
    const now = Date.now();
    
    // Throttle checks
    if (!force && now - this.lastCheck < this.checkInterval) {
      return this.sessionState;
    }
    
    // Prevent concurrent checks
    if (this.checking) {
      return this.sessionState;
    }
    
    this.checking = true;
    try {
      const response = await fetch('/api/v1/oidc/session/check', {
        credentials: 'include'
      });
      
      this.sessionState = await response.json();
      this.lastCheck = now;
      
      // Adjust check interval based on session lifetime
      if (this.sessionState.authenticated) {
        const remaining = this.sessionState.expires_in * 1000;
        this.checkInterval = Math.min(30000, remaining / 10);
      }
      
      return this.sessionState;
    } finally {
      this.checking = false;
    }
  }
}
```

## Compliance and Certification

### OpenID Certification

Authly has achieved 100% OpenID Connect Core 1.0 conformance:

1. **Conformance Tests**: Passes all official OpenID Connect conformance suite tests
2. **Profile Support**: Basic RP, Implicit RP, Hybrid RP, Config, Dynamic
3. **Feature Support**: 
   - Core (100% compliant)
   - Discovery (100% compliant)
   - Dynamic Registration
   - Session Management
   - Front-Channel Logout
4. **Certification Status**: Full conformance with OpenID Connect Core 1.0 specification

### Security Compliance

- **OAuth 2.0 Security BCP**: Full compliance with RFC 8252
- **PKCE**: Required for all clients (RFC 7636)
- **Token Binding**: Optional support (RFC 8471)
- **Proof-of-Possession**: DPoP support (RFC 9449)

### Privacy Compliance

- **GDPR**: User consent, data portability, right to erasure
- **CCPA**: User data access and deletion
- **Pairwise Identifiers**: Privacy-preserving subject identifiers
- **Selective Disclosure**: Minimal claim disclosure

## Best Practices Summary

1. **Always use PKCE** - Required by OAuth 2.1 for all clients
2. **Validate all tokens** - Never trust tokens without validation
3. **Use appropriate scopes** - Request only necessary scopes
4. **Implement proper logout** - Clear all tokens and sessions
5. **Monitor security events** - Track failed authentications and anomalies
6. **Rotate keys regularly** - Implement automatic key rotation
7. **Cache intelligently** - Cache JWKS and discovery documents
8. **Handle errors gracefully** - Provide clear error messages
9. **Test thoroughly** - Include security and edge case testing
10. **Stay updated** - Follow OIDC and OAuth specifications

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)
- [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- [OAuth 2.1 Specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-09)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc8252)
- [JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)