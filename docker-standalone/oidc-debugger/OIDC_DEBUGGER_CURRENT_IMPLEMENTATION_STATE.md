# OIDC Debugger Current Implementation State

## Overview
This document describes the current state of the OAuth2/OIDC testing tools implementation for Authly as of August 2025.

## Implementation History

### Initial Attempt: oauth2-oidc-debugger
We initially attempted to integrate the popular [oauth2-oidc-debugger](https://github.com/rcbj/oauth2-oidc-debugger) project.

**Issues Encountered:**
- **State management broken**: State mismatches between requests ("state=X, storedState=Y")
- **Complex architecture**: Required Node.js API server + client server (950MB image)
- **Poor UI/UX**: Hidden sections, confusing interface, non-intuitive workflow
- **Incompatible with Authly**: Couldn't handle Authly's API-only architecture properly

**Decision**: Abandoned due to fundamental incompatibilities and poor user experience.

### Current Solution: Custom OAuth Tester
Created a lightweight, purpose-built OAuth/OIDC tester specifically for Authly.

**Location**: `/docker-standalone/oauth-tester/`

**Architecture**:
- Single HTML file with embedded JavaScript
- Nginx container for serving (40MB vs 950MB)
- Nginx reverse proxy to handle CORS issues
- No external dependencies

## Current State

### What Works ✅

#### 1. Resource Owner Password Grant
- **Status**: Fully functional
- **Usage**: Select from dropdown, enter credentials, get tokens
- **Default credentials**: admin / ci_admin_test_password

#### 2. Token Display and Decoding
- Shows access tokens, refresh tokens, ID tokens
- Automatically decodes JWT tokens
- Displays token metadata (expiry, scopes, etc.)

#### 3. Token Operations
- **UserInfo endpoint**: Fetches user profile with access token
- **Token introspection**: Validates and inspects tokens
- **Refresh flow**: Exchange refresh tokens for new access tokens

#### 4. CORS Handling
- Nginx proxy endpoints avoid browser CORS blocks:
  - `/proxy/token` → `http://authly-standalone:8000/api/v1/oauth/token`
  - `/proxy/userinfo` → `http://authly-standalone:8000/api/v1/userinfo`
  - `/proxy/introspect` → `http://authly-standalone:8000/api/v1/oauth/introspect`

### What Doesn't Work ❌

#### 1. Authorization Code Flow
- **Issue**: Returns `error=login_required`
- **Root Cause**: Authly has no login UI
- **Details**: 
  - Authly has consent page templates (`/src/authly/templates/oauth/authorize.html`)
  - But no login page to authenticate users
  - Authorization endpoint expects Bearer token in header (browsers can't send this)

#### 2. Implicit Flow
- Same issue as Authorization Code flow
- Deprecated anyway per OAuth 2.1

#### 3. Client Credentials Flow
- Requires confidential client with secret
- Not implemented in tester UI yet

## Authly's OAuth Implementation Status

### What Authly Has
```
✅ OAuth 2.0 token endpoint (/api/v1/oauth/token)
✅ Authorization endpoint (/api/v1/oauth/authorize)
✅ Token introspection (RFC 7662)
✅ PKCE support (required for public clients)
✅ OpenID Connect discovery
✅ UserInfo endpoint
✅ Consent page template (authorize.html)
✅ Comprehensive scope system
```

### What Authly Lacks
```
❌ Login page/UI
❌ Session management (cookies)
❌ User registration UI
❌ Password reset UI
❌ Account management UI
❌ Way to authenticate for browser-based flows
```

## Network Architecture

### Docker Networking
- **Internal DNS**: Container-to-container uses `authly-standalone`
- **External Access**: Browser-to-container uses `localhost`
- **Port Mapping**:
  - Authly API: 8000
  - OAuth Tester: 8085
  - ~~OIDC Debugger: 8083-8084~~ (removed)

### Service Communication
```
Browser → localhost:8085 → OAuth Tester (nginx)
                              ↓ (proxy)
                        authly-standalone:8000
```

## File Structure

### Removed/Deprecated
```
docker-standalone/oidc-debugger/
├── Dockerfile (deprecated - was for oauth2-oidc-debugger)
├── authly-config.js (deprecated)
├── authly-defaults.patch (deprecated)
├── start.sh (deprecated)
└── Various test scripts (deprecated)
```

### Current Implementation
```
docker-standalone/oauth-tester/
├── Dockerfile (nginx:alpine based)
├── index.html (complete OAuth tester application)
├── nginx.conf (with proxy configuration)
└── README.md (documentation)
```

## Docker Compose Configuration

### Previous (Removed)
```yaml
oidc-debugger:
  build: ./docker-standalone/oidc-debugger
  ports:
    - "8083:3000"
    - "8084:4000"
```

### Current
```yaml
oauth-tester:
  build: ./docker-standalone/oauth-tester
  ports:
    - "8085:80"
  profiles:
    - tools
```

## Known Limitations

### 1. Authorization Code Flow Unusable
**Impact**: Cannot test the most common OAuth flow
**Workaround**: Use Password Grant for testing
**Proper Fix Would Require**:
- Implement login page in Authly
- Add session/cookie management
- Modify authorize endpoint to check sessions
- Create login redirect flow

### 2. No Browser-Based Authentication
**Impact**: Can't test real-world OAuth scenarios
**Workaround**: API-based flows only
**Root Cause**: Authly is API-only by design

### 3. CORS Complications
**Impact**: Direct browser-to-Authly calls blocked
**Workaround**: Nginx proxy endpoints
**Note**: This is standard browser security, not a bug

## Testing Instructions

### Working Flow (Password Grant)
```bash
1. Navigate to http://localhost:8085
2. Select "Resource Owner Password" from dropdown
3. Enter credentials:
   - Username: admin
   - Password: ci_admin_test_password
4. Click "Get Tokens"
5. View tokens in results section
```

### Non-Working Flow (Authorization Code)
```bash
1. Select "Authorization Code" - will show warning
2. Click "Start Authorization"
3. Redirected back with error=login_required
4. This is EXPECTED - Authly has no login UI
```

## Future Improvements

### Option 1: Add Login UI to Authly
- Create `/login` endpoint with form
- Implement session management
- Store sessions in Redis/database
- Modify authorize endpoint to check sessions

### Option 2: External Authentication Service
- Use separate service for authentication
- Issue tokens that Authly accepts
- More complex but maintains Authly as API-only

### Option 3: Development-Only Login UI
- Add simple login page for development/testing
- Not for production use
- Enables testing of authorization code flow

## Recommendations

### For Testing OAuth Flows
1. **Use Password Grant** - It works perfectly
2. **Use the custom OAuth tester** at http://localhost:8085
3. **Avoid the authorization code flow** - It won't work without login UI

### For Production
1. **Build your own login UI** if you need browser flows
2. **Use API-based flows** (password, client credentials)
3. **Consider a separate authentication service**

## Test Clients Created

### OAuth Tester Client
```
Client ID: client_mgjOYWRSXsb1PIGxicSooQ
Type: public
Redirect URI: http://localhost:8085/callback
Scopes: openid profile email
```

### Legacy OIDC Debugger Client (deprecated)
```
Client ID: client_q5IkUufL0c6CvzglVVZcIw
Redirect URI: http://localhost:8083/callback
Status: Can be deleted
```

## Conclusion

The current implementation provides a functional OAuth testing tool for Authly's API-based flows. The Authorization Code flow limitation is not a bug in our implementation but a fundamental architectural choice in Authly - it's an API-only OAuth server without user-facing authentication UI.

For testing purposes, the Resource Owner Password grant works perfectly and provides full access to tokens, introspection, and user info endpoints.

## References

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [Token Introspection RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)

---

*Last Updated: August 2025*
*Author: Authly Development Team via Claude*